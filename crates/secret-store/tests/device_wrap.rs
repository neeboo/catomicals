use catomicals_secret_store::{
    DeviceKeyProtectionError, DeviceKeyProtector, DeviceKeyProvider, DeviceKeyWrapAlgorithm,
    DeviceWrapBinding, DeviceWrapError, DeviceWrappedPackageV1, SecretValue,
};
use serde_json::Value;

const PROFILE_DIGEST: [u8; 32] = [0x42; 32];
const KEY_ID: &str = "catomicals.personal.desktop.1";
const TEST_KEK: [u8; 32] = [0xa5; 32];

#[derive(Clone)]
struct TestProtector {
    provider: DeviceKeyProvider,
    algorithm: DeviceKeyWrapAlgorithm,
    key_id: String,
}

impl TestProtector {
    fn new(
        provider: DeviceKeyProvider,
        algorithm: DeviceKeyWrapAlgorithm,
        key_id: impl Into<String>,
    ) -> Self {
        Self {
            provider,
            algorithm,
            key_id: key_id.into(),
        }
    }
}

impl DeviceKeyProtector for TestProtector {
    fn provider(&self) -> DeviceKeyProvider {
        self.provider
    }

    fn algorithm(&self) -> DeviceKeyWrapAlgorithm {
        self.algorithm
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn wrap_dek(&self, dek: SecretValue) -> Result<Vec<u8>, DeviceKeyProtectionError> {
        Ok(dek
            .expose()
            .iter()
            .zip(TEST_KEK)
            .map(|(byte, key)| byte ^ key)
            .collect())
    }

    fn unwrap_dek(&self, wrapped_dek: &[u8]) -> Result<SecretValue, DeviceKeyProtectionError> {
        Ok(SecretValue::new(
            wrapped_dek
                .iter()
                .zip(TEST_KEK)
                .map(|(byte, key)| byte ^ key)
                .collect(),
        ))
    }
}

fn binding() -> DeviceWrapBinding {
    DeviceWrapBinding::new(
        DeviceKeyProvider::MacosSecureEnclaveP256,
        DeviceKeyWrapAlgorithm::AppleEciesCofactorX963Sha256AesGcm,
        KEY_ID,
        PROFILE_DIGEST,
        2,
        7,
        3,
    )
    .expect("valid test binding")
}

fn protector_for(binding: &DeviceWrapBinding) -> TestProtector {
    TestProtector::new(binding.provider(), binding.algorithm(), binding.key_id())
}

#[test]
fn seals_and_opens_a_bounded_participant_package() {
    let binding = binding();
    let protector = protector_for(&binding);
    let package = DeviceWrappedPackageV1::seal(
        SecretValue::new(b"participant-package-secret".to_vec()),
        binding.clone(),
        &protector,
    )
    .expect("seal participant package");

    let encoded = package.to_bytes().expect("encode package");
    assert!(
        !encoded
            .windows(b"participant-package-secret".len())
            .any(|window| window == b"participant-package-secret")
    );
    let decoded = DeviceWrappedPackageV1::from_bytes(&encoded).expect("decode package");
    let opened = decoded
        .open(&binding, &protector)
        .expect("open participant package");
    assert_eq!(opened.expose(), b"participant-package-secret");
    assert_eq!(format!("{package:?}"), "DeviceWrappedPackageV1([REDACTED])");
}

#[test]
fn aad_binds_every_identity_and_generation_field() {
    let original = binding();
    let protector = protector_for(&original);
    let package = DeviceWrappedPackageV1::seal(
        SecretValue::new(b"bound secret".to_vec()),
        original,
        &protector,
    )
    .expect("seal participant package");
    let encoded = package.to_bytes().expect("encode package");

    let mutations: [(&str, Value); 7] = [
        ("profile_digest", serde_json::json!(vec![0x24; 32])),
        ("signer_id", serde_json::json!(3)),
        ("epoch", serde_json::json!(8)),
        ("device_generation", serde_json::json!(4)),
        ("provider", serde_json::json!("ios_secure_enclave_p256")),
        (
            "algorithm",
            serde_json::json!("android_ecies_hkdf_sha256_aes_gcm"),
        ),
        ("key_id", serde_json::json!("catomicals.personal.desktop.2")),
    ];

    for (field, replacement) in mutations {
        let mut value: Value = serde_json::from_slice(&encoded).expect("package JSON");
        value[field] = replacement;
        let mutated = serde_json::to_vec(&value).expect("mutated package JSON");
        let decoded = DeviceWrappedPackageV1::from_bytes(&mutated).unwrap_or_else(|error| {
            panic!("{field} mutation should remain structurally valid: {error}")
        });
        let mutated_binding = decoded.binding().clone();
        let mutated_protector = protector_for(&mutated_binding);
        let error = decoded
            .open(&mutated_binding, &mutated_protector)
            .expect_err("AAD mutation must fail authentication");
        assert_eq!(
            error,
            DeviceWrapError::AuthenticationFailed,
            "field {field}"
        );
    }
}

#[test]
fn rejects_unknown_fields_mismatched_binding_and_oversized_input() {
    let binding = binding();
    let protector = protector_for(&binding);
    let package = DeviceWrappedPackageV1::seal(
        SecretValue::new(b"secret".to_vec()),
        binding.clone(),
        &protector,
    )
    .expect("seal participant package");

    let mut value: Value =
        serde_json::from_slice(&package.to_bytes().expect("encode package")).expect("package JSON");
    value["unexpected"] = serde_json::json!(true);
    assert_eq!(
        DeviceWrappedPackageV1::from_bytes(&serde_json::to_vec(&value).expect("JSON"))
            .expect_err("unknown fields must be rejected"),
        DeviceWrapError::InvalidEncoding
    );

    let different = DeviceWrapBinding::new(
        binding.provider(),
        binding.algorithm(),
        binding.key_id(),
        [0x11; 32],
        binding.signer_id(),
        binding.epoch(),
        binding.device_generation(),
    )
    .expect("different binding");
    assert_eq!(
        package
            .open(&different, &protector)
            .expect_err("caller must supply the expected binding"),
        DeviceWrapError::BindingMismatch
    );

    assert_eq!(
        DeviceWrappedPackageV1::seal(
            SecretValue::new(vec![0u8; DeviceWrappedPackageV1::MAX_PLAINTEXT_BYTES + 1]),
            binding,
            &protector,
        )
        .expect_err("oversized participant package must fail"),
        DeviceWrapError::PlaintextTooLarge
    );
}

#[test]
fn error_and_protector_debug_output_are_redacted() {
    let binding = binding();
    let protector = protector_for(&binding);
    let mut encoded = DeviceWrappedPackageV1::seal(
        SecretValue::new(b"fixture-secret-that-must-not-leak".to_vec()),
        binding.clone(),
        &protector,
    )
    .expect("seal")
    .to_bytes()
    .expect("encode");
    let last = encoded.last_mut().expect("nonempty encoding");
    *last ^= 1;
    let error = DeviceWrappedPackageV1::from_bytes(&encoded).expect_err("corrupt JSON");
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("fixture-secret-that-must-not-leak"));
    assert!(!rendered.contains(KEY_ID));
}
