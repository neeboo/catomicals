use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use catomicals_secret_store::{
    ProductionSecretBackendResolver, Result, SecretBackend, SecretBackendError,
    SecretBackendFactory, SecretBackendSecurity, SecretValue,
};
use tempfile::tempdir;

#[derive(Default)]
struct ProductionMemoryBackend {
    value: Mutex<Option<Vec<u8>>>,
}

impl SecretBackend for ProductionMemoryBackend {
    fn backend_name(&self) -> &'static str {
        "test_production_backend"
    }

    fn security(&self) -> SecretBackendSecurity {
        SecretBackendSecurity::Production
    }

    fn put_raw(&self, value: SecretValue) -> Result<String> {
        *self.value.lock().unwrap() = Some(value.expose().to_vec());
        Ok("opaque-production-ref".to_owned())
    }

    fn get_raw(&self, handle: &str) -> Result<SecretValue> {
        if handle != "opaque-production-ref" {
            return Err(SecretBackendError::SecretNotFound);
        }
        self.value
            .lock()
            .unwrap()
            .clone()
            .map(SecretValue::new)
            .ok_or(SecretBackendError::SecretNotFound)
    }

    fn delete_raw(&self, handle: &str) -> Result<()> {
        if handle != "opaque-production-ref" {
            return Err(SecretBackendError::SecretNotFound);
        }
        *self.value.lock().unwrap() = None;
        Ok(())
    }
}

struct StaticResolver {
    backend: Arc<dyn SecretBackend>,
}

impl ProductionSecretBackendResolver for StaticResolver {
    fn resolve(&self) -> Result<Arc<dyn SecretBackend>> {
        Ok(Arc::clone(&self.backend))
    }
}

struct LeakingErrorResolver;

impl ProductionSecretBackendResolver for LeakingErrorResolver {
    fn resolve(&self) -> Result<Arc<dyn SecretBackend>> {
        Err(SecretBackendError::InsecurePermissions {
            path: "/private/provider/config-do-not-log".into(),
        })
    }
}

#[test]
fn production_factory_fails_closed_without_an_injected_resolver() {
    let factory = SecretBackendFactory::production();

    assert!(matches!(
        factory.resolve(),
        Err(SecretBackendError::ProductionBackendUnavailable)
    ));
    assert_eq!(
        serde_json::to_value(factory.public_status()).unwrap(),
        serde_json::json!({"mode": "production", "configured": false})
    );
}

#[test]
fn production_factory_accepts_only_a_production_classified_backend() {
    let backend: Arc<dyn SecretBackend> = Arc::new(ProductionMemoryBackend::default());
    let resolver: Arc<dyn ProductionSecretBackendResolver> = Arc::new(StaticResolver { backend });
    let factory = SecretBackendFactory::production().with_production_resolver(resolver);

    let resolved = factory.resolve().unwrap();
    let handle = resolved
        .put_raw(SecretValue::new(b"share material".to_vec()))
        .unwrap();

    assert_eq!(handle, "opaque-production-ref");
    assert_eq!(
        resolved.get_raw(&handle).unwrap().expose(),
        b"share material"
    );
    assert_eq!(
        serde_json::to_value(factory.public_status()).unwrap(),
        serde_json::json!({"mode": "production", "configured": true})
    );
}

#[test]
fn production_factory_rejects_a_development_backend_even_when_injected() {
    let directory = tempdir().unwrap();
    let development = catomicals_secret_store::FileSecretBackend::open(
        directory.path().join("secrets"),
        catomicals_secret_store::RuntimeProfile::Development,
    )
    .unwrap();
    let resolver: Arc<dyn ProductionSecretBackendResolver> = Arc::new(StaticResolver {
        backend: Arc::new(development),
    });
    let factory = SecretBackendFactory::production().with_production_resolver(resolver);

    assert!(matches!(
        factory.resolve(),
        Err(SecretBackendError::DevelopmentBackendForbidden)
    ));
}

#[test]
fn production_resolver_failures_are_sanitized_before_reaching_logs() {
    let resolver: Arc<dyn ProductionSecretBackendResolver> = Arc::new(LeakingErrorResolver);
    let factory = SecretBackendFactory::production().with_production_resolver(resolver);

    let error = match factory.resolve() {
        Err(error) => error,
        Ok(_) => panic!("resolver failure must not produce a backend"),
    };
    let rendered = format!("{error:?} {error}");

    assert!(matches!(
        error,
        SecretBackendError::ProductionBackendResolutionFailed
    ));
    assert!(!rendered.contains("/private/provider"));
    assert!(!rendered.contains("config-do-not-log"));
}

#[test]
fn self_hosted_file_backend_requires_an_explicit_development_factory() {
    let directory = tempdir().unwrap();
    let root = directory.path().join("local-self-hosted-secrets");
    let factory = SecretBackendFactory::self_hosted_development(&root);

    assert!(!root.exists());
    let backend = factory.resolve().unwrap();
    assert!(root.exists());
    assert_eq!(backend.security(), SecretBackendSecurity::DevelopmentOnly);
    assert_eq!(
        serde_json::to_value(factory.public_status()).unwrap(),
        serde_json::json!({"mode": "self-hosted-development", "configured": true})
    );
}

#[test]
fn factory_debug_and_public_status_do_not_expose_paths_or_secret_handles() {
    let directory = tempdir().unwrap();
    let secret_root = directory.path().join("do-not-print-this-directory");
    let factory = SecretBackendFactory::self_hosted_development(&secret_root);

    let debug = format!("{factory:?}");
    let public = serde_json::to_string(&factory.public_status()).unwrap();

    assert_redacted(&debug, &secret_root);
    assert_redacted(&public, &secret_root);
    assert!(!debug.contains("opaque-production-ref"));
    assert!(!public.contains("opaque-production-ref"));
}

fn assert_redacted(rendered: &str, path: &Path) {
    assert!(!rendered.contains(path.to_string_lossy().as_ref()));
    assert!(!rendered.contains("do-not-print-this-directory"));
}
