use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{BsvError, BsvNetwork};

const MAX_TRANSACTION_INPUTS: usize = 100_000;
const MAX_TRANSACTION_OUTPUTS: usize = 100_000;
const MAX_SCRIPT_BYTES: usize = 10_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TxInput {
    /// Transaction-id bytes in consensus wire order (little endian).
    pub previous_txid_le: [u8; 32],
    pub previous_output_index: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TxOutput {
    pub value_satoshis: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u32,
}

impl Transaction {
    pub fn consensus_encode(&self) -> Result<Vec<u8>, BsvError> {
        validate_transaction(self)?;
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&self.version.to_le_bytes());
        write_compact_size(&mut encoded, self.inputs.len());
        for input in &self.inputs {
            write_outpoint(&mut encoded, input);
            write_script(&mut encoded, &input.script_sig);
            encoded.extend_from_slice(&input.sequence.to_le_bytes());
        }
        write_compact_size(&mut encoded, self.outputs.len());
        for output in &self.outputs {
            write_output(&mut encoded, output);
        }
        encoded.extend_from_slice(&self.lock_time.to_le_bytes());
        Ok(encoded)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ForkIdSighashType(u8);

impl ForkIdSighashType {
    pub const ALL: Self = Self(0x41);
    pub const NONE: Self = Self(0x42);
    pub const SINGLE: Self = Self(0x43);
    pub const ALL_ANYONE_CAN_PAY: Self = Self(0xc1);
    pub const NONE_ANYONE_CAN_PAY: Self = Self(0xc2);
    pub const SINGLE_ANYONE_CAN_PAY: Self = Self(0xc3);

    pub fn from_u8(value: u8) -> Result<Self, BsvError> {
        match value {
            0x41 | 0x42 | 0x43 | 0xc1 | 0xc2 | 0xc3 => Ok(Self(value)),
            _ => Err(BsvError::InvalidSighashType(value)),
        }
    }

    pub const fn to_u8(self) -> u8 {
        self.0
    }

    const fn base(self) -> u8 {
        self.0 & 0x1f
    }

    const fn anyone_can_pay(self) -> bool {
        self.0 & 0x80 != 0
    }
}

impl<'de> Deserialize<'de> for ForkIdSighashType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        Self::from_u8(value).map_err(serde::de::Error::custom)
    }
}

pub fn fork_id_sighash(
    transaction: &Transaction,
    input_index: usize,
    script_code: &[u8],
    input_value_satoshis: u64,
    sighash_type: ForkIdSighashType,
) -> Result<[u8; 32], BsvError> {
    validate_transaction(transaction)?;
    if script_code.len() > MAX_SCRIPT_BYTES {
        return Err(BsvError::InvalidSigningMaterial(
            "scriptCode exceeds the configured bound".to_owned(),
        ));
    }
    let input = transaction
        .inputs
        .get(input_index)
        .ok_or(BsvError::InputIndexOutOfBounds { index: input_index })?;
    if sighash_type.base() == 3 && input_index >= transaction.outputs.len() {
        return Err(BsvError::MissingSingleOutput { index: input_index });
    }

    let hash_prevouts = if sighash_type.anyone_can_pay() {
        [0; 32]
    } else {
        let mut outpoints = Vec::with_capacity(transaction.inputs.len() * 36);
        for candidate in &transaction.inputs {
            write_outpoint(&mut outpoints, candidate);
        }
        double_sha256(&outpoints)
    };
    let hash_sequence = if sighash_type.anyone_can_pay() || matches!(sighash_type.base(), 2 | 3) {
        [0; 32]
    } else {
        let mut sequences = Vec::with_capacity(transaction.inputs.len() * 4);
        for candidate in &transaction.inputs {
            sequences.extend_from_slice(&candidate.sequence.to_le_bytes());
        }
        double_sha256(&sequences)
    };
    let hash_outputs = match sighash_type.base() {
        1 => {
            let mut outputs = Vec::new();
            for output in &transaction.outputs {
                write_output(&mut outputs, output);
            }
            double_sha256(&outputs)
        }
        3 => {
            let mut output = Vec::new();
            write_output(&mut output, &transaction.outputs[input_index]);
            double_sha256(&output)
        }
        _ => [0; 32],
    };

    let mut preimage = Vec::new();
    preimage.extend_from_slice(&transaction.version.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);
    write_outpoint(&mut preimage, input);
    write_script(&mut preimage, script_code);
    preimage.extend_from_slice(&input_value_satoshis.to_le_bytes());
    preimage.extend_from_slice(&input.sequence.to_le_bytes());
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&transaction.lock_time.to_le_bytes());
    preimage.extend_from_slice(&u32::from(sighash_type.to_u8()).to_le_bytes());
    Ok(double_sha256(&preimage))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BsvSigningRequest {
    pub network: BsvNetwork,
    pub transaction: Transaction,
    pub input_index: usize,
    pub script_code: Vec<u8>,
    pub input_value_satoshis: u64,
    pub sighash_type: ForkIdSighashType,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningRequestWire {
    schema_version: u16,
    network: String,
    transaction: Transaction,
    input_index: usize,
    script_code: Vec<u8>,
    input_value_satoshis: u64,
    sighash_type: u8,
}

impl BsvSigningRequest {
    pub fn signing_digest(&self) -> Result<[u8; 32], BsvError> {
        fork_id_sighash(
            &self.transaction,
            self.input_index,
            &self.script_code,
            self.input_value_satoshis,
            self.sighash_type,
        )
    }

    pub fn encode(&self) -> Result<Vec<u8>, BsvError> {
        self.signing_digest()?;
        serde_json::to_vec(&SigningRequestWire {
            schema_version: 1,
            network: network_name(self.network).to_owned(),
            transaction: self.transaction.clone(),
            input_index: self.input_index,
            script_code: self.script_code.clone(),
            input_value_satoshis: self.input_value_satoshis,
            sighash_type: self.sighash_type.to_u8(),
        })
        .map_err(|error| BsvError::InvalidSigningMaterial(error.to_string()))
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BsvError> {
        let wire = serde_json::from_slice::<SigningRequestWire>(bytes)
            .map_err(|error| BsvError::InvalidSigningMaterial(error.to_string()))?;
        if wire.schema_version != 1 {
            return Err(BsvError::InvalidSigningMaterial(format!(
                "unsupported schema version {}",
                wire.schema_version
            )));
        }
        let request = Self {
            network: parse_network(&wire.network)?,
            transaction: wire.transaction,
            input_index: wire.input_index,
            script_code: wire.script_code,
            input_value_satoshis: wire.input_value_satoshis,
            sighash_type: ForkIdSighashType::from_u8(wire.sighash_type)?,
        };
        request.signing_digest()?;
        Ok(request)
    }
}

pub(crate) const fn network_name(network: BsvNetwork) -> &'static str {
    match network {
        BsvNetwork::Mainnet => "mainnet",
        BsvNetwork::Testnet => "testnet",
        BsvNetwork::Stn => "stn",
        BsvNetwork::Regtest => "regtest",
    }
}

fn parse_network(value: &str) -> Result<BsvNetwork, BsvError> {
    match value {
        "mainnet" => Ok(BsvNetwork::Mainnet),
        "testnet" => Ok(BsvNetwork::Testnet),
        "stn" => Ok(BsvNetwork::Stn),
        "regtest" => Ok(BsvNetwork::Regtest),
        _ => Err(BsvError::InvalidSigningMaterial(format!(
            "unsupported BSV network {value}"
        ))),
    }
}

fn validate_transaction(transaction: &Transaction) -> Result<(), BsvError> {
    if transaction.inputs.is_empty() || transaction.inputs.len() > MAX_TRANSACTION_INPUTS {
        return Err(BsvError::InvalidSigningMaterial(
            "transaction input count is outside the configured bounds".to_owned(),
        ));
    }
    if transaction.outputs.is_empty() || transaction.outputs.len() > MAX_TRANSACTION_OUTPUTS {
        return Err(BsvError::InvalidSigningMaterial(
            "transaction output count is outside the configured bounds".to_owned(),
        ));
    }
    if transaction
        .inputs
        .iter()
        .any(|input| input.script_sig.len() > MAX_SCRIPT_BYTES)
        || transaction
            .outputs
            .iter()
            .any(|output| output.script_pubkey.len() > MAX_SCRIPT_BYTES)
    {
        return Err(BsvError::InvalidSigningMaterial(
            "transaction script exceeds the configured bound".to_owned(),
        ));
    }
    Ok(())
}

fn write_outpoint(encoded: &mut Vec<u8>, input: &TxInput) {
    encoded.extend_from_slice(&input.previous_txid_le);
    encoded.extend_from_slice(&input.previous_output_index.to_le_bytes());
}

fn write_output(encoded: &mut Vec<u8>, output: &TxOutput) {
    encoded.extend_from_slice(&output.value_satoshis.to_le_bytes());
    write_script(encoded, &output.script_pubkey);
}

fn write_script(encoded: &mut Vec<u8>, script: &[u8]) {
    write_compact_size(encoded, script.len());
    encoded.extend_from_slice(script);
}

fn write_compact_size(encoded: &mut Vec<u8>, value: usize) {
    if value < 0xfd {
        encoded.push(value as u8);
    } else if value <= 0xffff {
        encoded.push(0xfd);
        encoded.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffff_ffff {
        encoded.push(0xfe);
        encoded.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        encoded.push(0xff);
        encoded.extend_from_slice(&(value as u64).to_le_bytes());
    }
}

pub(crate) fn double_sha256(bytes: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(bytes);
    Sha256::digest(first).into()
}
