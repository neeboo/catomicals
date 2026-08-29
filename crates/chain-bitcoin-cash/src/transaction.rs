use sha2::{Digest, Sha256};

use crate::Error;

const MAX_TRANSACTION_BYTES: usize = 32 * 1024 * 1024;
const MAX_TRANSACTION_ELEMENTS: usize = 1_000_000;
const ZERO_HASH: [u8; 32] = [0; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkIdSighashType(u32);

impl ForkIdSighashType {
    pub const ALL: Self = Self(0x41);
    pub const NONE: Self = Self(0x42);
    pub const SINGLE: Self = Self(0x43);
    pub const ALL_ANYONECANPAY: Self = Self(0xc1);
    pub const NONE_ANYONECANPAY: Self = Self(0xc2);
    pub const SINGLE_ANYONECANPAY: Self = Self(0xc3);

    pub fn from_consensus(raw: u32) -> Result<Self, Error> {
        if raw & 0x40 == 0 {
            return Err(Error::MissingForkId);
        }
        let base = raw & 0x1f;
        let allowed_low = base | 0x40 | (raw & 0x80);
        if !matches!(base, 1..=3) || raw & 0xff != allowed_low {
            return Err(Error::UnsupportedSighashType(raw));
        }
        Ok(Self(raw))
    }

    pub const fn to_consensus(self) -> u32 {
        self.0
    }

    pub const fn fork_id(self) -> u32 {
        self.0 >> 8
    }

    const fn base(self) -> u32 {
        self.0 & 0x1f
    }

    const fn anyone_can_pay(self) -> bool {
        self.0 & 0x80 != 0
    }

    pub(crate) fn signature_byte(self) -> Result<u8, Error> {
        if self.fork_id() != 0 {
            return Err(Error::UnsupportedForkId(self.fork_id()));
        }
        Ok(self.0 as u8)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutPoint {
    /// Wire-order transaction hash bytes.
    pub txid: [u8; 32],
    pub output_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

impl Transaction {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_TRANSACTION_BYTES {
            return Err(Error::TransactionTooLarge {
                max_bytes: MAX_TRANSACTION_BYTES,
            });
        }
        let mut reader = Reader::new(bytes);
        let version = reader.read_i32()?;
        let input_count = reader.read_count("inputs")?;
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let txid = reader.read_array()?;
            let output_index = reader.read_u32()?;
            let script_sig = reader.read_var_bytes()?;
            let sequence = reader.read_u32()?;
            inputs.push(TxIn {
                previous_output: OutPoint { txid, output_index },
                script_sig,
                sequence,
            });
        }

        let output_count = reader.read_count("outputs")?;
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            outputs.push(TxOut {
                value: reader.read_u64()?,
                script_pubkey: reader.read_var_bytes()?,
            });
        }
        let lock_time = reader.read_u32()?;
        if !reader.is_finished() {
            return Err(Error::TrailingTransactionData);
        }
        Ok(Self {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&self.version.to_le_bytes());
        write_var_int(self.inputs.len() as u64, &mut encoded);
        for input in &self.inputs {
            encode_outpoint(input.previous_output, &mut encoded);
            write_var_bytes(&input.script_sig, &mut encoded);
            encoded.extend_from_slice(&input.sequence.to_le_bytes());
        }
        write_var_int(self.outputs.len() as u64, &mut encoded);
        for output in &self.outputs {
            encode_output(output, &mut encoded);
        }
        encoded.extend_from_slice(&self.lock_time.to_le_bytes());
        encoded
    }
}

pub fn fork_id_sighash(
    transaction: &Transaction,
    input_index: usize,
    script_code: &[u8],
    input_value: u64,
    hash_type: ForkIdSighashType,
) -> Result<[u8; 32], Error> {
    let input = transaction
        .inputs
        .get(input_index)
        .ok_or(Error::InputIndexOutOfBounds {
            index: input_index,
            input_count: transaction.inputs.len(),
        })?;

    let hash_prevouts = if hash_type.anyone_can_pay() {
        ZERO_HASH
    } else {
        let mut encoded = Vec::with_capacity(transaction.inputs.len() * 36);
        for transaction_input in &transaction.inputs {
            encode_outpoint(transaction_input.previous_output, &mut encoded);
        }
        double_sha256(&encoded)
    };

    let hash_sequence = if hash_type.anyone_can_pay() || matches!(hash_type.base(), 2 | 3) {
        ZERO_HASH
    } else {
        let mut encoded = Vec::with_capacity(transaction.inputs.len() * 4);
        for transaction_input in &transaction.inputs {
            encoded.extend_from_slice(&transaction_input.sequence.to_le_bytes());
        }
        double_sha256(&encoded)
    };

    let hash_outputs = match hash_type.base() {
        1 => {
            let mut encoded = Vec::new();
            for output in &transaction.outputs {
                encode_output(output, &mut encoded);
            }
            double_sha256(&encoded)
        }
        3 if input_index < transaction.outputs.len() => {
            let mut encoded = Vec::new();
            encode_output(&transaction.outputs[input_index], &mut encoded);
            double_sha256(&encoded)
        }
        2 | 3 => ZERO_HASH,
        _ => return Err(Error::UnsupportedSighashType(hash_type.to_consensus())),
    };

    let mut preimage = Vec::new();
    preimage.extend_from_slice(&transaction.version.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);
    encode_outpoint(input.previous_output, &mut preimage);
    write_var_bytes(script_code, &mut preimage);
    preimage.extend_from_slice(&input_value.to_le_bytes());
    preimage.extend_from_slice(&input.sequence.to_le_bytes());
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&transaction.lock_time.to_le_bytes());
    preimage.extend_from_slice(&hash_type.to_consensus().to_le_bytes());
    Ok(double_sha256(&preimage))
}

fn double_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(bytes)).into()
}

fn encode_outpoint(outpoint: OutPoint, output: &mut Vec<u8>) {
    output.extend_from_slice(&outpoint.txid);
    output.extend_from_slice(&outpoint.output_index.to_le_bytes());
}

fn encode_output(transaction_output: &TxOut, output: &mut Vec<u8>) {
    output.extend_from_slice(&transaction_output.value.to_le_bytes());
    write_var_bytes(&transaction_output.script_pubkey, output);
}

fn write_var_bytes(bytes: &[u8], output: &mut Vec<u8>) {
    write_var_int(bytes.len() as u64, output);
    output.extend_from_slice(bytes);
}

fn write_var_int(value: u64, output: &mut Vec<u8>) {
    match value {
        0..=0xfc => output.push(value as u8),
        0xfd..=0xffff => {
            output.push(0xfd);
            output.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(0xfe);
            output.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            output.push(0xff);
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(Error::MalformedTransaction)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(Error::MalformedTransaction)?;
        self.position = end;
        bytes.try_into().map_err(|_| Error::MalformedTransaction)
    }

    fn read_u8(&mut self) -> Result<u8, Error> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_i32(&mut self) -> Result<i32, Error> {
        Ok(i32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn read_var_int(&mut self) -> Result<u64, Error> {
        match self.read_u8()? {
            value @ 0..=0xfc => Ok(u64::from(value)),
            0xfd => {
                let value = u64::from(self.read_u16()?);
                if value < 0xfd {
                    Err(Error::NonCanonicalVarInt)
                } else {
                    Ok(value)
                }
            }
            0xfe => {
                let value = u64::from(self.read_u32()?);
                if value <= 0xffff {
                    Err(Error::NonCanonicalVarInt)
                } else {
                    Ok(value)
                }
            }
            0xff => {
                let value = self.read_u64()?;
                if value <= 0xffff_ffff {
                    Err(Error::NonCanonicalVarInt)
                } else {
                    Ok(value)
                }
            }
        }
    }

    fn read_count(&mut self, field: &'static str) -> Result<usize, Error> {
        let count = usize::try_from(self.read_var_int()?)
            .map_err(|_| Error::TooManyTransactionElements { field })?;
        if count > MAX_TRANSACTION_ELEMENTS {
            return Err(Error::TooManyTransactionElements { field });
        }
        Ok(count)
    }

    fn read_var_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let length =
            usize::try_from(self.read_var_int()?).map_err(|_| Error::MalformedTransaction)?;
        let end = self
            .position
            .checked_add(length)
            .ok_or(Error::MalformedTransaction)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(Error::MalformedTransaction)?;
        self.position = end;
        Ok(bytes.to_vec())
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}
