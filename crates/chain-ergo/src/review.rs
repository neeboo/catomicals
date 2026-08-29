use catomicals_chain_domain::{ErgoNetwork, MAX_REVIEW_MATERIAL_BYTES};
use ergo_lib::{
    chain::{
        ergo_state_context::{ErgoStateContext, Headers},
        parameters::{Parameter, Parameters},
        transaction::unsigned::UnsignedTransaction,
    },
    ergo_chain_types::{BlockId, EcPoint, Header, PreHeader, Votes},
    ergotree_ir::{chain::ergo_box::ErgoBox, serialization::SigmaSerializable},
};
use sigma_ser::ScorexSerializable;

use crate::ErgoAdapterError;

const MAGIC: &[u8; 8] = b"ERGOREV1";
const SCHEMA_VERSION: u16 = 1;
const MAX_COMPONENT_BYTES: usize = 512 * 1024;
const MAX_BOX_COUNT: usize = u16::MAX as usize;

const PARAMETERS: [Parameter; 9] = [
    Parameter::StorageFeeFactor,
    Parameter::MinValuePerByte,
    Parameter::MaxBlockSize,
    Parameter::MaxBlockCost,
    Parameter::TokenAccessCost,
    Parameter::InputCost,
    Parameter::DataInputCost,
    Parameter::OutputCost,
    Parameter::BlockVersion,
];

/// Canonical, bounded transaction context for Ergo P2PK review and signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErgoReviewMaterialV1 {
    pub network: ErgoNetwork,
    pub pre_header: PreHeader,
    pub unsigned_tx: UnsignedTransaction,
    pub bytes_to_sign: Vec<u8>,
    pub input_boxes: Vec<ErgoBox>,
    pub data_boxes: Vec<ErgoBox>,
    pub headers: Headers,
    pub parameters: Parameters,
}

impl ErgoReviewMaterialV1 {
    pub fn new(
        network: ErgoNetwork,
        pre_header: PreHeader,
        unsigned_tx: UnsignedTransaction,
        input_boxes: Vec<ErgoBox>,
        data_boxes: Vec<ErgoBox>,
        headers: Headers,
        parameters: Parameters,
    ) -> Result<Self, ErgoAdapterError> {
        if input_boxes.is_empty() || input_boxes.len() > MAX_BOX_COUNT {
            return Err(ErgoAdapterError::InvalidReviewMaterial(
                "input box count is outside the Ergo transaction bounds".into(),
            ));
        }
        if data_boxes.len() > MAX_BOX_COUNT {
            return Err(ErgoAdapterError::InvalidReviewMaterial(
                "data box count is outside the Ergo transaction bounds".into(),
            ));
        }
        let bytes_to_sign = unsigned_tx.bytes_to_sign().map_err(material_error)?;
        let headers = headers
            .into_iter()
            .map(|header| {
                Header::scorex_parse_bytes(
                    &header.scorex_serialize_bytes().map_err(material_error)?,
                )
                .map_err(material_error)
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| {
                ErgoAdapterError::InvalidReviewMaterial("exactly 10 headers are required".into())
            })?;
        Ok(Self {
            network,
            pre_header,
            unsigned_tx,
            bytes_to_sign,
            input_boxes,
            data_boxes,
            headers,
            parameters,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ErgoAdapterError> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(&SCHEMA_VERSION.to_be_bytes());
        encoded.push(match self.network {
            ErgoNetwork::Mainnet => 0,
            ErgoNetwork::Testnet => 1,
        });
        put_component(
            &mut encoded,
            &serde_json::to_vec(&PreHeaderWire::from(&self.pre_header)).map_err(material_error)?,
        )?;
        put_component(
            &mut encoded,
            &serde_json::to_vec(&self.unsigned_tx).map_err(material_error)?,
        )?;
        put_component(&mut encoded, &self.bytes_to_sign)?;
        put_boxes(&mut encoded, &self.input_boxes)?;
        put_boxes(&mut encoded, &self.data_boxes)?;
        for header in &self.headers {
            put_component(
                &mut encoded,
                &header.scorex_serialize_bytes().map_err(material_error)?,
            )?;
        }
        for parameter in PARAMETERS {
            if let Some(value) = self.parameters.parameters_table.get(&parameter) {
                encoded.push(1);
                encoded.extend_from_slice(&value.to_be_bytes());
            } else {
                encoded.push(0);
            }
        }
        if encoded.len() > MAX_REVIEW_MATERIAL_BYTES {
            return Err(ErgoAdapterError::InvalidReviewMaterial(format!(
                "review material exceeds {MAX_REVIEW_MATERIAL_BYTES} bytes"
            )));
        }
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, ErgoAdapterError> {
        if encoded.len() > MAX_REVIEW_MATERIAL_BYTES {
            return Err(ErgoAdapterError::InvalidReviewMaterial(format!(
                "review material exceeds {MAX_REVIEW_MATERIAL_BYTES} bytes"
            )));
        }
        let mut reader = BoundedReader::new(encoded);
        if reader.take(MAGIC.len())? != MAGIC {
            return Err(ErgoAdapterError::InvalidReviewMaterial(
                "invalid Ergo review material magic".into(),
            ));
        }
        let version = reader.u16()?;
        if version != SCHEMA_VERSION {
            return Err(ErgoAdapterError::UnsupportedReviewMaterialVersion {
                expected: SCHEMA_VERSION,
                actual: version,
            });
        }
        let network = match reader.u8()? {
            0 => ErgoNetwork::Mainnet,
            1 => ErgoNetwork::Testnet,
            value => {
                return Err(ErgoAdapterError::InvalidReviewMaterial(format!(
                    "invalid Ergo network tag {value}"
                )));
            }
        };
        let pre_header_bytes = reader.component()?;
        let pre_header_wire: PreHeaderWire =
            serde_json::from_slice(pre_header_bytes).map_err(material_error)?;
        if serde_json::to_vec(&pre_header_wire).map_err(material_error)? != pre_header_bytes {
            return Err(ErgoAdapterError::InvalidReviewMaterial(
                "non-canonical Ergo pre-header encoding".into(),
            ));
        }
        let pre_header = PreHeader::from(pre_header_wire);
        let unsigned_bytes = reader.component()?;
        let unsigned_tx: UnsignedTransaction =
            serde_json::from_slice(unsigned_bytes).map_err(material_error)?;
        if serde_json::to_vec(&unsigned_tx).map_err(material_error)? != unsigned_bytes {
            return Err(ErgoAdapterError::InvalidReviewMaterial(
                "non-canonical unsigned transaction encoding".into(),
            ));
        }
        let claimed_bytes_to_sign = reader.component()?.to_vec();
        let input_boxes = read_boxes(&mut reader)?;
        let data_boxes = read_boxes(&mut reader)?;
        let mut headers = Vec::with_capacity(10);
        for _ in 0..10 {
            let bytes = reader.component()?;
            let header = Header::scorex_parse_bytes(bytes).map_err(material_error)?;
            if header.scorex_serialize_bytes().map_err(material_error)? != bytes {
                return Err(ErgoAdapterError::InvalidReviewMaterial(
                    "non-canonical Ergo header encoding".into(),
                ));
            }
            headers.push(header);
        }
        let headers: Headers = headers.try_into().map_err(|_| {
            ErgoAdapterError::InvalidReviewMaterial("exactly 10 headers are required".into())
        })?;
        let mut parameters = Parameters::default();
        parameters.parameters_table.clear();
        for parameter in PARAMETERS {
            match reader.u8()? {
                0 => {}
                1 => {
                    let value = reader.i32()?;
                    parameters.parameters_table.insert(parameter, value);
                }
                value => {
                    return Err(ErgoAdapterError::InvalidReviewMaterial(format!(
                        "invalid parameter presence tag {value}"
                    )));
                }
            }
        }
        if !reader.is_empty() {
            return Err(ErgoAdapterError::InvalidReviewMaterial(
                "trailing bytes in Ergo review material".into(),
            ));
        }
        let material = Self::new(
            network,
            pre_header,
            unsigned_tx,
            input_boxes,
            data_boxes,
            headers,
            parameters,
        )?;
        if material.bytes_to_sign != claimed_bytes_to_sign {
            return Err(ErgoAdapterError::InvalidReviewMaterial(
                "unsigned transaction bytes_to_sign mismatch".into(),
            ));
        }
        if material.encode()? != encoded {
            return Err(ErgoAdapterError::InvalidReviewMaterial(
                "non-canonical Ergo review material encoding".into(),
            ));
        }
        Ok(material)
    }

    pub fn state_context(&self) -> ErgoStateContext {
        ErgoStateContext::new(
            self.pre_header.clone(),
            self.headers.clone(),
            self.parameters.clone(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PreHeaderWire {
    version: u8,
    parent_id: BlockId,
    timestamp: u64,
    n_bits: u32,
    height: u32,
    miner_pk: Box<EcPoint>,
    votes: Votes,
}

impl From<&PreHeader> for PreHeaderWire {
    fn from(pre_header: &PreHeader) -> Self {
        Self {
            version: pre_header.version,
            parent_id: pre_header.parent_id,
            timestamp: pre_header.timestamp,
            n_bits: pre_header.n_bits,
            height: pre_header.height,
            miner_pk: pre_header.miner_pk.clone(),
            votes: pre_header.votes.clone(),
        }
    }
}

impl From<PreHeaderWire> for PreHeader {
    fn from(wire: PreHeaderWire) -> Self {
        Self {
            version: wire.version,
            parent_id: wire.parent_id,
            timestamp: wire.timestamp,
            n_bits: wire.n_bits,
            height: wire.height,
            miner_pk: wire.miner_pk,
            votes: wire.votes,
        }
    }
}

fn put_boxes(encoded: &mut Vec<u8>, boxes: &[ErgoBox]) -> Result<(), ErgoAdapterError> {
    let count = u16::try_from(boxes.len())
        .map_err(|_| ErgoAdapterError::InvalidReviewMaterial("too many Ergo boxes".into()))?;
    encoded.extend_from_slice(&count.to_be_bytes());
    for ergo_box in boxes {
        put_component(
            encoded,
            &ergo_box.sigma_serialize_bytes().map_err(material_error)?,
        )?;
    }
    Ok(())
}

fn read_boxes(reader: &mut BoundedReader<'_>) -> Result<Vec<ErgoBox>, ErgoAdapterError> {
    let count = usize::from(reader.u16()?);
    let mut boxes = Vec::with_capacity(count);
    for _ in 0..count {
        let bytes = reader.component()?;
        let ergo_box = ErgoBox::sigma_parse_bytes(bytes).map_err(material_error)?;
        require_sigma_canonical(&ergo_box, bytes)?;
        boxes.push(ergo_box);
    }
    Ok(boxes)
}

fn require_sigma_canonical<T: SigmaSerializable>(
    value: &T,
    encoded: &[u8],
) -> Result<(), ErgoAdapterError> {
    if value.sigma_serialize_bytes().map_err(material_error)? != encoded {
        return Err(ErgoAdapterError::InvalidReviewMaterial(
            "non-canonical Sigma encoding".into(),
        ));
    }
    Ok(())
}

fn put_component(target: &mut Vec<u8>, component: &[u8]) -> Result<(), ErgoAdapterError> {
    if component.is_empty() || component.len() > MAX_COMPONENT_BYTES {
        return Err(ErgoAdapterError::InvalidReviewMaterial(format!(
            "component must contain 1..={MAX_COMPONENT_BYTES} bytes"
        )));
    }
    let length = u32::try_from(component.len()).map_err(material_error)?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(component);
    Ok(())
}

fn material_error(error: impl std::fmt::Display) -> ErgoAdapterError {
    ErgoAdapterError::InvalidReviewMaterial(error.to_string())
}

struct BoundedReader<'a> {
    remaining: &'a [u8],
}

impl<'a> BoundedReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ErgoAdapterError> {
        if length > self.remaining.len() {
            return Err(ErgoAdapterError::InvalidReviewMaterial(
                "truncated Ergo review material".into(),
            ));
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ErgoAdapterError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ErgoAdapterError> {
        let bytes: [u8; 2] = self.take(2)?.try_into().map_err(material_error)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, ErgoAdapterError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(material_error)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn i32(&mut self) -> Result<i32, ErgoAdapterError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(material_error)?;
        Ok(i32::from_be_bytes(bytes))
    }

    fn component(&mut self) -> Result<&'a [u8], ErgoAdapterError> {
        let length = usize::try_from(self.u32()?).map_err(material_error)?;
        if length == 0 || length > MAX_COMPONENT_BYTES {
            return Err(ErgoAdapterError::InvalidReviewMaterial(format!(
                "component must contain 1..={MAX_COMPONENT_BYTES} bytes"
            )));
        }
        self.take(length)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}
