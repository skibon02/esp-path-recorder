//! Configuration parameters for the storage driver.
//!
//! REG_ADDR and REG_SIZE are specified in sectors (4Kb = 0x1000)
//!
//! Configuration parameters also include HMAC code for data integrity. (32 bytes)

use std::collections::BTreeMap;
use chrono::{DateTime, Utc};
use log::warn;
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;

// Trait definitions
pub trait ConfigParam {
    const NAME: &'static str;
    const REG_ADDR: u32;
    type ParamType: BytesRepr + PartialEq + Clone;
}

pub trait BytesRepr: Sized + DeserializeOwned + Serialize {
    const REG_SIZE: u32;
    /// It is guaranteed that bytes input for this function was previously created by to_bytes, extended to full sector size
    fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
    /// Software must ensure that bytes length is less than (REG_SIZE * 0x1000 - 32)
    fn to_bytes(self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }
}


// Implementation
pub struct StoredPagesInfoParam;

impl ConfigParam for StoredPagesInfoParam {
    const NAME: &'static str = "StoredPagesInfo";
    const REG_ADDR: u32 = 1;
    type ParamType = StoredPagesInfo;
}

#[derive(Deserialize, Serialize, Debug, Default, Clone, PartialEq)]
pub struct StoredPagesInfo {
    pub pages_cnt: usize
}

impl BytesRepr for StoredPagesInfo {
    const REG_SIZE: u32 = 1;
    fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }

    fn to_bytes(self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }
}