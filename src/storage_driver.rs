//! Storage driver for configuration parameters and measurement data
//!
//! Concerns:
//! - Fixed configuration registers locations. Each flash address have limited 
//!   number of write cycles.
//! 


//! First 0xa000 bytes are reserved for configuration registers
//!
//! Configuration registers summary:
//! 1. WifiConfigurationParam: 0x0000..0x1000
//! 2. LocalRSAKeyParam: 0x1000..0x2000
//! 3. ServerInfoParam: 0x2000..0x3000
//! 4. SavedMeasurementScheduleParam: 0x3000..0x4000
//! 5. DeviceConfigParam: 0x4000..0x5000
//! 6. StoredMeasurementsParam: 0x5000..0x9000
//! 7. LastSrvPingParam: 0x9000..0xA000
//!
//! Range 0xa000 to 0xe000 is reserved for self-test
//!
//! Starting from 0x10000 and up to 0x1000000 is reserved for measurement data pages
//! - Each measurement page is 20000B (5 sectors)
//! - 10K samples are stored in a single measurement page
//! - Each sample is 2 bytes
//! 
//! Single measurement cover whole number of pages and is stored in a circular buffer


pub const MEASUREMENT_BUF_PAGE_CONSUMED_SIZE: u32 = 4096 * 5;

/// How much space is reserved for measurement data, each page is 20KB, starting address is 0x10000
/// An actual buffer length is MEASUREMENT_BUF_SIZE_PAGES - 1
pub const MEASUREMENT_BUF_SIZE_PAGES: u32 = 816;
pub const MAX_FAILED_MEASUREMENTS: usize = 80;

/// This must be <= flash size (16MB)
pub const MEASUREMENT_BUF_END: u32 = 0x10000 + MEASUREMENT_BUF_PAGE_CONSUMED_SIZE * MEASUREMENT_BUF_SIZE_PAGES;

use log::{error, info, warn};
use crate::ext_flash::ExtFlash;
use crate::storage_driver::configuration::{BytesRepr, ConfigParam};

mod configuration;
pub use configuration::*;
use crate::security::calc_hmac;

pub struct StorageDriver<'a> {
    ext_flash: ExtFlash<'a>
}

pub const MEASUREMENT_BUF_PAGE_SIZE: u32 = 20_000;

impl<'a> StorageDriver<'a> {
    pub fn new(ext_flash: ExtFlash<'a>) -> Self {
        Self {
            ext_flash
        }
    }

    pub fn read_reg_or_set_default<T: ConfigParam>(&mut self) -> T::ParamType
        where T::ParamType: Default {
        match self.read_reg::<T>() {
            Some(val) => val,
            None => {
                let default = T::ParamType::default();
                self.write_reg::<T>(default.clone());
                default
            }
        }
    }

    pub fn read_reg<T: ConfigParam>(&mut self) -> Option<T::ParamType> {
        info!("Reading configuration param {}...", T::NAME);
        let data = self.ext_flash.read_boxed(T::REG_ADDR * 0x1000, T::ParamType::REG_SIZE * 0x1000);
        let hmac = &data[data.len() - 32..];
        let data = &data[..data.len() - 32];
        let expected_hmac = calc_hmac(data);
        if hmac != expected_hmac {
            error!("HMAC mismatch for configuration param {}", T::NAME);
            // error!("Expected: {:?}", expected_hmac);
            if hmac.iter().all(|&x| x == 0) {
                error!("HMAC all zeroes");
            }
            if hmac.iter().all(|&x| x == 0xff) {
                error!("HMAC all ff, should've been erased");
            }
            return None;
        }
        T::ParamType::try_from_bytes(data)
    }

    pub fn write_reg<T: ConfigParam>(&mut self, value: T::ParamType) {
        // check if value is different
        let current = self.read_reg::<T>();
        if let Some(current) = current {
            if current == value {
                warn!("Configuration param {} is the same, skipping write", T::NAME);
                return;
            }
        }

        info!("Writing configuration param {}...", T::NAME);
        let mut data = value.to_bytes();
        let free_space = T::ParamType::REG_SIZE as isize * 0x1000 - data.len() as isize;
        if free_space < 32 {
            panic!("Configuration param {} is too large to fit into the register!", T::NAME);
        }
        data.extend(vec![0; free_space as usize - 32]);

        let hmac = calc_hmac(&data);
        data.extend(hmac);

        // data should be fully aligned to sectors at this point
        assert_eq!(data.len() % 4096, 0);
        self.ext_flash.write_overwrite(T::REG_ADDR * 0x1000, &data);
        self.ext_flash.wait_for_idle();
    }

    pub fn clear_reg<T: ConfigParam>(&mut self) {
        info!("Clearing configuration param {}...", T::NAME);
        self.ext_flash.erase_range(T::REG_ADDR * 0x1000, T::ParamType::REG_SIZE * 0x1000);
    }

    /// Harmless self test, includes write operation and verifying it
    pub fn self_test(&mut self) -> bool {
        // region 0xa000..0xe000 is reserved for self-test
        let start = 0xa000;
        let len = 0x4000;
        let data = self.ext_flash.read_boxed(start, len);
        let all_zeroes = data.iter().all(|&x| x == 0x00);
        if all_zeroes {
            info!("[self_test] External flash all zeroes state");
            self.ext_flash.erase_range(start, len);
            let data = self.ext_flash.read_boxed(start, len);
            if !data.iter().all(|&x| x == 0xff) {
                return false;
            }
        }
        else {
            // if any non-zero
            for (&v, addr) in data.iter().zip(start..) {
                if v != 0 {
                    info!("[self_test] External flash ff at {:x} state", addr - start);
                    self.ext_flash.write_and_byte(addr, 0x00);
                    let updated = self.ext_flash.read_boxed(addr, 1)[0];
                    if updated != 0x00 {
                        return false;
                    }
                    return true;
                }
            }
        }

        true
    }

    pub fn erase_measurement_pages(&mut self, start: u32, len: u32) {
        let (range1, range2) = if start + len < MEASUREMENT_BUF_SIZE_PAGES {
            (start..start+len, 0..0)
        } else {
            let len2 = start + len - MEASUREMENT_BUF_SIZE_PAGES;
            (start..MEASUREMENT_BUF_SIZE_PAGES, 0..len2)
        };
        for range in [range1, range2] {
            let start = 0x10000 + range.start * MEASUREMENT_BUF_PAGE_CONSUMED_SIZE;
            let size = range.len() as u32 * MEASUREMENT_BUF_PAGE_SIZE;
            self.ext_flash.erase_range(start, size);
        }
    }

    pub fn write_measurement_page(&mut self, page: u32, data: &[u8]) {
        let page = page % MEASUREMENT_BUF_SIZE_PAGES;
        assert_eq!(data.len(), MEASUREMENT_BUF_PAGE_SIZE as usize);
        let start = 0x10000 + page * MEASUREMENT_BUF_PAGE_CONSUMED_SIZE;
        self.ext_flash.write_overwrite(start, data);
    }

    pub fn read_measurement_page(&mut self, page: u32) -> Box<[u8]> {
        let page = page % MEASUREMENT_BUF_SIZE_PAGES;
        let start = 0x10000 + page * MEASUREMENT_BUF_PAGE_CONSUMED_SIZE;
        self.ext_flash.read_boxed(start, MEASUREMENT_BUF_PAGE_SIZE)
    }

    pub fn flush(&mut self) {
        self.ext_flash.wait_for_idle();
    }
}