use esp_idf_svc::hal::spi::{SpiDeviceDriver, SpiDriver};
use log::{debug, info};

enum WipState {
    Busy,
    Ready
}

pub struct ExtFlash<'a> {
    spi_flash: SpiDeviceDriver<'a, &'a SpiDriver<'a>>,
    wip_state: WipState
}

impl<'a> ExtFlash<'a> {
    pub fn new(spi: SpiDeviceDriver<'a, &'a SpiDriver<'a>>) -> Self {
        Self {
            spi_flash: spi,
            wip_state: WipState::Busy
        }
    }

    pub fn wait_for_idle(&mut self) {
        if let WipState::Busy = self.wip_state {
            let mut buf = [0; 2];
            self.spi_flash.transfer(&mut buf, &[0x05, 0]).unwrap();
            while buf[1] & 1 != 0 {
                self.spi_flash.transfer(&mut buf, &[0x05, 0]).unwrap();
            }
            self.wip_state = WipState::Ready;
        }
    }

    fn addr_from_u32(&self, addr: u32) -> [u8; 3] {
        [(addr >> 16) as u8, (addr >> 8) as u8, addr as u8]
    }

    /// Erase sector, located at specified byte address
    pub fn sec_ers(&mut self, addr: u32) {
        let addr = self.addr_from_u32(addr);
        self.wait_for_idle();
        //sector erase
        self.spi_flash.write(&[0x06]).unwrap();
        self.spi_flash.write(&[0x20, addr[0], addr[1], addr[2]]).unwrap();
        self.wip_state = WipState::Busy;
    }

    pub fn block64_ers(&mut self, addr: u32) {
        let addr = self.addr_from_u32(addr);
        self.wait_for_idle();
        //sector erase
        self.spi_flash.write(&[0x06]).unwrap();
        self.spi_flash.write(&[0xD8, addr[0], addr[1], addr[2]]).unwrap();
        self.wip_state = WipState::Busy;
    }

    /// Program a single page of data <= 256 bytes
    ///
    /// addr must be aligned to 256 byte page
    pub fn page_prog(&mut self, addr: u32, data: &[u8]) {
        if addr & 0xff != 0 && data.len() > 1 {
            panic!("[ext_flash::page_prog] Address must be aligned to 256 byte page");
        }
        if data.len() > 256 {
            panic!("[ext_flash::page_prog] Data length must be <= 256 page");
        }

        // info!("[ext_flash::page_prog] Writing {} bytes to address {:X}", data.len(), addr);
        let addr = self.addr_from_u32(addr);
        self.wait_for_idle();
        let mut write_data = vec![0; 4 + data.len()];
        write_data[0] = 0x02;
        write_data[1..4].copy_from_slice(&addr);
        write_data[4..].copy_from_slice(data);
        //page program
        self.spi_flash.write(&[0x06]).unwrap();
        self.spi_flash.write(&write_data).unwrap();
        self.wip_state = WipState::Busy;
    }

    /// Erase sectors, covered by bytes in range [start_addr; start_addr+len)
    pub fn erase_range(&mut self, start_addr: u32, len: u32) {
        info!("Erasing flash range...");
        let start_sector_start = start_addr & !0xfff;
        let end_sector_start = (start_addr + len - 1) & !0xfff;

        let mut cur_addr = start_sector_start;
        while cur_addr < end_sector_start {
            if cur_addr & 0xffff == 0 && cur_addr + 0x1_0000 <= end_sector_start {
                debug!("Erasing 64KB block at sector {:X}", cur_addr);
                // block ers
                self.block64_ers(cur_addr);
                cur_addr += 0x1_0000;
            }
            else {
                debug!("Erasing 4Kb sector at {:X}", cur_addr);
                self.sec_ers(cur_addr);
                cur_addr += 0x1000;
            }
        }
    }

    /// Erase covered flash region and write data without length limit
    ///
    /// addr must be aligned to 4096 byte sector
    pub fn write_overwrite(&mut self, mut addr: u32, data: &[u8]) {
        if addr & 0xfff != 0 {
            panic!("[ext_flash::write_overwrite] Address must be aligned to 4096 byte sector");
        }
        debug!("[ext_flash::write_overwrite] Writing {} bytes to address {:X}", data.len(), addr);
        let len = data.len();
        let covered_sectors = (len + 4095) / 4096;
        for i in 0..covered_sectors {
            self.sec_ers(addr + i as u32 * 4096);
        }

        let pages = data.chunks(256);
        for chunk in pages {
            self.page_prog(addr, chunk);
            addr += 256;
        }
    }

    /// Write bytes to flash, without erase operation. Result is AND operation with existing data
    ///
    /// addr must be aligned to 256 byte page
    pub fn write_and(&mut self, mut addr: u32, data: &[u8]) {
        if addr & 0xff != 0 {
            panic!("[ext_flash::write_overwrite] Address must be aligned to 256 byte page");
        }
        debug!("[ext_flash::write_and] Writing {} bytes to address {:X}", data.len(), addr);
        let pages = data.chunks(256);
        for chunk in pages {
            self.page_prog(addr, chunk);
            addr += 256;
        }
    }


    /// Write single byte to flash, without erase operation. Result is AND operation with existing data
    pub fn write_and_byte(&mut self, addr: u32, data: u8) {
        debug!("[ext_flash::write_and] Writing single byte to address {:X}", addr);
        self.page_prog(addr, &[data]);
    }

    /// Read data from flash, starting from any arbitrary address
    pub fn read_boxed(&mut self, addr: u32, len: u32) -> Box<[u8]> {
        debug!("[ext_flash::read_boxed] Reading {} bytes from address {:X}", len, addr);
        let addr = self.addr_from_u32(addr);
        self.wait_for_idle();
        // always use spi flash fast read
        let mut read_buf = vec![0; len as usize + 5];
        let write_buf = vec![0x0b, addr[0], addr[1], addr[2]];
        self.spi_flash.transfer(&mut read_buf, &write_buf).unwrap();

        read_buf[5..].into()
    }
}

impl<'a> Drop for ExtFlash<'a> {
    fn drop(&mut self) {
        self.wait_for_idle();
    }
}