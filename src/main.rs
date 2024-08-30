#![feature(c_size_t)]
#![feature(generic_const_exprs)]

use std::panic::set_hook;
use std::ptr::null_mut;
use std::time::Duration;
use esp_idf_svc::hal::delay::Delay;
use esp_idf_svc::hal::i2c::{I2cConfig, I2cDriver};
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::hal::prelude::FromValueType;
use esp_idf_svc::hal::reset;
use esp_idf_svc::hal::spi::{config, SpiDeviceDriver, SpiDriver, SpiDriverConfig};
use esp_idf_sys::{esp, esp_vfs_dev_uart_use_driver, uart_driver_install};
use log::{error, info};
use mpu6050::device::AccelRange;
use crate::ext_flash::ExtFlash;
use crate::storage_driver::{StorageDriver, StoredPagesInfoParam};

mod led_control;
mod storage_driver;
mod ext_flash;
mod security;

const SPI_FREQ_MHZ: u32 = 10;
const I2C_FREQ_KHZ: u32 = 400;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // It is necessary to call this function once. Otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    // esp_idf_svc::log::set_target_level("*", log::LevelFilter::Info)?;
    // esp_idf_svc::log::set_target_level("acoustic_sensor_device", log::LevelFilter::Trace)?;
    // esp_idf_svc::log::set_target_level("acoustic_sensor_device::server_connection::at_parser", log::LevelFilter::Trace)?;

    esp_idf_svc::log::EspLogger::initialize_default();

    log::trace!("TRACE");
    log::debug!("DEBUG");
    // To enable uart0 rx over stdin
    unsafe {
        esp!(uart_driver_install(0, 512, 512, 10, null_mut(), 0)).unwrap();
        esp_vfs_dev_uart_use_driver(0);
    }

    let last_reset_reason = reset::ResetReason::get();
    info!("\n\n\t\t*** ESP32C6 STARTUP ***");
    info!("Last reset reason: {:?}", last_reset_reason);

    set_hook(Box::new(|panic_info| {
        error!("Panic: {:?}", panic_info);
        // try downcast to str
        if let Some(payload) = panic_info.payload().downcast_ref::<&str>() {
            error!("{}", payload);
        }
        if let Some(payload) = panic_info.payload().downcast_ref::<String>() {
            error!("{}", payload);
        }

        // reboot?...
    }));

    let mut peripherals = Peripherals::take()?;

    led_control::start_task(peripherals.pins.gpio8, peripherals.rmt.channel0);

    let cfg = SpiDriverConfig::new();
    let spi = SpiDriver::new(peripherals.spi2, peripherals.pins.gpio19, peripherals.pins.gpio18, Some(peripherals.pins.gpio20), &cfg)?;
    let cfg = config::Config::new().baudrate(SPI_FREQ_MHZ.MHz().into());
    let spi_ext_flash = SpiDeviceDriver::new(&spi, Some(peripherals.pins.gpio21), &cfg)?;
    let mut storage_driver = StorageDriver::new(ExtFlash::new(spi_ext_flash));

    // if !storage_driver.self_test() {
    //     panic!("Storage self test failed!");
    // }

    // Setup rtc module
    let i2c_config = I2cConfig::new().baudrate(I2C_FREQ_KHZ.kHz().into());
    let i2c_rtc = I2cDriver::new(peripherals.i2c0, peripherals.pins.gpio22, peripherals.pins.gpio23, &i2c_config)?;

    let mut mpu = mpu6050::Mpu6050::new(i2c_rtc);
    let mut delay = Delay::default();
    mpu.init(&mut delay).unwrap();

    mpu.set_accel_range(AccelRange::G16).unwrap();

    let pages_info = storage_driver.read_reg_or_set_default::<StoredPagesInfoParam>();
    info!("Pages info: {pages_info:?}");

    loop {
        let angles = mpu.get_acc_angles().unwrap();
        let angles2 = mpu.get_acc_angles().unwrap();
        info!("Accel angles: {:?}", angles);
        info!("Accel angles: {:?}", angles2);

        let gyro = mpu.get_gyro().unwrap();
        info!("Gyro: {:?}", gyro);

        std::thread::sleep(Duration::from_millis(500));
    }
}