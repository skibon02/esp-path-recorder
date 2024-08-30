use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use atomic_enum::atomic_enum;
use esp_idf_svc::hal::gpio::Gpio8;
use esp_idf_svc::hal::rmt;
use ws2812_esp32_rmt_driver::driver::color::LedPixelColorGrb24;
use ws2812_esp32_rmt_driver::{LedPixelEsp32Rmt, RGB8};
use smart_leds_trait::SmartLedsWrite;

#[derive(Copy, Clone)]
enum FavColors {
    Pink,
    Magenta,
    Cyan,
    Green,
    Red,
    Blue,

    None,
    Yellow,
    White,
    Purple,
}

impl FavColors {
    fn to_rgb(&self) -> RGB8 {
        match self {
            FavColors::Pink => RGB8 { r: 200, g: 50, b: 170 },
            FavColors::Magenta => RGB8 { r: 255, g: 0, b: 255 },
            FavColors::Cyan => RGB8 { r: 0, g: 255, b: 255 },
            FavColors::Green => RGB8 { r: 0, g: 255, b: 0 },
            FavColors::Red => RGB8 { r: 255, g: 0, b: 0 },
            FavColors::None => RGB8 { r: 0, g: 0, b: 0 },
            FavColors::Yellow => RGB8 { r: 255, g: 255, b: 0 },
            FavColors::White => RGB8 { r: 255, g: 160, b: 66 },
            FavColors::Blue => RGB8 { r: 0, g: 0, b: 255 },
            FavColors::Purple => RGB8 { r: 50, g: 0, b: 200 },
        }
    }
}


#[atomic_enum]
#[derive(Eq, PartialEq)]
pub enum LedMode {
    Running,
    Recording,

    CriticalError,
}

static LED_MODE: AtomicLedMode = AtomicLedMode::new(LedMode::Running);

fn set_led_colors(ws2812: &mut LedPixelEsp32Rmt<RGB8, LedPixelColorGrb24>, color1_mgmt: FavColors) {
    let brightness = 1.0;
    let mut color1_mgmt = color1_mgmt.to_rgb();
    color1_mgmt.r = (color1_mgmt.r as f32 * brightness) as u8;
    color1_mgmt.g = (color1_mgmt.g as f32 * brightness) as u8;
    color1_mgmt.b = (color1_mgmt.b as f32 * brightness) as u8;

    ws2812.write([color1_mgmt]).unwrap();
}

pub fn set_led_mode(mode: LedMode) -> LedMode {
    let old_led_mode = LED_MODE.load(Ordering::Relaxed);
    LED_MODE.store(mode, Ordering::Relaxed);
    old_led_mode
}

pub fn wait_and_monitor_change(ms: u64, last_state: LedMode) -> bool {
    let start = std::time::Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(100));
        if LED_MODE.load(Ordering::Relaxed) != last_state {
            return true;
        }
        if start.elapsed().as_millis() as u64 > ms {
            return false;
        }
    }
}


pub static IS_LED_DISABLED: AtomicBool = AtomicBool::new(false);

pub fn disable_indication() {
    IS_LED_DISABLED.store(true, Ordering::Relaxed)
}

pub fn enable_indication() {
    IS_LED_DISABLED.store(false, Ordering::Relaxed)
}

pub fn start_task(led_pin: Gpio8, channel: rmt::CHANNEL0) {
    std::thread::spawn(move || {
        let mut ws2812 = LedPixelEsp32Rmt::<RGB8, LedPixelColorGrb24>::new(channel, led_pin).unwrap();

        let mut color = FavColors::None;
        set_led_colors(&mut ws2812, color);

        loop {
            if IS_LED_DISABLED.load(Ordering::Relaxed) {
                color = FavColors::None;
                set_led_colors(&mut ws2812, color);
                thread::sleep(Duration::from_millis(1_000));
                continue;
            }

            let cur_mode = LED_MODE.load(Ordering::Relaxed);
            match cur_mode {
                LedMode::Running=> {
                    color = FavColors::Green;
                    set_led_colors(&mut ws2812, color);
                    if wait_and_monitor_change(300, cur_mode) { continue; }
                }
                LedMode::Recording => {
                    color = FavColors::Cyan;
                    set_led_colors(&mut ws2812, color);
                    if wait_and_monitor_change(100, cur_mode) { continue; }

                    color = FavColors::Pink;
                    set_led_colors(&mut ws2812, color);
                    if wait_and_monitor_change(300, cur_mode) { continue; }
                }
                LedMode::CriticalError => {
                    color = FavColors::Red;
                    set_led_colors(&mut ws2812, color);
                    if wait_and_monitor_change(300, cur_mode) { continue; }

                    color = FavColors::None;
                    set_led_colors(&mut ws2812, color);
                    if wait_and_monitor_change(300, cur_mode) { continue; }
                }
            }
        }
    });
}