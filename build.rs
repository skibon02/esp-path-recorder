
fn main() {
    println!("cargo:rustc-link-arg=-Wl,-Map=esp32c6.map");
    embuild::espidf::sysenv::output();
}
