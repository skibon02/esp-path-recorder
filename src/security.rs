use core::ffi::c_size_t;
use std::ffi::{c_uchar, c_uint, c_void};
use std::mem::MaybeUninit;
use std::rc::Rc;
use esp_idf_sys::{esp_err_t, SOC_RSA_MAX_BIT_LEN, mbedtls_sha256, esp_fill_random};
use log::{error, info};
use serde::{Deserialize, Serialize};

// use rsa::RsaPublicKey;
// use rsa::pkcs1v15::{Signature, VerifyingKey};
// use rsa::sha2::Sha256;
// use rsa::signature::Verifier;

#[repr(C)]
enum hmac_key_id_t {
    HMAC_KEY0 = 0,
    HMAC_KEY1 = 1,
    HMAC_KEY2,
    HMAC_KEY3,
    HMAC_KEY4,
    HMAC_KEY5,
    HMAC_KEY_MAX,
}

extern "C" {
    fn esp_hmac_calculate(key_id: hmac_key_id_t, message: *const c_void,  message_len: c_size_t, hmac: *mut c_uchar) -> esp_err_t;
}

/// Utilize eFuse key 2 (block6) with purpose HMAC_UP for software integrity check
pub fn calc_hmac(data: &[u8]) -> [u8; 32] {
    let mut hmac = [0; 32];

    unsafe { esp_hmac_calculate(hmac_key_id_t::HMAC_KEY2, data.as_ptr() as *const _, data.len(), hmac.as_mut_ptr()); }
    hmac
}

// /// Helper function to encrypt RSA private params, suitable for further signing
// pub fn encrypt_rsa(rsa_plaintext: &esp_ds_p_data_t, hmac_key: [u8; 32]) -> Option<RsaEncryptedKeyBytes> {
//     let mut iv = [0; 16];
//     fill_random(&mut iv);
//
//     let mut res = esp_ds_data_t::default();
//     let is_err = unsafe { esp_ds_encrypt_params(&mut res, iv.as_ptr() as _, rsa_plaintext, hmac_key.as_ptr() as _) };
//
//     if is_err != 0 {
//         error!("Error encrypting RSA data: {}", is_err);
//         return None;
//     }
//     else {
//         info!("encrypt_rsa finished!");
//     }
//
//     Some(res.into())
// }



fn pkcs1v15_pad(hash: &[u8], key_size: usize) -> [u8; 256] {
    // Ensure the hash is 32 bytes (256 bits)
    assert_eq!(hash.len(), 32, "Hash length must be 32 bytes for SHA-256");

    // PKCS#1 v1.5 padding requires a 15-byte overhead
    let padding_len = key_size - hash.len() - 3 - 19;
    assert!(padding_len >= 8, "Padding length must be at least 8 bytes");

    // DER encoding of SHA-256 algorithm identifier
    let der_prefix = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20
    ];

    let mut padded = [0; 256];
    padded[0] = 0x00;
    padded[1] = 0x01;
    padded[2..padding_len+2].fill(0xFF);
    padded[padding_len+2] = 0x00;

    padded[padding_len+3..padding_len+3+19].copy_from_slice(&der_prefix);
    padded[padding_len+3+19..].copy_from_slice(hash);
    padded
}

// fn sign_rsa_internal(message: &[u32; 64], rsa_encrypted_key: &RsaEncryptedKeyBytes) -> Option<[u32; 64]> {
//     let rsa_encrypted_key_bytes = rsa_encrypted_key.as_ref();
//     let rsa_encrypted_key = rsa_encrypted_key_bytes.as_ptr();
//
//     let mut signature = [0u32; 64];
//     let is_err = unsafe { esp_ds_sign(message.as_ptr() as _, rsa_encrypted_key as *const _, hmac_key_id_t::HMAC_KEY0, signature.as_mut_ptr() as _) };
//
//     if is_err != 0 {
//         error!("Error signing RSA data: {:X}", is_err);
//         return None;
//     }
//     else {
//         info!("sign_rsa finished!");
//     }
//
//     Some(signature)
// }

fn u8_be_to_u32_le<const N: usize>(data: &[u8; N]) -> [u32; N/4] {
    let mut res = [0; N/4];
    for (word, chunk) in res.iter_mut().zip(data.rchunks(4)) {
        *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    res
}

fn u32_le_to_u8_be<const N: usize>(data: &[u32; N]) -> [u8; N*4] {
    let mut res = [0; N*4];
    for (word, chunk) in data.iter().zip(res.rchunks_mut(4)) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    res
}

/// Return SHA-256 hash of the input data in big-endian format
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut sha256 = [0u8; 32];
    let res = unsafe {
        mbedtls_sha256(data.as_ptr() as *const _, data.len(), sha256.as_mut_ptr(), 0)
    };
    if res != 0 {
        error!("Error calculating sha256: {}", res);
    }
    sha256
}

// /// Sign a message using RSA with PKCS#1 v1.5 padding
// pub fn sign_rsa(message: &[u8], rsa_encrypted_key: &RsaEncryptedKeyBytes) -> Option<Box<[u8; 256]>> {
//     let sha256 = sha256(message);
//     let padded = pkcs1v15_pad(&sha256, 256);
//     let message = u8_be_to_u32_le(&padded);
//
//     assert_eq!(padded, u32_le_to_u8_be(&message));
//
//     let u32_le_res = sign_rsa_internal(&message, rsa_encrypted_key)?;
//     Some(Box::new(u32_le_to_u8_be(&u32_le_res)))
// }
//
// pub fn verify_signature(message: &[u8], signature: &[u8], pub_exponent: &[u8; 256], pub_modulus: &[u8; 256]) -> bool {
//     let exp = rsa::BigUint::from_bytes_be(pub_exponent);
//     let modulus = rsa::BigUint::from_bytes_be(pub_modulus);
//
//     let pub_key = RsaPublicKey::new(modulus, exp).expect("Invalid public key");
//     let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(pub_key);
//
//     let signature = Signature::try_from(signature).expect("Invalid signature");
//
//     match verifying_key.verify(
//         message,
//         &signature
//     ) {
//         Ok(_) => true,
//         Err(e) => {
//             error!("Error verifying signature: {}", e);
//             false
//         }
//     }
// }
pub fn fill_random(data: &mut [u8]) {
    unsafe {
        esp_fill_random(data.as_mut_ptr() as _, data.len());
    }
}

// #[repr(C)]
// #[derive(Debug)]
// pub struct esp_ds_p_data_t {
//     pub y: [u32; SOC_RSA_MAX_BIT_LEN as usize / 32],
//     pub m: [u32; SOC_RSA_MAX_BIT_LEN as usize / 32],
//     pub rb: [u32; SOC_RSA_MAX_BIT_LEN as usize / 32],
//     pub m_prime: u32,
//     pub length: u32
// }
//
//
// #[repr(C)]
// #[derive(Debug)]
// pub struct esp_ds_data_t {
//     rsa_length: c_uint,
//     iv: [u8; 16],
//     c: [u8; SOC_RSA_MAX_BIT_LEN as usize * 3 / 8 + 32 + 8 + 8],
// }
// impl Default for esp_ds_data_t {
//     fn default() -> Self {
//         Self {
//             rsa_length: 0,
//             iv: [0; 16],
//             c: [0; SOC_RSA_MAX_BIT_LEN as usize * 3 / 8 + 32 + 8 + 8]
//         }
//     }
//
// }


// /// RSA encrypted private params, RSA public signature
// pub type LocalRsaKey = (RsaEncryptedKeyBytes, [u8; 32]);
//
// pub type RsaEncryptedKeyBytes = Rc<[u8]>;
//
// #[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
// pub struct RsaPublicKeypair {
//     pub_exp: Rc<[u8]>,
//     pub_mod: Rc<[u8]>,
// }
//
// impl RsaPublicKeypair {
//     pub fn new(pub_exp: &[u8; 256], pub_mod: &[u8; 256]) -> Self {
//         Self {
//             pub_exp: Rc::from(pub_exp.to_vec()),
//             pub_mod: Rc::from(pub_mod.to_vec()),
//         }
//     }
//     pub fn get_remote_identity(&self) -> RemoteIdentity {
//         let combined = [self.pub_exp.as_ref(), self.pub_mod.as_ref()].concat();
//         RemoteIdentity::from_sha256(sha256(&combined))
//     }
//     pub fn pub_exp(&self) -> &[u8; 256] {
//         self.pub_exp.as_ref().try_into().unwrap()
//     }
//     pub fn pub_mod(&self) -> &[u8; 256] {
//         self.pub_mod.as_ref().try_into().unwrap()
//     }
// }
//
// impl From<RsaEncryptedKeyBytes> for esp_ds_data_t {
//     fn from(data: RsaEncryptedKeyBytes) -> Self {
//         let mut res = MaybeUninit::<esp_ds_data_t>::uninit();
//         unsafe {
//             std::ptr::copy_nonoverlapping(data.as_ptr(), res.as_mut_ptr() as *mut u8, size_of::<esp_ds_data_t>());
//             res.assume_init()
//         }
//     }
// }
//
// impl From<esp_ds_data_t> for RsaEncryptedKeyBytes {
//     fn from(data: esp_ds_data_t) -> Self {
//         let mut res = [0; size_of::<esp_ds_data_t>()];
//         unsafe {
//             std::ptr::copy_nonoverlapping(&data as *const _ as *const u8, res.as_mut_ptr(), size_of::<esp_ds_data_t>());
//         }
//         res.into()
//     }
// }
// impl Default for esp_ds_p_data_t {
//     fn default() -> Self {
//         Self {
//             y: [0; SOC_RSA_MAX_BIT_LEN as usize / 32],
//             m: [0; SOC_RSA_MAX_BIT_LEN as usize / 32],
//             rb: [0; SOC_RSA_MAX_BIT_LEN as usize / 32],
//             m_prime: 0,
//             length: 0
//         }
//     }
// }