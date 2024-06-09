//! The Trivium synchronous stream cipher.
//!
//! Cipher functionality is accessed using traits from re-exported
//! [`stream-cipher`](https://docs.rs/stream-cipher) crate.
//!
//! # Security Warning
//!
//! This crate does not ensure ciphertexts are authentic! Thus ciphertext integrity
//! is not verified, which can lead to serious vulnerabilities!
//!
//! # Usage
//!
//! ```
//! use trivium::Trivium;
//! use trivium::stream_cipher::generic_array::GenericArray;
//! use trivium::stream_cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
//!
//! let mut data = [1, 2, 3, 4, 5, 6, 7];
//! 
//! let key = GenericArray::from_slice(b"an example");
//! let nonce = GenericArray::from_slice(b"a nonce...");
//! 
//! // create cipher instance
//! let mut cipher = Trivium::new(&key, &nonce);
//! 
//! // apply keystream (encrypt)
//! cipher.apply_keystream(&mut data);
//! assert_eq!(data, [1, 181, 178, 4, 216, 223, 247]);
//! 
//! // reset instance and apply it again to the `data` (decrypt)
//! let mut cipher = Trivium::new(&key, &nonce);
//! cipher.apply_keystream(&mut data);
//! assert_eq!(data, [1, 2, 3, 4, 5, 6, 7]);
//! ```

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs, rust_2018_idioms, trivial_casts, unused_qualifications)]

pub use stream_cipher;

use block_cipher_trait::generic_array::typenum::U10;
use block_cipher_trait::generic_array::GenericArray;
use stream_cipher::{LoopError, NewStreamCipher, SyncStreamCipher};

/// Size of a Trivium key in bytes (80-bits)
pub const KEY_SIZE: usize = 10;

/// Number of bytes in the Trivium IV (80-bits)
const IV_SIZE: usize = 10;

/// Number of 32-bit words in the Trivium state (288-bits)
const STATE_WORDS: usize = 10; // actually 9 + 1 for padding

/// The Trivium cipher.
#[derive(Debug)]
pub struct Trivium {
    state: [u32; STATE_WORDS],
}

macro_rules! load_u32 {
    ($d:ident, $i:expr) => {{
        $d[(4 * $i) + 0] as u32 & 0xff
            | ($d[(4 * $i) + 1] as u32 & 0xff) << 8
            | ($d[(4 * $i) + 2] as u32 & 0xff) << 16
            | ($d[(4 * $i) + 3] as u32 & 0xff) << 24
    }};
}

macro_rules! store_u32 {
    ($o:ident, $i:ident, $d:expr) => {{
        $o[(4 * $i) + 0] = ($d >> 0) as u8;
        $o[(4 * $i) + 1] = ($d >> 8) as u8;
        $o[(4 * $i) + 2] = ($d >> 16) as u8;
        $o[(4 * $i) + 3] = ($d >> 24) as u8;
    }};
}

fn setup(key: &[u8], iv: &[u8]) -> [u32; STATE_WORDS] {
    let mut data = [0u8; STATE_WORDS * 4];
    // 96 bits
    for i in 0..KEY_SIZE {
        data[i] = key[i]
    }
    for i in KEY_SIZE..12 {
        data[i] = 0;
    }
    // 96 bits
    for i in 0..IV_SIZE {
        data[12 + i] = iv[i]
    }
    for i in IV_SIZE..12 {
        data[12 + i] = 0;
    }
    for i in 0..13 {
        data[24 + i] = 0
    }
    data[24 + 13] = 0x70;
    let mut r = [0; STATE_WORDS];
    for i in 0..STATE_WORDS {
        r[i] = load_u32!(data, i);
    }
    r
}

impl Trivium {
    /// Creates a Trivium synchronous stream cipher instance.
    //pub fn new(key: &[u8], iv: &[u8]) -> Self {
    pub fn new(key: &GenericArray<u8, U10>, iv: &GenericArray<u8, U10>) -> Self {
        let mut t = Trivium {
            state: setup(&key, &iv),
        };
        for _ in 0..4 * 9 {
            let [s11, s12, s13, s21, s22, s23, s31, s32, s33, s34] = t.state;
            macro_rules! s1 {
                ($e:literal) => {
                    (s13 << (96 - $e)) | (s12 >> ($e - 64))
                };
            }
            macro_rules! s2 {
                ($e:literal) => {
                    (s23 << (96 - $e)) | (s22 >> ($e - 64))
                };
            }
            macro_rules! s3 {
                ($e:literal) => {
                    (s33 << (96 - $e)) | (s32 >> ($e - 64))
                };
            }
            macro_rules! s4 {
                ($e:literal) => {
                    (s34 << (128 - $e)) | (s33 >> ($e - 96))
                };
            }
            let t1 = s1!(66) ^ s1!(91) & s1!(92) ^ s1!(93) ^ s2!(78);
            let t2 = s2!(69) ^ s2!(82) & s2!(83) ^ s2!(84) ^ s3!(87);
            let t3 = s3!(66) ^ s4!(109) & s4!(110) ^ s4!(111) ^ s1!(69);
            t.state = [t3, s11, s12, t1, s21, s22, t2, s31, s32, s33];
        }
        t
    }

    /// Process a stream of input in-place
    pub fn process(&mut self, data: &mut [u8]) {
        let block = data.len() / 4;
        let remainder = data.len() % 4;
        for i in 0..block {
            let [s11, s12, s13, s21, s22, s23, s31, s32, s33, s34] = self.state;
            macro_rules! s1 {
                ($e:literal) => {
                    (s13 << (96 - $e)) | (s12 >> ($e - 64))
                };
            }
            macro_rules! s2 {
                ($e:literal) => {
                    (s23 << (96 - $e)) | (s22 >> ($e - 64))
                };
            }
            macro_rules! s3 {
                ($e:literal) => {
                    (s33 << (96 - $e)) | (s32 >> ($e - 64))
                };
            }
            macro_rules! s4 {
                ($e:literal) => {
                    (s34 << (128 - $e)) | (s33 >> ($e - 96))
                };
            }
            let t1 = s1!(66) ^ s1!(93);
            let t2 = s2!(69) ^ s2!(84);
            let t3 = s3!(66) ^ s4!(111);
            let z = t1 ^ t2 ^ t3;
            store_u32!(data, i, load_u32!(data, i) ^ z);
            let t1 = t1 ^ s1!(91) & s1!(92) ^ s2!(78);
            let t2 = t2 ^ s2!(82) & s2!(83) ^ s3!(87);
            let t3 = t3 ^ s4!(109) & s4!(110) ^ s1!(69);
            self.state = [t3, s11, s12, t1, s21, s22, t2, s31, s32, s33];
        }
        if remainder > 0 {
            let [s11, s12, s13, s21, s22, s23, s31, s32, s33, s34] = self.state;
            macro_rules! s1 {
                ($e:literal) => {
                    (s13 << (96 - $e)) | (s12 >> ($e - 64))
                };
            }
            macro_rules! s2 {
                ($e:literal) => {
                    (s23 << (96 - $e)) | (s22 >> ($e - 64))
                };
            }
            macro_rules! s3 {
                ($e:literal) => {
                    (s33 << (96 - $e)) | (s32 >> ($e - 64))
                };
            }
            macro_rules! s4 {
                ($e:literal) => {
                    (s34 << (128 - $e)) | (s33 >> ($e - 96))
                };
            }
            let t1 = s1!(66) ^ s1!(93);
            let t2 = s2!(69) ^ s2!(84);
            let t3 = s3!(66) ^ s4!(111);
            let mut z = t1 ^ t2 ^ t3;
            let t1 = t1 ^ s1!(91) & s1!(92) ^ s2!(78);
            let t2 = t2 ^ s2!(82) & s2!(83) ^ s3!(87);
            let t3 = t3 ^ s4!(109) & s4!(110) ^ s1!(69);
            self.state = [t3, s11, s12, t1, s21, s22, t2, s31, s32, s33];
/*
            let b = block * 4;
            for i in b..b + remainder {
                data[i] = data[i] ^ (z & 0xff) as u8;
                z >>= 8;
            }
*/
            for byte in data.iter_mut().skip(block * 4).take(remainder) {
                let v = *byte;
                *byte = v ^ (z & 0xff) as u8;
                z >>= 8;
            }
        }
    }
}

impl NewStreamCipher for Trivium {
    /// Key size in bytes
    type KeySize = U10;

    /// Nonce size in bytes
    type NonceSize = U10;

    fn new(key: &GenericArray<u8, Self::KeySize>, iv: &GenericArray<u8, Self::NonceSize>) -> Self {
        Trivium::new(&key, &iv)
    }
}

impl SyncStreamCipher for Trivium {
    fn try_apply_keystream(&mut self, mut data: &mut [u8]) -> Result<(), LoopError> {
        self.process(&mut data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup() {
        let key = [0x10; KEY_SIZE];
        let iv = [0x0f; IV_SIZE];
        let state = [
            3643845612, 2495511203, 4058779361, 2349380106, 1431260227, 3896559603, 966649850,
            3524433667, 2697193510, 2546550395,
        ];

        let trivium = Trivium::new(&key.into(), &iv.into());
        assert_eq!(state, trivium.state);

        let key = [0; KEY_SIZE];
        let iv = [0; IV_SIZE];
        let state = [
            1955797637, 1764419101, 3793434860, 91357893, 1411422466, 3096799615, 3300326026,
            2889411024, 608113471, 46516566,
        ];
        let trivium = Trivium::new(&key.into(), &iv.into());
        assert_eq!(state, trivium.state);
    }

    #[test]
    fn process_1_byte() {
        let key = [0x0; KEY_SIZE];
        let iv = [0x0; IV_SIZE];
        let mut data = [0x0; 1];
        let check = data;

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, [100]);

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, check);
    }

    #[test]
    fn process_2_bytes() {
        let key = [0x0; KEY_SIZE];
        let iv = [0x0; IV_SIZE];
        let mut data = [0x0; 2];
        let check = data;

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, [100, 253]);

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, check);
    }

    #[test]
    fn process_3_bytes() {
        let key = [0x0; KEY_SIZE];
        let iv = [0x0; IV_SIZE];
        let mut data = [0x0; 3];
        let check = data;

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, [100, 253, 7]);

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, check);
    }

    #[test]
    fn process_4_bytes() {
        let key = [0x0; KEY_SIZE];
        let iv = [0x0; IV_SIZE];
        let mut data = [0x0; 4];
        let check = data;

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, [100, 253, 7, 223]);

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, check);
    }

    #[test]
    fn process_5_bytes() {
        let key = [0x0; KEY_SIZE];
        let iv = [0x0; IV_SIZE];
        let mut data = [0x0; 5];
        let check = data;

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, [100, 253, 7, 223, 216]);

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, check);
    }

    #[test]
    fn process_6_bytes() {
        let key = [0x0; KEY_SIZE];
        let iv = [0x0; IV_SIZE];
        let mut data = [0x0; 6];
        let check = data;

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, [100, 253, 7, 223, 216, 160]);

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, check);
    }

    #[test]
    fn process_7_bytes() {
        let key = [0x0; KEY_SIZE];
        let iv = [0x0; IV_SIZE];
        let mut data = [0x0; 7];
        let check = data;

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, [100, 253, 7, 223, 216, 160, 154]);

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, check);
    }

    #[test]
    fn process_8_bytes() {
        let key = [0x0; KEY_SIZE];
        let iv = [0x0; IV_SIZE];
        let mut data = [0x0; 8];
        let check = data;

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, [100, 253, 7, 223, 216, 160, 154, 26]);

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, check);
    }

    #[test]
    fn process_9_bytes() {
        let key = [0x0; KEY_SIZE];
        let iv = [0x0; IV_SIZE];
        let mut data = [0x0; 9];
        let check = data;

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, [100, 253, 7, 223, 216, 160, 154, 26, 114]);

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, check);
    }

    #[test]
    fn process_24_bytes() {
        let key = [0x0; KEY_SIZE];
        let iv = [0x0; IV_SIZE];
        let mut data = [0x0; 24];
        let check = data;

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(
            data,
            [
                100, 253, 7, 223, 216, 160, 154, 26, 114, 116, 94, 138, 254, 147, 249, 196, 104,
                192, 76, 106, 180, 243, 224, 152
            ]
        );

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, check);
    }

    #[test]
    fn process_10_bytes_key_iv() {
        let key = [0x10u8; KEY_SIZE];
        let iv = [0x0fu8; IV_SIZE];
        let mut data = [0x10; KEY_SIZE];
        let check = data;

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, [197, 82, 249, 84, 126, 79, 33, 181, 157, 84]);

        let mut trivium = Trivium::new(&key.into(), &iv.into());
        trivium.process(&mut data);
        assert_eq!(data, check);
    }
}
