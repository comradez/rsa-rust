#[cfg(test)]
pub mod autobench {
    use test::bench::Bencher;
    use crate::prime_check::{PrimeUtils, encrypt, decrypt};
    use crate::convert::{base64_to_key, key_to_base64};
    use rand::Rng;
    use std::time::Instant;

    #[bench]
    pub fn test_gen_key(b: &mut Bencher) {
        let mut checker = PrimeUtils::new(1024);
        b.iter(|| {
            let (pub_key, pri_key) = checker.gen_key();
            println!("public key is {}", key_to_base64(&pub_key));
            println!("private key is {}", key_to_base64(&pri_key));
        }) 
    }

    #[bench]
    pub fn test_encrypt(b: &mut Bencher) {
        let public_key = base64_to_key(&String::from_utf8(std::fs::read("id_rsa.pub").unwrap()).unwrap());
        let mut rng = rand::thread_rng();
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
            abcdefghijklmnopqrstuvwxyz\
            0123456789)(*&^%$#@!~";
        const LENGTH: u64 = 1000_00;
        let sequence: String = (0 .. LENGTH)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
        b.iter(|| {
            encrypt(&public_key, &sequence);
        })
    }

    #[bench]
    pub fn test_decrypt(b: &mut Bencher) {
        let public_key = base64_to_key(&String::from_utf8(std::fs::read("id_rsa.pub").unwrap()).unwrap());
        let private_key = base64_to_key(&String::from_utf8(std::fs::read("id_rsa").unwrap()).unwrap());
        let mut rng = rand::thread_rng();
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
            abcdefghijklmnopqrstuvwxyz\
            0123456789)(*&^%$#@!~";
        const LENGTH: u64 = 1000_00;
        let sequence: String = (0 .. LENGTH)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
        let secret = encrypt(&public_key, &sequence);
        b.iter(|| {
            decrypt(&private_key, &secret);
        })
    }
}

use crate::prime_check::{PrimeUtils, encrypt, decrypt};
use crate::convert::{base64_to_key, key_to_base64};
use rand::Rng;
use std::time::Instant;

pub fn bench_gen_key() {
    println!("----- Begin bench_gen_key -----");
    let mut checker = PrimeUtils::new(1024);
    let start = Instant::now();
    let (pub_key, pri_key) = checker.gen_key();
    println!("public key is {}", key_to_base64(&pub_key));
    println!("private key is {}", key_to_base64(&pri_key));
    let duration = start.elapsed();
    println!("Time elapsed: {}ms", duration.as_millis());
    println!("------ End bench_gen_key ------\n");
}

pub fn bench_encrypt() {
    println!("----- Begin bench_encrypt -----");
    let public_key = base64_to_key(&String::from_utf8(std::fs::read("id_rsa.pub").unwrap()).unwrap());
    let mut rng = rand::thread_rng();
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
        abcdefghijklmnopqrstuvwxyz\
        0123456789)(*&^%$#@!~";
    const LENGTH: u64 = 1000_000;
    let sequence: String = (0 .. LENGTH)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    let start = Instant::now();
    encrypt(&public_key, &sequence);
    let duration = start.elapsed();
    println!("Time elapsed: {}ms", duration.as_millis());
    println!("------ End bench_encrypt ------\n");
}

pub fn bench_decrypt() {
    println!("----- Begin bench_decrypt -----");
    let public_key = base64_to_key(&String::from_utf8(std::fs::read("id_rsa.pub").unwrap()).unwrap());
    let private_key = base64_to_key(&String::from_utf8(std::fs::read("id_rsa").unwrap()).unwrap());
    let mut rng = rand::thread_rng();
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
        abcdefghijklmnopqrstuvwxyz\
        0123456789)(*&^%$#@!~";
    const LENGTH: u64 = 1000_000;
    let sequence: String = (0 .. LENGTH)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    let secret = encrypt(&public_key, &sequence);
    let start = Instant::now();
    decrypt(&private_key, &secret);
    let duration = start.elapsed();
    println!("Time elapsed: {}ms", duration.as_millis());
    println!("------ End bench_decrypt ------\n");
}