use std::fmt::LowerHex;

use num_bigint_dig::BigUint;
use num_bigint_dig::RandBigInt;
use num_bigint_dig::RandPrime;
use num_bigint_dig::BigInt;
use num_bigint_dig::ToBigInt;
use num_traits::{One, RefNum, Zero};
use rand::{prelude::ThreadRng, thread_rng};

pub struct PrimeUtils {
    bit_size: usize,
    times: usize,
    rng: ThreadRng,
}

type RSAPublicKey = (BigUint, BigUint);
type RSAPrivateKey = (BigUint, BigUint);

impl PrimeUtils {
    pub fn new(bit_size: usize) -> Self {
        let bit_size_f64 = bit_size as f64;
        let times = (bit_size_f64 / bit_size_f64.ln() / 2_f64) as usize;
        // println!("Times is {}", &times);
        Self {
            bit_size,
            times,
            rng: thread_rng(),
        }
    }

    fn is_prime(&mut self, testee: &BigUint) -> bool {
        let mut count = 0;
        let one: BigUint = One::one();
        let testee_minus_one: BigUint = testee.clone() - &one;
        while count < self.times {
            let rand_num = self.rng.gen_biguint(self.bit_size) % testee;
            if &rand_num == &one || &rand_num == &testee_minus_one {
                continue;
            }
            if !miller_rabin_single(testee, rand_num.clone()) {
                println!("This is not a prime");
                return false;
            }
            count += 1;
        }
        true
    }

    pub fn gen_key(&mut self) -> (RSAPublicKey, RSAPrivateKey) {
        // (pub_key, pri_key)
        // ((N, e), (N, d))
        let e = BigUint::from(65537_u32);
        loop {
            let p = self.rng.gen_prime(self.bit_size);
            let q = self.rng.gen_prime(self.bit_size);
            let n = &p * &q;
            let phi = &n - &p - &q + BigUint::from(1_u32);
            let (mut x, _, d) = exgcd(&e, &phi);
            if d == One::one() {
                if x < Zero::zero() {
                    let k = (-&x).to_biguint().unwrap() / &phi + BigUint::from(1_u32);
                    x = x + (k * &phi).to_bigint().unwrap();
                }
                let x = x.to_biguint().unwrap();
                // println!("{}", &e * &x % &phi);
                assert!(self.test_key(&phi, &e, &x));
                break ((n.clone(), e), (n, x))
            }
        }
    }

    pub fn test_key(&self, phi: &BigUint, e: &BigUint, d: &BigUint) -> bool {
        return e * d % phi == One::one();
    }
}

fn encrypt_uint(private_key: &RSAPublicKey, message: &BigUint) -> BigUint {
    let (n, e) = private_key;
    quick_pow(message.clone(), e.clone(), Some(n.clone()))
}

fn decrypt_uint(public_key: &RSAPrivateKey, secret: &BigUint) -> BigUint {
    let (n, d) = public_key;
    quick_pow(secret.clone(), d.clone(), Some(n.clone()))
}

pub fn oct_to_str(encoded: BigUint) -> String {
    let ret = unsafe {
        String::from_utf8_unchecked(encoded
            .to_bytes_be()
        )
    };
    println!("From oct is: {}", ret);
    ret    
}

fn str_to_oct(to_encode: &str) -> BigUint {
    BigUint::from_radix_be(to_encode.as_bytes(), 256).unwrap()
}

pub fn encrypt(private_key: &RSAPublicKey, message: &str) -> String {
    oct_to_str(encrypt_uint(private_key, &str_to_oct(message)))
}

pub fn decrypt(public_key: &RSAPrivateKey, secret: &str) -> String {
    oct_to_str(decrypt_uint(public_key, &str_to_oct(secret)))
}

pub fn miller_rabin_single<T>(testee: &T, base: T) -> bool
where
    T: RefNum<T> + From<u32> + Ord + Clone,
    for<'a> &'a T: RefNum<T>,
{
    let exp: T = testee.clone() - T::from(1_u32);
    quick_pow(base, exp, Some(testee.clone())) == 1.into()
}

pub fn quick_pow<T>(base: T, mut exp: T, prime: Option<T>) -> T
where
    T: RefNum<T> + From<u32> + Ord,
    for<'a> &'a T: RefNum<T>,
{
    let mut temp_val = if let Some(prime) = &prime {
        base % prime
    } else {
        base
    };
    let mut return_val: T = 1.into();
    let one: T = 1.into();
    let two: T = 2.into();
    while exp >= one {
        if let Some(prime) = &prime {
            temp_val = temp_val % prime;
        }
        if &exp % &two == one {
            return_val = return_val * &temp_val;
        }
        temp_val = &temp_val * &temp_val;
        exp = exp / &two;
    }
    if let Some(prime) = &prime {
        return_val % prime
    } else {
        return_val
    }
}

pub fn exgcd(first: &BigUint, second: &BigUint) -> (BigInt, BigInt, BigInt) {
    let (a, b) = if first > second {
        (first.clone(), second.clone())
    } else {
        (second.clone(), first.clone())
    }; // a >= b
    let mut pair: ((BigInt, BigInt, BigInt), (BigInt, BigInt, BigInt)) = (
        (One::one(), Zero::zero(), BigInt::from(a)),
        (Zero::zero(), One::one(), BigInt::from(b))
    );
    while pair.1.2 != Zero::zero() {
        let q = &(&pair.0).2 / &(&pair.1).2;
        let new_pair_1 = (
            (pair.0).0 - &q * &(&pair.1).0,
            (pair.0).1 - &q * &(&pair.1).1,
            (pair.0).2 - &q * &(&pair.1).2
        );
        pair = (pair.1, new_pair_1)
    }
    if first > second {
        pair.0
    } else {
        ((pair.0).1, (pair.0).0, (pair.0).2)
    }
}