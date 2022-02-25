use std::fmt::{Debug, Display};
use std::process::Output;
use std::ops::Sub;

use num::{BigUint, BigInt};
use num::bigint::{ToBigInt, RandBigInt, ToBigUint};
use num::traits::{One, RefNum, Zero, int};
use num::Integer;
use rand::{prelude::ThreadRng, thread_rng};

pub struct PrimeUtils {
    bit_size: u64,
    rng: ThreadRng,
    current_p: Option<BigUint>
}

type RSAPublicKey = (BigUint, BigUint);
type RSAPrivateKey = (BigUint, BigUint);

impl PrimeUtils {
    pub fn new(bit_size: u64) -> Self {
        Self {
            bit_size,
            rng: thread_rng(),
            current_p: None
        }
    }

    fn is_prime(&mut self) -> bool {
        self.current_p.as_ref().map_or(false, |testee| {
            let mut count = 0;
            let one: BigUint = One::one();
            let testee_minus_one: BigUint = testee.clone() - &one;
            // let prime_factor = Factorization::prime_factor(testee_minus_one).unwrap();
            while count < 10 {
                let rand_num = self.rng.gen_biguint(self.bit_size) % testee;
                if &rand_num == &one || &rand_num == &testee_minus_one {
                    continue;
                }
                if !miller_rabin_single(testee, rand_num.clone()) {
                    // println!("This is not a prime");
                    return false;
                }
                count += 1;
            }
            true
        })
    }

    pub fn gen_prime(&mut self) -> BigUint {
        if self.current_p.is_none() {
            let random_val = self.rng.gen_biguint(self.bit_size);
            self.current_p = Some(if &random_val % BigUint::from(2_u32) == Zero::zero() {
                random_val + BigUint::from(1_u32)
            } else {
                random_val
            });
        }
        loop {
            if self.is_prime() {
                break self.current_p.as_ref().unwrap().clone()
            } else {
                self.current_p = Some(self.current_p.as_ref().unwrap() + BigUint::from(2_u32))
            }
        }
    }

    pub fn gen_key(&mut self) -> (RSAPublicKey, RSAPrivateKey) {
        // (pub_key, pri_key)
        // ((N, e), (N, d))
        let e = BigUint::from(65537_u32);
        loop {
            let p = self.gen_prime();
            let q = self.gen_prime();
            // let p = self.rng.gen_prime(self.bit_size);
            // let q = self.rng.gen_prime(self.bit_size);
            let n = &p * &q;
            let phi = &n - &p - &q + BigUint::from(1_u32);
            let result = BigInt::extended_gcd(&e.to_bigint().unwrap(), &phi.to_bigint().unwrap());
            let (mut x, d) = (result.x, result.gcd);
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

fn get_rank<T>(testee: &T) -> T
where
    T: RefNum<T> + From<u32> + Ord + Clone,
    for<'a> &'a T: RefNum<T>,
{
    let zero = T::from(0_u32);
    let one = T::from(1_u32);
    let two = T::from(2_u32);
    let mut num: T = testee.clone() - &one;
    while &num % &two == zero {
        num = num / &two;
    }
    num
}

fn encrypt_uint(private_key: &RSAPublicKey, message: &BigUint) -> BigUint {
    let (n, e) = private_key;
    quick_pow(message.clone(), e.clone(), Some(n.clone()))
}

fn decrypt_uint(public_key: &RSAPrivateKey, secret: &BigUint) -> BigUint {
    let (n, d) = public_key;
    quick_pow(secret.clone(), d.clone(), Some(n.clone()))
}

pub fn oct_to_base64(octet: &BigUint) -> String {
    base64::encode(octet.to_bytes_be())
}

pub fn base64_to_oct(base64: &str) -> BigUint {
    BigUint::from_bytes_be(&base64::decode(base64.as_bytes()).unwrap())
}

pub fn oct_to_str(encoded: BigUint) -> String {
    unsafe {
        String::from_utf8_unchecked(encoded
            .to_bytes_be()
        )
    }
}

fn str_to_oct(to_encode: &str) -> BigUint {
    BigUint::from_radix_be(to_encode.as_bytes(), 256).unwrap()
}

pub fn encrypt(private_key: &RSAPublicKey, message: &str) -> String {
    oct_to_base64(&encrypt_uint(private_key, &str_to_oct(message)))
}

pub fn decrypt(public_key: &RSAPrivateKey, secret: &str) -> String {
    oct_to_str(decrypt_uint(public_key, &base64_to_oct(secret)))
}

pub fn miller_rabin_single<T>(testee: &T, base: T) -> bool
where
    T: RefNum<T> + From<u32> + Ord + Clone + Display,
    for<'a> &'a T: RefNum<T>,
{
    let mut exp: T = get_rank(testee);
    // println!("testee is {}, rank is {}", &testee, &exp);
    let one: T = 1.into();
    let two: T = 2.into();
    let testee_minus_one = testee - &one;
    let mut intermediate = quick_pow(base.clone(), exp.clone(), Some(testee.clone()));
    if intermediate == one {
        return true;
    }
    exp = exp * &two;
    while &exp <= testee {
        intermediate = &intermediate * &intermediate % testee;
        if intermediate == testee_minus_one {
            return true;
        }
        exp = exp * &two;
    }
    false
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