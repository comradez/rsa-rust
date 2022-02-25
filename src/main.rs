use prime_check::miller_rabin_single;

use crate::prime_check::{PrimeUtils, encrypt, decrypt};

mod prime_check;
fn main() {
    let mut checker = PrimeUtils::new(1024);
    let (pub_key, pri_key) = checker.gen_key();
    let message = "moderncryptography";
    let secret = encrypt(&pri_key, message);
    println!("{}", secret);
    let message = decrypt(&pub_key, &secret);
    // checker.is_prime(testee)
    println!("{}", message);
    // println!("{}", miller_rabin_single(&341_u32, 20_u32));
}
