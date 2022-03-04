use num::BigUint;

pub fn key_to_base64(key: &(BigUint, BigUint)) -> String {
    oct_to_base64(&key.0) + "-" + &oct_to_base64(&key.1)
}

pub fn base64_to_key(base64: &str) -> (BigUint, BigUint) {
    let parts: Vec<&str> = base64.split('-').collect();
    (base64_to_oct(parts[0]), base64_to_oct(parts[1]))
}

pub fn oct_to_base64(octet: &BigUint) -> String {
    base64::encode(octet.to_bytes_be())
}

pub fn base64_to_oct(base64: &str) -> BigUint {
    BigUint::from_radix_be(&base64::decode(base64.as_bytes()).unwrap(), 256).unwrap()
}

pub fn oct_to_str(encoded: BigUint) -> String {
    unsafe { String::from_utf8_unchecked(encoded.to_bytes_be()) }
}

pub fn str_to_oct(to_encode: &str) -> BigUint {
    BigUint::from_radix_be(to_encode.as_bytes(), 256).unwrap()
}

pub fn split_len(string: &str, interval_length: usize) -> Vec<String> {
    let mut string = String::from(string);
    let mut return_vector: Vec<String> = vec![];
    while !string.is_empty() {
        return_vector.push(if string.len() >= interval_length {
            string.drain(..interval_length).collect()
        } else {
            string.drain(..).collect()
        });
    }
    return_vector
}
