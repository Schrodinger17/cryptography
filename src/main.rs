#![allow(unused)]
mod aes;
mod math;

use aes::{AES128, AES192, AES256, Key128, Key192, Key256};

fn main() {
    let message = "Hello, AES!".to_string();
    println!("Message: {:?}", &message);
    println!("Message (utf8): {:?}", &message.as_bytes());

    let key = Key128::from("key");
    let encrypted = AES128::encrypt(&message, &key);
    println!("Encrypted: {:?}", String::from_utf8_lossy(&encrypted));
    println!("Encrypted (utf8): {:?}", &encrypted);

    let decrypted = AES128::decrypt(&encrypted, &key);
    println!("Decrypted: {:?}", decrypted);
    println!("Decrypted (utf8): {:?}", &decrypted.as_bytes());
}
