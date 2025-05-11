#![allow(unused)]
mod aes;
mod math;

use aes::Key;

fn main() {
    let message = "Hello, AES!".to_string();

    println!("Message: {:?}", &message);

    let key = Key::from("key");
    let encrypted = aes::encrypt(&message, &key);
    println!("Encrypted: {:?}", encrypted);
    println!("Encrypted (hex): {:?}", &encrypted);
    let decrypted = aes::decrypt(&encrypted, &key);
    println!("Decrypted: {:?}", decrypted);
    println!("Decrypted (utf8): {:?}", &decrypted);
}
