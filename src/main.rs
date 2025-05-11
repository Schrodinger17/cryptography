#![allow(unused)]
mod aes;
mod math;

use aes::Key;

fn main() {
    let message = "Hello, AES!".to_string();
    println!("Message: {:?}", &message);
    println!("Message (utf8): {:?}", &message.as_bytes());

    let key = Key::from("key");
    let encrypted = aes::encrypt(&message, &key);
    println!("Encrypted: {:?}", String::from_utf8_lossy(&encrypted));
    println!("Encrypted (utf8): {:?}", &encrypted);

    let decrypted = aes::decrypt(&encrypted, &key);
    println!("Decrypted: {:?}", decrypted);
    println!("Decrypted (utf8): {:?}", &decrypted.as_bytes());
}
