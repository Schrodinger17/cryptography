#![allow(unused)]
mod aes;
mod math;
use aes::AES128;
use aes::Key;

fn main() {
    let message = b"Hello, AES!".to_vec();

    println!("Message: {:?}", String::from_utf8_lossy(&message));

    let key = Key::from("key");
    let mut aes = AES128::new();
    let encrypted = aes.encrypt(&message, &key);
    println!("Encrypted: {:?}", encrypted);
    println!("Encrypted (hex): {:?}", String::from_utf8_lossy(&encrypted));
    let decrypted = aes.decrypt(&encrypted, &key);
    println!("Decrypted: {:?}", decrypted);
    println!(
        "Decrypted (utf8): {:?}",
        String::from_utf8_lossy(&decrypted)
    );

    //aes::main();
}
