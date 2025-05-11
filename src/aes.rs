use crate::math::*;
use std::{
    fmt::Debug,
    ops::{BitXor, BitXorAssign, Index, IndexMut},
};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Block {
    data: [[u8; 4]; 4],
}

impl Block {
    fn new() -> Self {
        Block { data: [[0; 4]; 4] }
    }

    fn from_hex_string(hex: &str) -> Self {
        let bytes = hex
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                let byte_str = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(byte_str, 16).unwrap()
            })
            .collect::<Vec<_>>();

        let mut data = [[0; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                data[j][i] = bytes[i * 4 + j];
            }
        }
        Block { data }
    }
}

impl Debug for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        let len = self.data.len();
        for i in 0..len {
            for j in 0..4 {
                write!(f, "{:02x} ", self.data[i][j])?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

impl Index<usize> for Block {
    type Output = [u8; 4];

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl IndexMut<usize> for Block {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index]
    }
}

impl BitXorAssign<&Key> for Block {
    fn bitxor_assign(&mut self, rhs: &Key) {
        for i in 0..4 {
            for j in 0..4 {
                self.data[i][j] ^= rhs.subkeys[i][j];
            }
        }
    }
}

type SubKey = [u8; 4];

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    subkeys: [SubKey; 4],
}

impl Key {
    fn new() -> Self {
        Key {
            subkeys: [[0; 4]; 4],
        }
    }

    fn from_subkeys(subkeys: [SubKey; 4]) -> Self {
        Key { subkeys }
    }

    fn from_hex_string(hex: &str) -> Self {
        let bytes = hex
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                let byte_str = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(byte_str, 16).unwrap()
            })
            .collect::<Vec<_>>();

        let mut subkeys = [[0; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                subkeys[j][i] = bytes[i * 4 + j];
            }
        }
        Key { subkeys }
    }

    fn subkeys(&self) -> [SubKey; 4] {
        self.subkeys
    }

    fn subkey_xor(lhs: SubKey, rhs: SubKey) -> SubKey {
        lhs.iter()
            .zip(rhs.iter())
            .map(|(l, r)| l ^ r)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap_or_else(|_| {
                panic!(
                    "Invalid length for Key: expected 4 bytes, got {}",
                    lhs.len()
                )
            })
    }

    fn flip(&mut self) {
        let copy = self.subkeys;
        for (i, row) in copy.iter().enumerate() {
            for (j, v) in row.iter().enumerate() {
                self.subkeys[j][i] = *v;
            }
        }
    }

    fn fliped(&self) -> Self {
        let mut key = *self;
        key.flip();
        key
    }

    fn rounds_keys(&self, sbox: &[[u8; 16]; 16]) -> Vec<Key> {
        let key = self.fliped();
        let mut keys = vec![key];
        for round in 1..=(AES_ROUNDS as u8) {
            let sub_keys = keys.last().unwrap().subkeys();

            let mut next_sub_keys = [[0u8; 4]; 4];

            next_sub_keys[0] = Key::subkey_xor(sub_keys[0], Key::g(&sub_keys[3], round, sbox));
            next_sub_keys[1] = Key::subkey_xor(sub_keys[1], next_sub_keys[0]);
            next_sub_keys[2] = Key::subkey_xor(sub_keys[2], next_sub_keys[1]);
            next_sub_keys[3] = Key::subkey_xor(sub_keys[3], next_sub_keys[2]);
            let next_key = Key::from_subkeys(next_sub_keys);
            keys.push(next_key);
        }
        keys = keys.iter().map(|key| key.fliped()).collect::<Vec<_>>();
        keys
    }

    fn r(round: u8) -> u8 {
        gf_power(0x02, round - 1)
    }

    fn g(key: &SubKey, round: u8, sbox: &[[u8; 16]; 16]) -> SubKey {
        let mut new_key = [0; 4];
        new_key[0] = gf_add(AES128::substitute(key[1], sbox), Key::r(round));
        new_key[1] = AES128::substitute(key[2], sbox);
        new_key[2] = AES128::substitute(key[3], sbox);
        new_key[3] = AES128::substitute(key[0], sbox);
        new_key
    }
}

impl Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        let len = self.subkeys.len();
        for i in 0..len {
            for j in 0..4 {
                write!(f, "{:02x} ", self.subkeys[i][j])?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

impl From<&str> for Key {
    fn from(key: &str) -> Self {
        let bytes = key.as_bytes();
        let mut subkeys = [[0; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                if i * 4 + j < bytes.len() {
                    subkeys[i][j] = bytes[i * 4 + j];
                } else {
                    subkeys[i][j] = 0;
                }
            }
        }
        Key { subkeys }
    }
}

impl<T> From<&[T; 16]> for Key
where
    T: Copy + Into<u8>,
{
    fn from(key: &[T; 16]) -> Self {
        let mut subkeys = [[0; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                subkeys[i][j] = key[i * 4 + j].into();
            }
        }
        Key { subkeys }
    }
}

impl From<Key> for [u8; 16] {
    fn from(key: Key) -> Self {
        let mut bytes = [0; 16];
        for i in 0..4 {
            for j in 0..4 {
                bytes[i * 4 + j] = key.subkeys[i][j];
            }
        }
        bytes
    }
}

impl Index<usize> for Key {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.subkeys[index / 4][index % 4]
    }
}

impl IndexMut<usize> for Key {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.subkeys[index / 4][index % 4]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AES128;

impl AES128 {
    pub fn new() -> Self {
        AES128 {}
    }

    pub fn encrypt(&self, data: &[u8], key: &Key) -> Vec<u8> {
        let blocks = self.blocks(data);

        let empcripted_blocks = blocks
            .into_iter()
            .map(|block| self.encrypt_block(block, key))
            .collect::<Vec<_>>();

        self.blocks_to_bytes(empcripted_blocks)
    }

    fn encrypt_block(&self, block: Block, key: &Key) -> Block {
        let mut block = block;
        let round_keys = key.rounds_keys(&AES_SBOX);
        // 1st round
        self.add_round_key(&mut block, key);
        // 2nd to n-1th rounds
        for round_key in round_keys.iter().take(AES_ROUNDS).skip(1) {
            self.sub_bytes(&mut block, &AES_SBOX);
            AES128::shift_rows(&mut block);
            AES128::mix_columns(&mut block, &AES_MIX_COLUMNS_MATRIX);
            self.add_round_key(&mut block, round_key);
        }
        // Last round
        self.sub_bytes(&mut block, &AES_SBOX);
        AES128::shift_rows(&mut block);
        self.add_round_key(&mut block, &round_keys[AES_ROUNDS]);
        block
    }

    pub fn decrypt(&self, data: &[u8], key: &Key) -> Vec<u8> {
        let blocks = self.blocks(data);

        let empcripted_blocks = blocks
            .into_iter()
            .map(|block| self.decrypt_block(block, key))
            .collect::<Vec<_>>();

        self.blocks_to_bytes(empcripted_blocks)
    }

    fn decrypt_block(&self, block: Block, key: &Key) -> Block {
        let mut block = block;
        let round_keys = key.rounds_keys(&AES_SBOX);
        // 1st round
        self.add_round_key(&mut block, round_keys.last().unwrap());
        AES128::inv_shift_rows(&mut block);
        self.sub_bytes(&mut block, &AES_INV_SBOX);
        // 2nd to n-1th rounds
        for round_key in round_keys.iter().skip(1).rev().skip(1) {
            self.add_round_key(&mut block, round_key);
            AES128::mix_columns(&mut block, &AES_INV_MIX_COLUMNS_MATRIX);
            AES128::inv_shift_rows(&mut block);
            self.sub_bytes(&mut block, &AES_INV_SBOX);
        }
        // Last round
        self.add_round_key(&mut block, round_keys.first().unwrap());
        block
    }

    fn blocks(&self, data: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        for chunk in data.chunks(16) {
            let mut block = Block::new();
            for (i, byte) in chunk.iter().enumerate() {
                block.data[i / 4][i % 4] = *byte;
            }
            blocks.push(block);
        }
        blocks
    }

    fn blocks_to_bytes(&self, blocks: Vec<Block>) -> Vec<u8> {
        blocks
            .into_iter()
            .flat_map(|block| block.data.into_iter().flat_map(|row| row.into_iter()))
            .collect()
    }

    fn sub_bytes(&self, state: &mut Block, sbox: &[[u8; 16]; 16]) {
        for i in 0..4 {
            for j in 0..4 {
                state[i][j] = AES128::substitute(state[i][j], sbox);
            }
        }
    }

    fn add_round_key(&self, state: &mut Block, round_key: &Key) {
        *state ^= round_key;
    }

    fn shift_rows(state: &mut Block) {
        for i in 1..4 {
            let temp = state[i];
            for j in 0..4 {
                state[i][j] = temp[(j + i) % 4];
            }
        }
    }

    fn inv_shift_rows(state: &mut Block) {
        for i in 1..4 {
            let temp = state[i];
            for j in 0..4 {
                state[i][j] = temp[(j + 4 - i) % 4];
            }
        }
    }

    fn mix_columns(block: &mut Block, mix_columns: &[[u8; 4]; 4]) {
        let temp = matrix_multiply(mix_columns, &block.data);
        *block = Block { data: temp };
    }

    fn substitute(byte: u8, sbox: &[[u8; 16]; 16]) -> u8 {
        sbox[(byte >> 4) as usize][(byte & 0x0F) as usize]
    }
}

const AES_ROUNDS: usize = 10;

#[rustfmt::skip]
const AES_SBOX: [[u8; 16]; 16] = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16],
];

#[rustfmt::skip]
const AES_INV_SBOX: [[u8; 16]; 16] = [
    [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
    [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
    [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
    [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
    [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
    [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
    [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
    [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
    [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
    [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
    [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
    [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
    [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
    [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
    [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d],
];

#[rustfmt::skip]
const AES_MIX_COLUMNS_MATRIX: [[u8; 4]; 4] = [
    [0x2, 0x3, 0x1, 0x1],
    [0x1, 0x2, 0x3, 0x1],
    [0x1, 0x1, 0x2, 0x3],
    [0x3, 0x1, 0x1, 0x2],
];

#[rustfmt::skip]
const AES_INV_MIX_COLUMNS_MATRIX: [[u8; 4]; 4] = [
    [0xe, 0xb, 0xd, 0x9],
    [0x9, 0xe, 0xb, 0xd],
    [0xd, 0x9, 0xe, 0xb],
    [0xb, 0xd, 0x9, 0xe],
];

#[rustfmt::skip]
const AES_ADD_ROUND_KEY: [[u8; 4]; 4] = [
    [0x01, 0x00, 0x00, 0x00],
    [0x00, 0x01, 0x00, 0x00],
    [0x00, 0x00, 0x01, 0x00],
    [0x00, 0x00, 0x00, 0x01],
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes() {
        let block = Block::from_hex_string("3243f6a8885a308d313198a2e0370734");
        let key = Key::from_hex_string("2b7e151628aed2a6abf7158809cf4f3c");

        let expected_encrypted = Block::from_hex_string("3925841d02dc09fbdc118597196a0b32");

        let mut aes = AES128::new();
        let encrypted = aes.encrypt_block(block.clone(), &key);
        assert_ne!(block, encrypted);
        assert_eq!(expected_encrypted, encrypted);

        let decrypted = aes.decrypt_block(encrypted, &key);

        assert_eq!(block, decrypted);
    }

    #[test]
    fn r() {
        assert_eq!(Key::r(1), 0x01);
        assert_eq!(Key::r(2), 0x02);
        assert_eq!(Key::r(3), 0x04);
        assert_eq!(Key::r(4), 0x08);
        assert_eq!(Key::r(5), 0x10);
        assert_eq!(Key::r(6), 0x20);
        assert_eq!(Key::r(7), 0x40);
        assert_eq!(Key::r(8), 0x80);
        assert_eq!(Key::r(9), 0x1b);
        assert_eq!(Key::r(10), 0x36);
    }

    #[test]
    fn round_key() {
        let key0 = Key::from_hex_string("2b7e151628aed2a6abf7158809cf4f3c");
        let key1 = Key::from_hex_string("a0fafe1788542cb123a339392a6c7605");
        let key11 = Key::from_hex_string("d014f9a8c9ee2589e13f0cc8b6630ca6");

        let rounds_keys = key0.rounds_keys(&AES_SBOX);

        assert_eq!(rounds_keys.len(), 11);

        assert_eq!(rounds_keys[0], key0);
        assert_eq!(rounds_keys[1], key1);
        assert_eq!(rounds_keys[10], key11);
    }

    #[test]
    fn substitute() {
        let byte = 0x9b;
        let substituted = AES128::substitute(byte, &AES_SBOX);
        assert_eq!(substituted, 0x14);
    }

    #[test]
    fn shift_rows() {
        let mut block = Block::new();
        block[0] = [0x01, 0x02, 0x03, 0x04];
        block[1] = [0x05, 0x06, 0x07, 0x08];
        block[2] = [0x09, 0x0a, 0x0b, 0x0c];
        block[3] = [0x0d, 0x0e, 0x0f, 0x10];

        let expected = Block {
            data: [
                [0x01, 0x02, 0x03, 0x04],
                [0x06, 0x07, 0x08, 0x05],
                [0x0b, 0x0c, 0x09, 0x0a],
                [0x10, 0x0d, 0x0e, 0x0f],
            ],
        };

        AES128::shift_rows(&mut block);
        assert_eq!(block.data, expected.data);
    }

    #[test]
    fn mix_columns() {
        let mut block = Block {
            data: [
                [0x01, 0x02, 0x03, 0x04],
                [0x05, 0x06, 0x07, 0x08],
                [0x09, 0x0a, 0x0b, 0x0c],
                [0x0d, 0x0e, 0x0f, 0x10],
            ],
        };

        let expected = Block {
            data: [
                [0x09, 0x0a, 0x0b, 0x0c],
                [0x1d, 0x1e, 0x1f, 0x10],
                [0x01, 0x02, 0x03, 0x24],
                [0x15, 0x16, 0x17, 0x28],
            ],
        };

        AES128::mix_columns(&mut block, &AES_MIX_COLUMNS_MATRIX);
        assert_eq!(block.data, expected.data);
    }

    #[test]
    fn mix_columns2() {
        let mut block = Block {
            data: [
                [0x87, 0xf2, 0x4d, 0x97],
                [0x6e, 0x4c, 0x90, 0xec],
                [0x46, 0xe7, 0x4a, 0xc3],
                [0xa6, 0x8c, 0xd8, 0x95],
            ],
        };

        let expected = Block {
            data: [
                [0x47, 0x40, 0xa3, 0x4c],
                [0x37, 0xd4, 0x70, 0x9f],
                [0x94, 0xe4, 0x3a, 0x42],
                [0xed, 0xa5, 0xa6, 0xbc],
            ],
        };

        AES128::mix_columns(&mut block, &AES_MIX_COLUMNS_MATRIX);
        assert_eq!(block.data, expected.data);
    }

    #[test]
    fn test_u8() {
        let a: u8 = 0x12;
        let b: u8 = 18;
        assert_eq!(a, b);
    }
}

pub fn main() {}
