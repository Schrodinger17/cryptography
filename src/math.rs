pub fn matrix_multiply(a: &[[u8; 4]; 4], b: &[[u8; 4]; 4]) -> [[u8; 4]; 4] {
    let mut result = [[0; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            result[i][j] = gf_multiply(a[i][0], b[0][j])
                ^ gf_multiply(a[i][1], b[1][j])
                ^ gf_multiply(a[i][2], b[2][j])
                ^ gf_multiply(a[i][3], b[3][j]);
        }
    }
    result
}

pub fn gf_multiply(a: u8, b: u8) -> u8 {
    let mut result = 0;
    let mut temp_a = a;
    let mut temp_b = b;

    while temp_b > 0 {
        if temp_b & 1 != 0 {
            result ^= temp_a; // Add (XOR) if the lowest bit of b is set
        }
        temp_a = (temp_a << 1) ^ if temp_a & 0x80 != 0 { 0x1b } else { 0 }; // Modulo x^8 + x^4 + x^3 + x + 1
        temp_b >>= 1; // Shift b to the right
    }

    result
}

pub fn gf_power(base: u8, exp: u8) -> u8 {
    let mut result = 1;
    let mut base = base;
    let mut exp = exp;

    while exp > 0 {
        if exp & 1 != 0 {
            result = gf_multiply(result, base);
        }
        base = gf_multiply(base, base);
        exp >>= 1;
    }

    result
}

pub fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_power_test() {
        assert_eq!(gf_power(0x02, 0), 0x01);
        assert_eq!(gf_power(0x02, 1), 0x02);
        assert_eq!(gf_power(0x02, 2), 0x04);
        assert_eq!(gf_power(0x02, 3), 0x08);
        assert_eq!(gf_power(0x02, 9), 0x36);
    }

    #[test]
    fn gf_add_test() {
        assert_eq!(gf_add(0x01, 0x01), 0x00);
        assert_eq!(gf_add(0x01, 0x02), 0x03);
        assert_eq!(gf_add(0x02, 0x03), 0x01);
        assert_eq!(gf_add(0x04, 0x05), 0x01);
    }

    #[test]
    fn gf_multiply_test() {
        assert_eq!(gf_multiply(0x57, 0x83), 0xc1);
        assert_eq!(gf_multiply(0x01, 0x01), 0x01);
        assert_eq!(gf_multiply(0x01, 0x00), 0x00);
        assert_eq!(gf_multiply(0x00, 0x01), 0x00);
        assert_eq!(gf_multiply(0x00, 0x00), 0x00);
    }
}
