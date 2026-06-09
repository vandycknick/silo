pub fn parse_u64(input: &[u8]) -> Option<u64> {
    if input.is_empty() {
        return None;
    }
    let mut value = 0u64;
    for &byte in input {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((byte - b'0') as u64)?;
    }
    Some(value)
}

pub fn parse_i64(input: &[u8]) -> Option<i64> {
    if input.is_empty() {
        return None;
    }
    let (negative, digits) = if input[0] == b'-' {
        (true, &input[1..])
    } else if input[0] == b'+' {
        (false, &input[1..])
    } else {
        (false, input)
    };
    let value = parse_u64(digits)?;
    if negative {
        if value == (i64::MAX as u64) + 1 {
            Some(i64::MIN)
        } else {
            Some(-(i64::try_from(value).ok()?))
        }
    } else {
        i64::try_from(value).ok()
    }
}

pub fn format_u64(mut value: u64, out: &mut [u8]) -> &[u8] {
    if out.is_empty() {
        return &[];
    }
    if value == 0 {
        out[0] = b'0';
        return &out[..1];
    }

    let mut index = out.len();
    while value > 0 && index > 0 {
        index -= 1;
        out[index] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    &out[index..]
}

pub fn format_hex(mut value: u64, out: &mut [u8]) -> &[u8] {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    if out.is_empty() {
        return &[];
    }
    if value == 0 {
        out[0] = b'0';
        return &out[..1];
    }

    let mut index = out.len();
    while value > 0 && index > 0 {
        index -= 1;
        out[index] = DIGITS[(value & 0xf) as usize];
        value >>= 4;
    }
    &out[index..]
}
