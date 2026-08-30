pub fn push_hpack_integer(out: &mut Vec<u8>, mut value: usize, prefix_bits: u8, first_mask: u8) {
    debug_assert!(prefix_bits <= 8);
    let prefix_max = (1_usize << prefix_bits) - 1;
    if value < prefix_max {
        out.push(first_mask | value as u8);
        return;
    }
    out.push(first_mask | prefix_max as u8);
    value -= prefix_max;
    while value >= 128 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

pub fn push_hpack_string(out: &mut Vec<u8>, value: &[u8]) {
    push_hpack_integer(out, value.len(), 7, 0);
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::{push_hpack_integer, push_hpack_string};

    #[test]
    fn short_integer_single_byte() {
        let mut out = Vec::new();
        push_hpack_integer(&mut out, 10, 7, 0);
        assert_eq!(out, vec![10]);
    }

    #[test]
    fn long_integer_uses_continuation() {
        let mut out = Vec::new();
        push_hpack_integer(&mut out, 127, 7, 0);
        assert_eq!(out, vec![127, 0]);
        let mut out = Vec::new();
        push_hpack_integer(&mut out, 128, 7, 0);
        assert_eq!(out, vec![127, 1]);
    }

    #[test]
    fn string_longer_than_127_bytes_encodes_without_assert() {
        let value = vec![b'x'; 512];
        let mut out = Vec::new();
        push_hpack_string(&mut out, &value);
        assert_eq!(out[0], 127);
        assert_eq!(out[1], 0x81);
        assert_eq!(out[2], 0x03);
        assert_eq!(&out[3..], value.as_slice());
    }

    #[test]
    fn matches_grpc_legacy_encoder() {
        for value in [0usize, 1, 10, 126, 127, 128, 255, 256, 16383, 16384, 65535] {
            let mut legacy = Vec::new();
            let mut shared = Vec::new();
            let mut v = value;
            let prefix_max = (1usize << 7) - 1;
            if v < prefix_max {
                legacy.push(v as u8);
            } else {
                legacy.push(prefix_max as u8);
                v -= prefix_max;
                while v >= 128 {
                    legacy.push((v as u8 & 0x7f) | 0x80);
                    v >>= 7;
                }
                legacy.push(v as u8);
            }
            push_hpack_integer(&mut shared, value, 7, 0);
            assert_eq!(shared, legacy, "value {value}");
        }
    }
}
