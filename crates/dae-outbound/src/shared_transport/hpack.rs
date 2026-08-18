//! 共享 HPACK wire 编码原语（F-10）。
//!
//! xHTTP 与 gRPC 两处 header 构造各自实现过简化 encoder（xHTTP 曾以
//! `assert!(len < 128)` 拒绝长 literal，可被合法长配置触发 panic）。
//! 本模块提供唯一的 integer/string 编码实现，两处共用，移除 assert
//! 与重复实现漂移。

/// 按 HPACK/RFC 7541 编码一个带前缀的 integer（无失败路径）。
pub(crate) fn push_hpack_integer(
    out: &mut Vec<u8>,
    mut value: usize,
    prefix_bits: u8,
    first_mask: u8,
) {
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

/// 编码一个 string literal（7-bit 前缀 + 原始字节；本工程不启用 Huffman）。
pub(crate) fn push_hpack_string(out: &mut Vec<u8>, value: &[u8]) {
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
        // 127 是 7-bit 前缀上限：value == prefix_max 也走扩展路径，
        // 编码为 [127, 0]（前缀满 + remainder 0）；[127] 单独是不完整编码。
        let mut out = Vec::new();
        push_hpack_integer(&mut out, 127, 7, 0);
        assert_eq!(out, vec![127, 0]);
        let mut out = Vec::new();
        push_hpack_integer(&mut out, 128, 7, 0);
        assert_eq!(out, vec![127, 1]);
    }

    #[test]
    fn string_longer_than_127_bytes_encodes_without_assert() {
        // F-10 回归：此前 xHTTP 版本 assert!(len < 128) 会 panic。
        let value = vec![b'x'; 512];
        let mut out = Vec::new();
        push_hpack_string(&mut out, &value);
        assert_eq!(out[0], 127);
        // 512 = 127 + 385; 385 编码为 0x03 0x03（385 = 0b11_0000001）
        // 512 - 127 = 385 -> 385 >= 128 -> 0x01|0x80 = 0x81, 385>>7 = 3 -> 0x03
        assert_eq!(out[1], 0x81);
        assert_eq!(out[2], 0x03);
        assert_eq!(&out[3..], value.as_slice());
    }

    #[test]
    fn matches_grpc_legacy_encoder() {
        // 与 grpc_http2 旧实现输出一致（回归保护）。
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
