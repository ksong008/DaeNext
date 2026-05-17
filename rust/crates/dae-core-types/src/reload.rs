pub const RELOAD_SEND: u8 = b'0';
pub const RELOAD_PROCESSING: u8 = b'1';
pub const RELOAD_DONE: u8 = b'2';
pub const RELOAD_ERROR: u8 = b'3';

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reload_bytes_match_golden_fixture() {
        let fixture = dae_golden::load_json("abi/consts/reserved_indices.json").unwrap();
        let reload = &fixture["reload"];

        assert_eq!(RELOAD_SEND, reload["send"]["byte"].as_u64().unwrap() as u8);
        assert_eq!(
            RELOAD_PROCESSING,
            reload["processing"]["byte"].as_u64().unwrap() as u8
        );
        assert_eq!(RELOAD_DONE, reload["done"]["byte"].as_u64().unwrap() as u8);
        assert_eq!(
            RELOAD_ERROR,
            reload["error"]["byte"].as_u64().unwrap() as u8
        );
        assert_eq!((RELOAD_SEND as char).to_string(), reload["send"]["char"]);
        assert_eq!(
            (RELOAD_PROCESSING as char).to_string(),
            reload["processing"]["char"]
        );
        assert_eq!((RELOAD_DONE as char).to_string(), reload["done"]["char"]);
        assert_eq!((RELOAD_ERROR as char).to_string(), reload["error"]["char"]);
    }
}
