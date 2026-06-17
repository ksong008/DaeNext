use crate::*;
#[test]
pub(super) fn parses_mac_and_bool_values() {
    assert_eq!(
        parse_mac("aa:bb:cc:dd:ee:ff").unwrap(),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    );
    assert!(parse_bool("on").unwrap());
    assert!(!parse_bool("off").unwrap());
}
