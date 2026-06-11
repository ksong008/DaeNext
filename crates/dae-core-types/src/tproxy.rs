pub const TPROXY_MARK: u32 = 0x08000000;
pub const TPROXY_MARK_STRING: &str = "0x08000000";
pub const RECOGNIZE: u16 = 0x2017;
pub const LOOPBACK_IFINDEX: u32 = 1;
pub const TASK_COMM_LEN: usize = 16;
pub const BPF_PIN_ROOT: &str = "/sys/fs/bpf";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tproxy_constants_match_golden_fixture() {
        let fixture = dae_golden::load_json("abi/consts/reserved_indices.json").unwrap();
        let tproxy = &fixture["tproxy"];

        assert_eq!(TPROXY_MARK, tproxy["mark"].as_u64().unwrap() as u32);
        assert_eq!(TPROXY_MARK_STRING, tproxy["mark_hex"].as_str().unwrap());
        assert_eq!(RECOGNIZE, tproxy["recognize"].as_u64().unwrap() as u16);
        assert_eq!(
            LOOPBACK_IFINDEX,
            tproxy["loopback_ifindex"].as_u64().unwrap() as u32
        );
        assert_eq!(
            TASK_COMM_LEN,
            tproxy["task_comm_len"].as_u64().unwrap() as usize
        );
        assert_eq!(BPF_PIN_ROOT, tproxy["bpf_pin_root"].as_str().unwrap());
    }
}
