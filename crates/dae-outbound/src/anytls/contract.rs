pub const ADAPTER_MODE: &str = "rust-native";
pub const PROTOCOL_SCOPE: &[&str] = &["anytls"];
pub const DEFERRED_PROTOCOL_SCOPE: &[&str] = &["transport-combos"];
pub const LIVE_SMOKE_REQUIRED: &[&str] = &[
    "local parser smoke for AnyTLS",
    "local auth key / frame contract smoke",
    "local UDP magic domain / underlay contract smoke",
];

pub const EMPTY_SNI_SERVER_NAME: &str = "127.0.0.1";
pub const INSECURE_ONLY_WHEN: &str = "insecure=1";
pub const PEER_OVERRIDES_SNI: bool = true;

pub const UDP_MAGIC_DOMAIN: &str = "sp.v2.udp-over-tcp.arpa";
pub const HEADER_OVERHEAD_SIZE: usize = 7;
pub const CHECK_MARK: i32 = -1;
pub const PADDING_STOP: u32 = 8;
pub const DEFAULT_PADDING_RAW: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";
pub const DEFAULT_PADDING_MD5: &str = "75cff2ad89aadf5e257059ee571ebe11";

pub const CMD_WASTE: u8 = 0;
pub const CMD_SYN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_FIN: u8 = 3;
pub const CMD_SETTINGS: u8 = 4;
pub const CMD_ALERT: u8 = 5;
pub const CMD_UPDATE_PADDING: u8 = 6;
pub const CMD_SYNACK: u8 = 7;
pub const CMD_HEART_REQUEST: u8 = 8;
pub const CMD_HEART_RESPONSE: u8 = 9;
pub const CMD_SERVER_SETTINGS: u8 = 10;

pub const IDLE_SESSION_REUSE_MAP: bool = true;
pub const SESSION_COUNTER: bool = true;
pub const UNDERLAY_ALWAYS_TCP: bool = true;
pub const UNDERLAY_PRESERVES_MARK: bool = true;
pub const UNDERLAY_PRESERVES_MPTCP: bool = true;
pub const PRODUCTION_DATA_PLANE_OWNER: &str = "dae-resident-dataplane";
pub const STANDALONE_SMOKE_SURFACE: &str = "test-support-only";
