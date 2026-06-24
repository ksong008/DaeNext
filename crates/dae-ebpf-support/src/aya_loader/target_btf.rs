use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AyaTargetBtfSource {
    Sysfs,
    OpenwrtDebugBootVersioned,
    OpenwrtDebugBoot,
    None,
}

impl AyaTargetBtfSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sysfs => "sysfs",
            Self::OpenwrtDebugBootVersioned => "openwrt-debug-boot-versioned",
            Self::OpenwrtDebugBoot => "openwrt-debug-boot",
            Self::None => "none",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaTargetBtfReport {
    pub required: bool,
    pub source: AyaTargetBtfSource,
    pub path: Option<PathBuf>,
    pub canonical_path: Option<PathBuf>,
    pub parse_ok: bool,
    pub parse_error: Option<String>,
    pub candidate_paths: Vec<PathBuf>,
}

impl AyaTargetBtfReport {
    fn none(required: bool, candidate_paths: Vec<PathBuf>) -> Self {
        Self {
            required,
            source: AyaTargetBtfSource::None,
            path: None,
            canonical_path: None,
            parse_ok: false,
            parse_error: None,
            candidate_paths,
        }
    }
}

pub struct AyaTargetBtfSelection {
    pub btf: Option<aya::Btf>,
    pub report: AyaTargetBtfReport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AyaPnameBtfOffsets {
    pub task_struct_mm_offset: u32,
    pub mm_struct_arg_start_offset: u32,
}

pub fn discover_aya_target_btf(required: bool) -> AyaTargetBtfSelection {
    let candidates = target_btf_candidates();
    let candidate_paths = candidates
        .iter()
        .map(|(_, path)| path.clone())
        .collect::<Vec<_>>();
    let Some((source, path)) = candidates.into_iter().find(|(_, path)| path.is_file()) else {
        return AyaTargetBtfSelection {
            btf: None,
            report: AyaTargetBtfReport::none(required, candidate_paths),
        };
    };

    let canonical_path = fs::canonicalize(&path).ok();
    match aya::Btf::parse_file(&path, aya::Endianness::default()) {
        Ok(btf) => AyaTargetBtfSelection {
            btf: Some(btf),
            report: AyaTargetBtfReport {
                required,
                source,
                path: Some(path),
                canonical_path,
                parse_ok: true,
                parse_error: None,
                candidate_paths,
            },
        },
        Err(err) => AyaTargetBtfSelection {
            btf: None,
            report: AyaTargetBtfReport {
                required,
                source,
                path: Some(path),
                canonical_path,
                parse_ok: false,
                parse_error: Some(format!("{err:?}")),
                candidate_paths,
            },
        },
    }
}

pub fn resolve_pname_btf_offsets(
    report: &AyaTargetBtfReport,
) -> Result<AyaPnameBtfOffsets, String> {
    let path = report
        .path
        .as_deref()
        .ok_or_else(|| "target BTF path is not selected".to_owned())?;
    resolve_pname_btf_offsets_from_path(path)
}

pub fn resolve_pname_btf_offsets_from_path(path: &Path) -> Result<AyaPnameBtfOffsets, String> {
    let data =
        fs::read(path).map_err(|err| format!("read target BTF {}: {err}", path.display()))?;
    let view = RawBtfView::parse(&data)?;
    let task_struct_mm_offset = view
        .struct_member_byte_offset("task_struct", "mm")?
        .ok_or_else(|| "target BTF missing task_struct.mm".to_owned())?;
    let mm_struct_arg_start_offset = view
        .struct_member_byte_offset("mm_struct", "arg_start")?
        .ok_or_else(|| "target BTF missing mm_struct.arg_start".to_owned())?;
    Ok(AyaPnameBtfOffsets {
        task_struct_mm_offset,
        mm_struct_arg_start_offset,
    })
}

fn target_btf_candidates() -> Vec<(AyaTargetBtfSource, PathBuf)> {
    let mut candidates = vec![(
        AyaTargetBtfSource::Sysfs,
        PathBuf::from("/sys/kernel/btf/vmlinux"),
    )];
    if let Some(release) = kernel_release() {
        candidates.push((
            AyaTargetBtfSource::OpenwrtDebugBootVersioned,
            PathBuf::from(format!("/usr/lib/debug/boot/vmlinux-{release}")),
        ));
    }
    candidates.push((
        AyaTargetBtfSource::OpenwrtDebugBoot,
        PathBuf::from("/usr/lib/debug/boot/vmlinux"),
    ));
    candidates
}

fn kernel_release() -> Option<String> {
    let mut uts = std::mem::MaybeUninit::<libc::utsname>::zeroed();
    if unsafe { libc::uname(uts.as_mut_ptr()) } != 0 {
        return None;
    }
    let uts = unsafe { uts.assume_init() };
    let bytes = uts
        .release
        .iter()
        .map(|byte| *byte as u8)
        .take_while(|byte| *byte != 0)
        .collect::<Vec<_>>();
    String::from_utf8(bytes)
        .ok()
        .filter(|value| !value.is_empty())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RawBtfEndian {
    Little,
    Big,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawBtfTypeHeader {
    name_off: u32,
    info: u32,
    size_or_type: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawBtfMember {
    name_off: u32,
    type_id: u32,
    offset: u32,
}

struct RawBtfComposite<'a> {
    type_id: u32,
    kind: u32,
    name: &'a str,
    members: Vec<RawBtfMember>,
}

struct RawBtfView<'a> {
    strings: &'a [u8],
    composites: Vec<RawBtfComposite<'a>>,
}

impl<'a> RawBtfView<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < 24 {
            return Err("target BTF header is too short".to_owned());
        }
        let endian = match &data[0..2] {
            [0x9f, 0xeb] => RawBtfEndian::Little,
            [0xeb, 0x9f] => RawBtfEndian::Big,
            _ => return Err("target BTF magic is invalid".to_owned()),
        };
        let hdr_len = read_u32(data, 4, endian)? as usize;
        let type_off = read_u32(data, 8, endian)? as usize;
        let type_len = read_u32(data, 12, endian)? as usize;
        let str_off = read_u32(data, 16, endian)? as usize;
        let str_len = read_u32(data, 20, endian)? as usize;
        let type_start = hdr_len
            .checked_add(type_off)
            .ok_or_else(|| "target BTF type offset overflow".to_owned())?;
        let type_end = type_start
            .checked_add(type_len)
            .ok_or_else(|| "target BTF type length overflow".to_owned())?;
        let str_start = hdr_len
            .checked_add(str_off)
            .ok_or_else(|| "target BTF string offset overflow".to_owned())?;
        let str_end = str_start
            .checked_add(str_len)
            .ok_or_else(|| "target BTF string length overflow".to_owned())?;
        if type_end > data.len() || str_end > data.len() {
            return Err("target BTF sections exceed file length".to_owned());
        }

        let strings = &data[str_start..str_end];
        let mut composites = Vec::new();
        let mut cursor = type_start;
        let mut type_id = 1u32;
        while cursor < type_end {
            let header = RawBtfTypeHeader {
                name_off: read_u32(data, cursor, endian)?,
                info: read_u32(data, cursor + 4, endian)?,
                size_or_type: read_u32(data, cursor + 8, endian)?,
            };
            cursor += 12;
            let kind = (header.info >> 24) & 0x1f;
            let kind_flag = (header.info >> 31) != 0;
            let vlen = (header.info & 0xffff) as usize;
            match kind {
                4 | 5 => {
                    let name = string_at(strings, header.name_off)?;
                    let mut members = Vec::with_capacity(vlen);
                    for _ in 0..vlen {
                        let name_off = read_u32(data, cursor, endian)?;
                        let member_type_id = read_u32(data, cursor + 4, endian)?;
                        let raw_offset = read_u32(data, cursor + 8, endian)?;
                        cursor += 12;
                        let bit_offset = if kind_flag {
                            raw_offset & 0x00ff_ffff
                        } else {
                            raw_offset
                        };
                        members.push(RawBtfMember {
                            name_off,
                            type_id: member_type_id,
                            offset: bit_offset,
                        });
                    }
                    composites.push(RawBtfComposite {
                        type_id,
                        kind,
                        name,
                        members,
                    });
                }
                _ => {
                    cursor = cursor
                        .checked_add(extra_type_info_len(kind, vlen)?)
                        .ok_or_else(|| "target BTF type cursor overflow".to_owned())?;
                }
            }
            if cursor > type_end {
                return Err("target BTF type record exceeds type section".to_owned());
            }
            type_id = type_id
                .checked_add(1)
                .ok_or_else(|| "target BTF type id overflow".to_owned())?;
        }
        Ok(Self {
            strings,
            composites,
        })
    }

    fn struct_member_byte_offset(
        &self,
        struct_name: &str,
        member_name: &str,
    ) -> Result<Option<u32>, String> {
        let Some(record) = self
            .composites
            .iter()
            .find(|record| record.kind == 4 && record.name == struct_name)
        else {
            return Ok(None);
        };
        self.member_byte_offset_in_composite(record, member_name, 0, 0)
    }

    fn member_byte_offset_in_composite(
        &self,
        record: &RawBtfComposite<'_>,
        member_name: &str,
        base_bit_offset: u32,
        depth: u8,
    ) -> Result<Option<u32>, String> {
        if depth > 8 {
            return Err(format!(
                "target BTF anonymous member nesting is too deep while resolving {}.{member_name}",
                record.name
            ));
        }
        for member in &record.members {
            let name = string_at(self.strings, member.name_off)?;
            let bit_offset = base_bit_offset
                .checked_add(member.offset)
                .ok_or_else(|| "target BTF member offset overflow".to_owned())?;
            if name == member_name {
                if bit_offset % 8 != 0 {
                    return Err(format!(
                        "target BTF member {}.{member_name} is not byte-aligned",
                        record.name
                    ));
                }
                return Ok(Some(bit_offset / 8));
            }

            if !is_anonymous_member_name(name) {
                continue;
            }
            let Some(nested) = self
                .composites
                .iter()
                .find(|nested| nested.type_id == member.type_id)
            else {
                continue;
            };
            if let Some(offset) =
                self.member_byte_offset_in_composite(nested, member_name, bit_offset, depth + 1)?
            {
                return Ok(Some(offset));
            }
        }
        Ok(None)
    }
}

fn is_anonymous_member_name(name: &str) -> bool {
    name.is_empty() || name == "(anon)"
}

fn extra_type_info_len(kind: u32, vlen: usize) -> Result<usize, String> {
    let fixed = match kind {
        1 | 14 | 17 => Some(4),
        3 => Some(12),
        2 | 7 | 8 | 9 | 10 | 11 | 12 | 16 | 18 => Some(0),
        _ => None,
    };
    if let Some(len) = fixed {
        return Ok(len);
    }
    let unit: usize = match kind {
        6 | 13 => 8,
        15 | 19 => 12,
        other => return Err(format!("unsupported target BTF kind {other}")),
    };
    unit.checked_mul(vlen)
        .ok_or_else(|| "target BTF type extra length overflow".to_owned())
}

fn read_u32(data: &[u8], offset: usize, endian: RawBtfEndian) -> Result<u32, String> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| "target BTF read exceeds file length".to_owned())?;
    let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
    Ok(match endian {
        RawBtfEndian::Little => u32::from_le_bytes(bytes),
        RawBtfEndian::Big => u32::from_be_bytes(bytes),
    })
}

fn string_at(strings: &[u8], offset: u32) -> Result<&str, String> {
    let start = offset as usize;
    if start >= strings.len() {
        return Err(format!("target BTF string offset {offset} is out of range"));
    }
    let rest = &strings[start..];
    let len = rest
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "target BTF string is not NUL terminated".to_owned())?;
    std::str::from_utf8(&rest[..len])
        .map_err(|err| format!("target BTF string is not UTF-8: {err}"))
}
