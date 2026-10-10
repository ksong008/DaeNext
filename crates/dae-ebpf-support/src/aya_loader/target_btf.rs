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
    pname_offsets: Option<Result<AyaPnameBtfOffsets, String>>,
}

impl AyaTargetBtfSelection {
    pub fn pname_offsets(&self) -> Result<AyaPnameBtfOffsets, String> {
        self.pname_offsets
            .clone()
            .unwrap_or_else(|| Err("target BTF path is not selected".to_owned()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AyaPnameBtfOffsets {
    pub task_struct_mm_offset: u32,
    pub mm_struct_arg_start_offset: u32,
}

pub fn discover_aya_target_btf(required: bool) -> AyaTargetBtfSelection {
    let candidates = if required {
        kernel_target_btf_candidates()
    } else {
        target_btf_candidates()
    };
    let candidate_paths = candidates
        .iter()
        .map(|(_, path)| path.clone())
        .collect::<Vec<_>>();
    if !required {
        return AyaTargetBtfSelection {
            btf: None,
            pname_offsets: None,
            report: AyaTargetBtfReport::none(required, candidate_paths),
        };
    }
    let Some((source, path)) = candidates.into_iter().find(|(_, path)| path.is_file()) else {
        return AyaTargetBtfSelection {
            btf: None,
            pname_offsets: None,
            report: AyaTargetBtfReport::none(required, candidate_paths),
        };
    };

    let canonical_path = fs::canonicalize(&path).ok();
    let parsed = fs::read(&path)
        .map_err(|err| format!("{err:?}"))
        .and_then(|data| {
            aya::Btf::parse(&data, aya::Endianness::default())
                .map(|btf| (btf, resolve_pname_btf_offsets_from_bytes(&data)))
                .map_err(|err| format!("{err:?}"))
        });
    match parsed {
        Ok((btf, offsets)) => AyaTargetBtfSelection {
            btf: Some(btf),
            pname_offsets: Some(offsets),
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
            pname_offsets: None,
            report: AyaTargetBtfReport {
                required,
                source,
                path: Some(path),
                canonical_path,
                parse_ok: false,
                parse_error: Some(err),
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
    resolve_pname_btf_offsets_from_bytes(&data)
}

fn resolve_pname_btf_offsets_from_bytes(data: &[u8]) -> Result<AyaPnameBtfOffsets, String> {
    let view = RawBtfView::parse(data)?;
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

fn kernel_target_btf_candidates() -> Vec<(AyaTargetBtfSource, PathBuf)> {
    vec![(
        AyaTargetBtfSource::Sysfs,
        PathBuf::from("/sys/kernel/btf/vmlinux"),
    )]
}

fn target_btf_candidates() -> Vec<(AyaTargetBtfSource, PathBuf)> {
    let mut candidates = kernel_target_btf_candidates();
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
}

struct RawBtfView<'a> {
    data: &'a [u8],
    strings: &'a [u8],
    endian: RawBtfEndian,
    offsets: Vec<usize>,
    task: Option<usize>,
    mm: Option<usize>,
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
        let mut offsets = Vec::new();
        let mut task = None;
        let mut mm = None;
        let mut cursor = type_start;
        while cursor < type_end {
            let offset = cursor;
            let header = RawBtfTypeHeader {
                name_off: read_u32(data, cursor, endian)?,
                info: read_u32(data, cursor + 4, endian)?,
            };
            offsets.push(offset);
            cursor += 12;
            let kind = (header.info >> 24) & 0x1f;
            let vlen = (header.info & 0xffff) as usize;
            if kind == 4 {
                match string_at(strings, header.name_off)? {
                    "task_struct" if task.is_none() => task = Some(offset),
                    "mm_struct" if mm.is_none() => mm = Some(offset),
                    _ => {}
                }
            }
            let extra = if matches!(kind, 4 | 5) {
                vlen * 12
            } else {
                extra_type_info_len(kind, vlen)?
            };
            cursor = cursor
                .checked_add(extra)
                .ok_or_else(|| "target BTF type cursor overflow".to_owned())?;
            if cursor > type_end {
                return Err("target BTF type record exceeds type section".to_owned());
            }
        }
        Ok(Self {
            data,
            strings,
            endian,
            offsets,
            task,
            mm,
        })
    }

    fn struct_member_byte_offset(
        &self,
        struct_name: &str,
        member_name: &str,
    ) -> Result<Option<u32>, String> {
        let offset = match struct_name {
            "task_struct" => self.task,
            "mm_struct" => self.mm,
            _ => None,
        };
        let Some(offset) = offset else {
            return Ok(None);
        };
        self.member_byte_offset(offset, member_name, 0, 0)
    }

    fn member_byte_offset(
        &self,
        offset: usize,
        member_name: &str,
        base: u32,
        depth: u8,
    ) -> Result<Option<u32>, String> {
        if depth > 8 {
            return Err("target BTF anonymous member nesting is too deep".to_owned());
        }
        let info = read_u32(self.data, offset + 4, self.endian)?;
        let kind = (info >> 24) & 0x1f;
        if !matches!(kind, 4 | 5) {
            return Ok(None);
        }
        for index in 0..(info & 0xffff) as usize {
            let cursor = offset + 12 + index * 12;
            let name = string_at(self.strings, read_u32(self.data, cursor, self.endian)?)?;
            let type_id = read_u32(self.data, cursor + 4, self.endian)?;
            let raw = read_u32(self.data, cursor + 8, self.endian)?;
            let bits = if info >> 31 != 0 {
                raw & 0x00ff_ffff
            } else {
                raw
            };
            let bits = base
                .checked_add(bits)
                .ok_or_else(|| "target BTF member offset overflow".to_owned())?;
            if name == member_name {
                if bits % 8 != 0 {
                    return Err(format!(
                        "target BTF member {member_name} is not byte-aligned"
                    ));
                }
                return Ok(Some(bits / 8));
            }
            if is_anonymous_member_name(name)
                && type_id > 0
                && let Some(&nested) = self.offsets.get(type_id as usize - 1)
                && let Some(found) =
                    self.member_byte_offset(nested, member_name, bits, depth + 1)?
            {
                return Ok(Some(found));
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
