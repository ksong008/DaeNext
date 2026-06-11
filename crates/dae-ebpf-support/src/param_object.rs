use std::fs;
use std::io;
use std::path::Path;

use crate::{BpfDaeParam, DAE_PARAM_SYMBOL, DAE_PARAM_SYMBOL_SIZE};

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LITTLE_ENDIAN: u8 = 1;
const SHT_SYMTAB: u32 = 2;
const SHN_UNDEF: u16 = 0;
const ELF64_HEADER_SIZE: usize = 64;
const ELF64_SECTION_HEADER_SIZE: usize = 64;
const ELF64_SYMBOL_SIZE: usize = 24;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParamSymbolLocation {
    pub symbol: String,
    pub section: String,
    pub section_index: u16,
    pub section_offset: u64,
    pub symbol_value: u64,
    pub symbol_size: u64,
    pub file_offset: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParamObjectRewriteReport {
    pub source_len: usize,
    pub output_len: usize,
    pub location: ParamSymbolLocation,
    pub expected_param_size: usize,
    pub previous_param_was_zero: bool,
    pub rewritten_param_matches: bool,
}

pub fn locate_param_symbol_in_object(path: impl AsRef<Path>) -> io::Result<ParamSymbolLocation> {
    let bytes = fs::read(path)?;
    locate_param_symbol(&bytes)
}

pub fn read_param_from_object(path: impl AsRef<Path>) -> io::Result<BpfDaeParam> {
    let bytes = fs::read(path)?;
    let location = locate_param_symbol(&bytes)?;
    read_param_at(&bytes, &location)
}

pub fn write_param_aware_object(
    source: impl AsRef<Path>,
    output: impl AsRef<Path>,
    param: BpfDaeParam,
) -> io::Result<ParamObjectRewriteReport> {
    let mut bytes = fs::read(source)?;
    let source_len = bytes.len();
    let location = locate_param_symbol(&bytes)?;
    let previous = read_param_at(&bytes, &location)?;
    write_param_at(&mut bytes, &location, param)?;
    if let Some(parent) = output.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, &bytes)?;
    let rewritten = read_param_from_object(output)?;
    Ok(ParamObjectRewriteReport {
        source_len,
        output_len: bytes.len(),
        location,
        expected_param_size: DAE_PARAM_SYMBOL_SIZE,
        previous_param_was_zero: previous == BpfDaeParam::default(),
        rewritten_param_matches: rewritten == param,
    })
}

pub fn param_to_object_bytes(param: BpfDaeParam) -> [u8; DAE_PARAM_SYMBOL_SIZE] {
    let mut bytes = [0_u8; DAE_PARAM_SYMBOL_SIZE];
    bytes[0..4].copy_from_slice(&param.tproxy_port.to_le_bytes());
    bytes[4..8].copy_from_slice(&param.control_plane_pid.to_le_bytes());
    bytes[8..12].copy_from_slice(&param.dae0_ifindex.to_le_bytes());
    bytes[12..16].copy_from_slice(&param.dae_netns_id.to_le_bytes());
    bytes[16..22].copy_from_slice(&param.dae0peer_mac);
    bytes[22] = param.has_bpf_get_current_task;
    bytes[23] = param.padding;
    bytes
}

pub fn param_from_object_bytes(bytes: &[u8]) -> io::Result<BpfDaeParam> {
    if bytes.len() != DAE_PARAM_SYMBOL_SIZE {
        return Err(invalid_data(format!(
            "invalid PARAM byte length: got {}, want {}",
            bytes.len(),
            DAE_PARAM_SYMBOL_SIZE
        )));
    }
    let mut mac = [0_u8; 6];
    mac.copy_from_slice(&bytes[16..22]);
    Ok(BpfDaeParam {
        tproxy_port: u32::from_le_bytes(copy4(&bytes[0..4])?),
        control_plane_pid: u32::from_le_bytes(copy4(&bytes[4..8])?),
        dae0_ifindex: u32::from_le_bytes(copy4(&bytes[8..12])?),
        dae_netns_id: u32::from_le_bytes(copy4(&bytes[12..16])?),
        dae0peer_mac: mac,
        has_bpf_get_current_task: bytes[22],
        padding: bytes[23],
    })
}

fn locate_param_symbol(bytes: &[u8]) -> io::Result<ParamSymbolLocation> {
    let header = ElfHeader::parse(bytes)?;
    let sections = parse_section_headers(bytes, &header)?;
    let section_names = parse_section_names(bytes, &header, &sections)?;
    for section in sections.iter().filter(|section| section.kind == SHT_SYMTAB) {
        let linked_strings = sections
            .get(section.link as usize)
            .ok_or_else(|| invalid_data("ELF symtab links to missing string table"))?;
        let strings = slice(bytes, linked_strings.offset, linked_strings.size)?;
        let symtab = slice(bytes, section.offset, section.size)?;
        for entry in symtab.chunks_exact(ELF64_SYMBOL_SIZE) {
            let symbol = ElfSymbol::parse(entry)?;
            if symbol.name_offset == 0 || symbol.section_index == SHN_UNDEF {
                continue;
            }
            let name = read_cstr(strings, symbol.name_offset as usize)?;
            if name != DAE_PARAM_SYMBOL {
                continue;
            }
            let target_section = sections
                .get(symbol.section_index as usize)
                .ok_or_else(|| invalid_data("PARAM symbol points to missing section"))?;
            let section_name = section_names
                .get(symbol.section_index as usize)
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_owned());
            if symbol.size != DAE_PARAM_SYMBOL_SIZE as u64 {
                return Err(invalid_data(format!(
                    "PARAM symbol size mismatch: got {}, want {}",
                    symbol.size, DAE_PARAM_SYMBOL_SIZE
                )));
            }
            let file_offset = target_section
                .offset
                .checked_add(symbol.value)
                .ok_or_else(|| invalid_data("PARAM file offset overflow"))?;
            let end = file_offset
                .checked_add(symbol.size)
                .ok_or_else(|| invalid_data("PARAM file end overflow"))?;
            if end as usize > bytes.len() {
                return Err(invalid_data("PARAM symbol extends past object length"));
            }
            return Ok(ParamSymbolLocation {
                symbol: name,
                section: section_name,
                section_index: symbol.section_index,
                section_offset: target_section.offset,
                symbol_value: symbol.value,
                symbol_size: symbol.size,
                file_offset,
            });
        }
    }
    Err(invalid_data("PARAM symbol not found in ELF symtab"))
}

fn read_param_at(bytes: &[u8], location: &ParamSymbolLocation) -> io::Result<BpfDaeParam> {
    let start = location.file_offset as usize;
    let end = start + DAE_PARAM_SYMBOL_SIZE;
    param_from_object_bytes(&bytes[start..end])
}

fn write_param_at(
    bytes: &mut [u8],
    location: &ParamSymbolLocation,
    param: BpfDaeParam,
) -> io::Result<()> {
    let start = location.file_offset as usize;
    let end = start + DAE_PARAM_SYMBOL_SIZE;
    bytes
        .get_mut(start..end)
        .ok_or_else(|| invalid_data("PARAM write range is outside object"))?
        .copy_from_slice(&param_to_object_bytes(param));
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct ElfHeader {
    section_header_offset: u64,
    section_header_entry_size: u16,
    section_header_count: u16,
    section_name_index: u16,
}

impl ElfHeader {
    fn parse(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < ELF64_HEADER_SIZE {
            return Err(invalid_data("ELF header is too short"));
        }
        if &bytes[0..4] != ELF_MAGIC {
            return Err(invalid_data("object is not an ELF file"));
        }
        if bytes[4] != ELF_CLASS_64 {
            return Err(invalid_data("object is not ELF64"));
        }
        if bytes[5] != ELF_DATA_LITTLE_ENDIAN {
            return Err(invalid_data("object is not little-endian ELF"));
        }
        let section_header_offset = u64::from_le_bytes(copy8(&bytes[40..48])?);
        let section_header_entry_size = u16::from_le_bytes(copy2(&bytes[58..60])?);
        let section_header_count = u16::from_le_bytes(copy2(&bytes[60..62])?);
        let section_name_index = u16::from_le_bytes(copy2(&bytes[62..64])?);
        if section_header_entry_size as usize != ELF64_SECTION_HEADER_SIZE {
            return Err(invalid_data(format!(
                "unexpected ELF section header size: {section_header_entry_size}"
            )));
        }
        Ok(Self {
            section_header_offset,
            section_header_entry_size,
            section_header_count,
            section_name_index,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct ElfSectionHeader {
    name_offset: u32,
    kind: u32,
    offset: u64,
    size: u64,
    link: u32,
}

#[derive(Clone, Copy, Debug)]
struct ElfSymbol {
    name_offset: u32,
    section_index: u16,
    value: u64,
    size: u64,
}

impl ElfSymbol {
    fn parse(bytes: &[u8]) -> io::Result<Self> {
        Ok(Self {
            name_offset: u32::from_le_bytes(copy4(&bytes[0..4])?),
            section_index: u16::from_le_bytes(copy2(&bytes[6..8])?),
            value: u64::from_le_bytes(copy8(&bytes[8..16])?),
            size: u64::from_le_bytes(copy8(&bytes[16..24])?),
        })
    }
}

fn parse_section_headers(bytes: &[u8], header: &ElfHeader) -> io::Result<Vec<ElfSectionHeader>> {
    let mut sections = Vec::new();
    for index in 0..header.section_header_count as usize {
        let start = header.section_header_offset as usize
            + index * header.section_header_entry_size as usize;
        let end = start + header.section_header_entry_size as usize;
        let entry = bytes
            .get(start..end)
            .ok_or_else(|| invalid_data("ELF section header extends past object length"))?;
        sections.push(ElfSectionHeader {
            name_offset: u32::from_le_bytes(copy4(&entry[0..4])?),
            kind: u32::from_le_bytes(copy4(&entry[4..8])?),
            offset: u64::from_le_bytes(copy8(&entry[24..32])?),
            size: u64::from_le_bytes(copy8(&entry[32..40])?),
            link: u32::from_le_bytes(copy4(&entry[40..44])?),
        });
    }
    Ok(sections)
}

fn parse_section_names(
    bytes: &[u8],
    header: &ElfHeader,
    sections: &[ElfSectionHeader],
) -> io::Result<Vec<String>> {
    let names_section = sections
        .get(header.section_name_index as usize)
        .ok_or_else(|| invalid_data("ELF section name table is missing"))?;
    let names = slice(bytes, names_section.offset, names_section.size)?;
    sections
        .iter()
        .map(|section| read_cstr(names, section.name_offset as usize))
        .collect()
}

fn slice(bytes: &[u8], offset: u64, size: u64) -> io::Result<&[u8]> {
    let start = offset as usize;
    let end = start
        .checked_add(size as usize)
        .ok_or_else(|| invalid_data("ELF range overflow"))?;
    bytes
        .get(start..end)
        .ok_or_else(|| invalid_data("ELF range extends past object length"))
}

fn read_cstr(bytes: &[u8], offset: usize) -> io::Result<String> {
    let tail = bytes
        .get(offset..)
        .ok_or_else(|| invalid_data("ELF string offset is outside table"))?;
    let len = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| invalid_data("ELF string is not null terminated"))?;
    Ok(String::from_utf8_lossy(&tail[..len]).into_owned())
}

fn copy2(bytes: &[u8]) -> io::Result<[u8; 2]> {
    bytes
        .try_into()
        .map_err(|_| invalid_data("expected two bytes"))
}

fn copy4(bytes: &[u8]) -> io::Result<[u8; 4]> {
    bytes
        .try_into()
        .map_err(|_| invalid_data("expected four bytes"))
}

fn copy8(bytes: &[u8]) -> io::Result<[u8; 8]> {
    bytes
        .try_into()
        .map_err(|_| invalid_data("expected eight bytes"))
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
