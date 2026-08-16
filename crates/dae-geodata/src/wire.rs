use std::{io::Read, ops::Range};

use crate::GeoDataError;

const MAX_STREAMED_GEODATA_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

pub fn decode_entry_bytes(data: &[u8], code: &str) -> Result<Vec<u8>, GeoDataError> {
    decode_entry_view_bytes(data, code).map(<[u8]>::to_vec)
}

pub fn decode_entry_view_bytes<'a>(data: &'a [u8], code: &str) -> Result<&'a [u8], GeoDataError> {
    let mut input = data;
    while !input.is_empty() {
        let tag = read_varint(&mut input)?;
        if tag != 10 {
            return Err(GeoDataError::InvalidGeodataFile);
        }
        let entry = read_length_delimited(&mut input)?;
        if country_code_eq_ignore_ascii_case(entry, code)? {
            return Ok(entry);
        }
    }

    Err(GeoDataError::CodeNotFound)
}

pub fn decode_entry_range(data: &[u8], code: &str) -> Result<Range<usize>, GeoDataError> {
    let entry = decode_entry_view_bytes(data, code)?;
    let start = entry.as_ptr() as usize - data.as_ptr() as usize;
    Ok(start..start + entry.len())
}

pub fn decode_entry_reader(mut reader: impl Read, code: &str) -> Result<Vec<u8>, GeoDataError> {
    while let Some(tag) = read_varint_reader(&mut reader)? {
        if tag != 10 {
            return Err(GeoDataError::InvalidGeodataFile);
        }
        let length = read_varint_reader(&mut reader)?.ok_or(GeoDataError::FailedToReadBytes)?;
        if length > MAX_STREAMED_GEODATA_ENTRY_BYTES {
            return Err(GeoDataError::EntryTooLarge(length));
        }
        let length = usize::try_from(length).map_err(|_| GeoDataError::EntryTooLarge(length))?;
        let mut entry = vec![0; length];
        reader
            .read_exact(&mut entry)
            .map_err(|_| GeoDataError::FailedToReadExpectedLenBytes)?;
        if country_code(&entry)?.eq_ignore_ascii_case(code) {
            return Ok(entry);
        }
    }

    Err(GeoDataError::CodeNotFound)
}

pub fn entries_from_list(data: &[u8]) -> Result<Vec<Vec<u8>>, GeoDataError> {
    let mut input = data;
    let mut entries = Vec::new();
    while !input.is_empty() {
        let tag = read_varint(&mut input)?;
        let field = tag >> 3;
        let wire_type = tag & 0x07;
        if field == 1 && wire_type == 2 {
            entries.push(read_length_delimited(&mut input)?.to_vec());
        } else {
            skip_field(wire_type, &mut input)?;
        }
    }
    Ok(entries)
}

pub fn country_code(entry: &[u8]) -> Result<String, GeoDataError> {
    country_code_view(entry).map(str::to_owned)
}

pub fn country_code_view(entry: &[u8]) -> Result<&str, GeoDataError> {
    let mut input = entry;
    while !input.is_empty() {
        let tag = read_varint(&mut input)?;
        let field = tag >> 3;
        let wire_type = tag & 0x07;
        if field == 1 && wire_type == 2 {
            return string_view(read_length_delimited(&mut input));
        }
        skip_field(wire_type, &mut input)?;
    }
    Ok("")
}

pub fn country_code_eq_ignore_ascii_case(entry: &[u8], code: &str) -> Result<bool, GeoDataError> {
    Ok(country_code_view(entry)?.eq_ignore_ascii_case(code))
}

pub fn read_varint(input: &mut &[u8]) -> Result<u64, GeoDataError> {
    let mut value = 0_u64;
    for shift in (0..64).step_by(7) {
        let Some((&byte, rest)) = input.split_first() else {
            return Err(GeoDataError::FailedToReadBytes);
        };
        *input = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Ok(value);
        }
    }
    Err(GeoDataError::InvalidGeodataVarintLength)
}

pub fn read_length_delimited<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], GeoDataError> {
    let length = read_varint(input)? as usize;
    if input.len() < length {
        return Err(GeoDataError::FailedToReadExpectedLenBytes);
    }
    let (data, rest) = input.split_at(length);
    *input = rest;
    Ok(data)
}

pub fn string(data: Result<&[u8], GeoDataError>) -> Result<String, GeoDataError> {
    string_view(data).map(str::to_owned)
}

pub fn string_view(data: Result<&[u8], GeoDataError>) -> Result<&str, GeoDataError> {
    let data = data?;
    std::str::from_utf8(data).map_err(|_| GeoDataError::InvalidUtf8)
}

pub fn skip_field(wire_type: u64, input: &mut &[u8]) -> Result<(), GeoDataError> {
    match wire_type {
        0 => {
            read_varint(input)?;
            Ok(())
        }
        1 => skip_bytes(input, 8),
        2 => {
            read_length_delimited(input)?;
            Ok(())
        }
        5 => skip_bytes(input, 4),
        _ => Err(GeoDataError::UnsupportedWireType(wire_type)),
    }
}

fn skip_bytes(input: &mut &[u8], length: usize) -> Result<(), GeoDataError> {
    if input.len() < length {
        return Err(GeoDataError::FailedToReadExpectedLenBytes);
    }
    *input = &input[length..];
    Ok(())
}

fn read_varint_reader(reader: &mut impl Read) -> Result<Option<u64>, GeoDataError> {
    let mut value = 0_u64;
    let mut byte = [0_u8; 1];
    for shift in (0..64).step_by(7) {
        match reader.read_exact(&mut byte) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof && shift == 0 => {
                return Ok(None);
            }
            Err(_) => return Err(GeoDataError::FailedToReadBytes),
        }
        value |= u64::from(byte[0] & 0x7f) << shift;
        if byte[0] < 0x80 {
            return Ok(Some(value));
        }
    }
    Err(GeoDataError::InvalidGeodataVarintLength)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn streamed_entry_rejects_oversized_length_before_allocation() {
        let length = MAX_STREAMED_GEODATA_ENTRY_BYTES + 1;
        let mut encoded = vec![10];
        let mut value = length;
        while value >= 0x80 {
            encoded.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        encoded.push(value as u8);
        assert_eq!(
            decode_entry_reader(Cursor::new(encoded), "US"),
            Err(GeoDataError::EntryTooLarge(length))
        );
    }
}
