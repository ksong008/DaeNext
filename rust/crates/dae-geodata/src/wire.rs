use std::io::Read;

use crate::GeoDataError;

pub fn decode_entry_bytes(data: &[u8], code: &str) -> Result<Vec<u8>, GeoDataError> {
    let mut input = data;
    while !input.is_empty() {
        let tag = read_varint(&mut input)?;
        if tag != 10 {
            return Err(GeoDataError::InvalidGeodataFile);
        }
        let entry = read_length_delimited(&mut input)?;
        if country_code(entry)?.eq_ignore_ascii_case(code) {
            return Ok(entry.to_vec());
        }
    }

    Err(GeoDataError::CodeNotFound)
}

pub fn decode_entry_reader(mut reader: impl Read, code: &str) -> Result<Vec<u8>, GeoDataError> {
    while let Some(tag) = read_varint_reader(&mut reader)? {
        if tag != 10 {
            return Err(GeoDataError::InvalidGeodataFile);
        }
        let length =
            read_varint_reader(&mut reader)?.ok_or(GeoDataError::FailedToReadBytes)? as usize;
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
    let mut input = entry;
    while !input.is_empty() {
        let tag = read_varint(&mut input)?;
        let field = tag >> 3;
        let wire_type = tag & 0x07;
        if field == 1 && wire_type == 2 {
            return string(read_length_delimited(&mut input));
        }
        skip_field(wire_type, &mut input)?;
    }
    Ok(String::new())
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
    let data = data?;
    std::str::from_utf8(data)
        .map(str::to_owned)
        .map_err(|_| GeoDataError::InvalidUtf8)
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
