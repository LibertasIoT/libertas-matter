// Copyright (c) 2026 Smartonlabs Inc.
// SPDX-License-Identifier: MIT

//! Borrowed, allocation-free Matter TLV decoding.

use crate::error::Error;

use super::{Tag, ValueType};

/// One complete borrowed TLV element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Element<'a> {
    encoded: &'a [u8],
    tag: Tag,
    value_type: ValueType,
    value_offset: usize,
    value_len: usize,
}

impl<'a> Element<'a> {
    /// Parse exactly one complete TLV element.
    pub fn from_bytes(encoded: &'a [u8]) -> Result<Self, Error> {
        let (element, consumed) = Self::parse_prefix(encoded)?;
        if consumed == encoded.len() {
            Ok(element)
        } else {
            Err(Error::Malformed)
        }
    }

    pub const fn tag(self) -> Tag {
        self.tag
    }

    pub const fn value_type(self) -> ValueType {
        self.value_type
    }

    /// Complete encoding, including tag, length, nested content, and container
    /// terminator when applicable.
    pub const fn encoded(self) -> &'a [u8] {
        self.encoded
    }

    /// Raw value bytes. Container values include their final end marker.
    pub fn value_bytes(self) -> &'a [u8] {
        &self.encoded[self.value_offset..self.value_offset + self.value_len]
    }

    pub const fn is_container(self) -> bool {
        self.value_type.is_container_start()
    }

    pub const fn is_null(self) -> bool {
        matches!(self.value_type, ValueType::Null)
    }

    /// Read direct children of a structure, array, or list.
    pub fn children(self) -> Result<Reader<'a>, Error> {
        if !self.is_container() {
            return Err(Error::TypeMismatch);
        }
        let body = self.value_bytes();
        let body = body
            .get(..body.len().saturating_sub(1))
            .ok_or(Error::Malformed)?;
        Ok(Reader::new(body))
    }

    /// Find a direct child by exact tag.
    pub fn get(self, tag: Tag) -> Result<Option<Self>, Error> {
        let mut reader = self.children()?;
        while let Some(child) = reader.read_element()? {
            if child.tag == tag {
                return Ok(Some(child));
            }
        }
        Ok(None)
    }

    /// Find a required direct context-tagged child.
    pub fn context(self, tag: u8) -> Result<Self, Error> {
        self.get(Tag::Context(tag))?.ok_or(Error::MissingField(tag))
    }

    pub fn signed(self) -> Result<i64, Error> {
        let value = self.value_bytes();
        Ok(match self.value_type {
            ValueType::Signed8 => i8::from_le_bytes([value[0]]) as i64,
            ValueType::Signed16 => i16::from_le_bytes(copy_array(value)?) as i64,
            ValueType::Signed32 => i32::from_le_bytes(copy_array(value)?) as i64,
            ValueType::Signed64 => i64::from_le_bytes(copy_array(value)?),
            _ => return Err(Error::TypeMismatch),
        })
    }

    pub fn unsigned(self) -> Result<u64, Error> {
        let value = self.value_bytes();
        Ok(match self.value_type {
            ValueType::Unsigned8 => value[0] as u64,
            ValueType::Unsigned16 => u16::from_le_bytes(copy_array(value)?) as u64,
            ValueType::Unsigned32 => u32::from_le_bytes(copy_array(value)?) as u64,
            ValueType::Unsigned64 => u64::from_le_bytes(copy_array(value)?),
            _ => return Err(Error::TypeMismatch),
        })
    }

    pub fn i8(self) -> Result<i8, Error> {
        self.signed()?.try_into().map_err(|_| Error::OutOfRange)
    }

    pub fn i16(self) -> Result<i16, Error> {
        self.signed()?.try_into().map_err(|_| Error::OutOfRange)
    }

    pub fn i32(self) -> Result<i32, Error> {
        self.signed()?.try_into().map_err(|_| Error::OutOfRange)
    }

    pub fn i64(self) -> Result<i64, Error> {
        self.signed()
    }

    pub fn u8(self) -> Result<u8, Error> {
        self.unsigned()?.try_into().map_err(|_| Error::OutOfRange)
    }

    pub fn u16(self) -> Result<u16, Error> {
        self.unsigned()?.try_into().map_err(|_| Error::OutOfRange)
    }

    pub fn u32(self) -> Result<u32, Error> {
        self.unsigned()?.try_into().map_err(|_| Error::OutOfRange)
    }

    pub fn u64(self) -> Result<u64, Error> {
        self.unsigned()
    }

    pub fn bool(self) -> Result<bool, Error> {
        match self.value_type {
            ValueType::BooleanFalse => Ok(false),
            ValueType::BooleanTrue => Ok(true),
            _ => Err(Error::TypeMismatch),
        }
    }

    pub fn f32(self) -> Result<f32, Error> {
        if self.value_type != ValueType::Float32 {
            return Err(Error::TypeMismatch);
        }
        Ok(f32::from_le_bytes(copy_array(self.value_bytes())?))
    }

    pub fn f64(self) -> Result<f64, Error> {
        if self.value_type != ValueType::Float64 {
            return Err(Error::TypeMismatch);
        }
        Ok(f64::from_le_bytes(copy_array(self.value_bytes())?))
    }

    pub fn utf8(self) -> Result<&'a str, Error> {
        if !self.value_type.is_utf8() {
            return Err(Error::TypeMismatch);
        }
        Ok(core::str::from_utf8(self.value_bytes())?)
    }

    pub fn bytes(self) -> Result<&'a [u8], Error> {
        if !self.value_type.is_bytes() {
            return Err(Error::TypeMismatch);
        }
        Ok(self.value_bytes())
    }

    pub(crate) fn parse_prefix(encoded: &'a [u8]) -> Result<(Self, usize), Error> {
        let header = parse_header(encoded)?;
        let total = if header.value_type.is_container_start() {
            scan_container(encoded, header.value_offset)?
        } else {
            header
                .value_offset
                .checked_add(header.value_len)
                .ok_or(Error::Malformed)?
        };
        let complete = encoded.get(..total).ok_or(Error::Truncated)?;
        let value_len = total - header.value_offset;
        Ok((
            Self {
                encoded: complete,
                tag: header.tag,
                value_type: header.value_type,
                value_offset: header.value_offset,
                value_len,
            },
            total,
        ))
    }
}

/// Cursor for a sequence of sibling TLV elements.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    pub const fn new(encoded: &'a [u8]) -> Self {
        Self { remaining: encoded }
    }

    pub const fn remaining(self) -> &'a [u8] {
        self.remaining
    }

    /// Decode the next sibling without implementing or allocating an iterator.
    pub fn read_element(&mut self) -> Result<Option<Element<'a>>, Error> {
        if self.remaining.is_empty() {
            return Ok(None);
        }
        let (element, consumed) = Element::parse_prefix(self.remaining)?;
        if element.value_type == ValueType::EndOfContainer {
            return Err(Error::Malformed);
        }
        self.remaining = &self.remaining[consumed..];
        Ok(Some(element))
    }
}

#[derive(Clone, Copy)]
struct Header {
    tag: Tag,
    value_type: ValueType,
    value_offset: usize,
    value_len: usize,
}

fn parse_header(encoded: &[u8]) -> Result<Header, Error> {
    let control = *encoded.first().ok_or(Error::Truncated)?;
    let value_type = ValueType::try_from(control & 0x1f)?;
    let (tag, tag_len) = Tag::decode(control >> 5, encoded.get(1..).ok_or(Error::Truncated)?)?;
    let mut value_offset = 1_usize.checked_add(tag_len).ok_or(Error::Malformed)?;

    if value_type == ValueType::EndOfContainer && tag != Tag::Anonymous {
        return Err(Error::Malformed);
    }

    let value_len = if let Some(width) = value_type.fixed_width() {
        width
    } else {
        let length_width = value_type.length_width();
        let length_end = value_offset
            .checked_add(length_width)
            .ok_or(Error::Malformed)?;
        let length = read_length(
            encoded
                .get(value_offset..length_end)
                .ok_or(Error::Truncated)?,
        )?;
        value_offset = length_end;
        length
    };

    let end = value_offset
        .checked_add(value_len)
        .ok_or(Error::Malformed)?;
    if end > encoded.len() {
        return Err(Error::Truncated);
    }

    Ok(Header {
        tag,
        value_type,
        value_offset,
        value_len,
    })
}

fn scan_container(encoded: &[u8], mut cursor: usize) -> Result<usize, Error> {
    let mut depth = 1_usize;
    while depth != 0 {
        let header = parse_header(encoded.get(cursor..).ok_or(Error::Truncated)?)?;
        if header.value_type.is_container_start() {
            depth = depth.checked_add(1).ok_or(Error::Malformed)?;
            cursor = cursor
                .checked_add(header.value_offset)
                .ok_or(Error::Malformed)?;
        } else {
            let size = header
                .value_offset
                .checked_add(header.value_len)
                .ok_or(Error::Malformed)?;
            cursor = cursor.checked_add(size).ok_or(Error::Malformed)?;
            if header.value_type == ValueType::EndOfContainer {
                depth -= 1;
            }
        }
    }
    Ok(cursor)
}

fn read_length(bytes: &[u8]) -> Result<usize, Error> {
    let value = match bytes.len() {
        1 => bytes[0] as u64,
        2 => u16::from_le_bytes(copy_array(bytes)?) as u64,
        4 => u32::from_le_bytes(copy_array(bytes)?) as u64,
        8 => u64::from_le_bytes(copy_array(bytes)?),
        _ => return Err(Error::Malformed),
    };
    value.try_into().map_err(|_| Error::OutOfRange)
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Malformed)
}
