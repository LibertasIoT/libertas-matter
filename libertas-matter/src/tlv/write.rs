// Copyright (c) 2026 Smartonlabs Inc.
// SPDX-License-Identifier: MIT

//! Transactional Matter TLV writers.

use crate::{InlineByteBuffer, error::Error};

use super::{Tag, ValueType};

/// Append-only TLV storage with a rollback position.
///
/// Every public encoding operation is transactional: if an append fails, the
/// writer is restored to the position it had before that operation.
pub trait TLVWrite {
    /// Current initialized byte length.
    fn position(&self) -> usize;

    /// Remove bytes after `position`.
    ///
    /// Implementations may assume that `position <= self.position()`.
    fn truncate(&mut self, position: usize);

    /// Append raw bytes or return [`Error::NoSpace`] without changing earlier
    /// bytes.
    fn write_raw(&mut self, bytes: &[u8]) -> Result<(), Error>;

    /// Write a signed integer using its shortest valid Matter representation.
    fn signed(&mut self, tag: Tag, value: i64) -> Result<(), Error> {
        if i8::try_from(value).is_ok() {
            self.raw_element(ValueType::Signed8, tag, &[value as i8 as u8])
        } else if i16::try_from(value).is_ok() {
            self.raw_element(ValueType::Signed16, tag, &(value as i16).to_le_bytes())
        } else if i32::try_from(value).is_ok() {
            self.raw_element(ValueType::Signed32, tag, &(value as i32).to_le_bytes())
        } else {
            self.raw_element(ValueType::Signed64, tag, &value.to_le_bytes())
        }
    }

    /// Write an unsigned integer using its shortest valid Matter representation.
    fn unsigned(&mut self, tag: Tag, value: u64) -> Result<(), Error> {
        if u8::try_from(value).is_ok() {
            self.raw_element(ValueType::Unsigned8, tag, &[value as u8])
        } else if u16::try_from(value).is_ok() {
            self.raw_element(ValueType::Unsigned16, tag, &(value as u16).to_le_bytes())
        } else if u32::try_from(value).is_ok() {
            self.raw_element(ValueType::Unsigned32, tag, &(value as u32).to_le_bytes())
        } else {
            self.raw_element(ValueType::Unsigned64, tag, &value.to_le_bytes())
        }
    }

    fn i8(&mut self, tag: Tag, value: i8) -> Result<(), Error> {
        self.signed(tag, value.into())
    }

    fn i16(&mut self, tag: Tag, value: i16) -> Result<(), Error> {
        self.signed(tag, value.into())
    }

    fn i32(&mut self, tag: Tag, value: i32) -> Result<(), Error> {
        self.signed(tag, value.into())
    }

    fn i64(&mut self, tag: Tag, value: i64) -> Result<(), Error> {
        self.signed(tag, value)
    }

    fn u8(&mut self, tag: Tag, value: u8) -> Result<(), Error> {
        self.unsigned(tag, value.into())
    }

    fn u16(&mut self, tag: Tag, value: u16) -> Result<(), Error> {
        self.unsigned(tag, value.into())
    }

    fn u32(&mut self, tag: Tag, value: u32) -> Result<(), Error> {
        self.unsigned(tag, value.into())
    }

    fn u64(&mut self, tag: Tag, value: u64) -> Result<(), Error> {
        self.unsigned(tag, value)
    }

    fn bool(&mut self, tag: Tag, value: bool) -> Result<(), Error> {
        self.raw_element(
            if value {
                ValueType::BooleanTrue
            } else {
                ValueType::BooleanFalse
            },
            tag,
            &[],
        )
    }

    fn f32(&mut self, tag: Tag, value: f32) -> Result<(), Error> {
        self.raw_element(ValueType::Float32, tag, &value.to_le_bytes())
    }

    fn f64(&mut self, tag: Tag, value: f64) -> Result<(), Error> {
        self.raw_element(ValueType::Float64, tag, &value.to_le_bytes())
    }

    fn utf8(&mut self, tag: Tag, value: &str) -> Result<(), Error> {
        self.string_element(true, tag, value.as_bytes())
    }

    fn bytes(&mut self, tag: Tag, value: &[u8]) -> Result<(), Error> {
        self.string_element(false, tag, value)
    }

    fn null(&mut self, tag: Tag) -> Result<(), Error> {
        self.raw_element(ValueType::Null, tag, &[])
    }

    fn start_struct(&mut self, tag: Tag) -> Result<(), Error> {
        self.raw_element(ValueType::Structure, tag, &[])
    }

    fn start_array(&mut self, tag: Tag) -> Result<(), Error> {
        self.raw_element(ValueType::Array, tag, &[])
    }

    fn start_list(&mut self, tag: Tag) -> Result<(), Error> {
        self.raw_element(ValueType::List, tag, &[])
    }

    fn end_container(&mut self) -> Result<(), Error> {
        self.raw_element(ValueType::EndOfContainer, Tag::Anonymous, &[])
    }

    /// Write a value from its already-decoded type and payload.
    ///
    /// For containers, `payload` is the encoded body including its final
    /// anonymous end-of-container marker. For strings, `payload` contains only
    /// the string bytes, not the length field.
    #[doc(hidden)]
    fn raw_element(
        &mut self,
        value_type: ValueType,
        tag: Tag,
        payload: &[u8],
    ) -> Result<(), Error> {
        transaction(self, |writer| {
            let mut tag_bytes = [0_u8; 8];
            let (tag_control, tag_len) = tag.encode(&mut tag_bytes);
            let control = (tag_control << 5) | value_type as u8;
            writer.write_raw(core::slice::from_ref(&control))?;
            writer.write_raw(&tag_bytes[..tag_len])?;

            match value_type.length_width() {
                0 => {}
                1 => writer
                    .write_raw(&[u8::try_from(payload.len()).map_err(|_| Error::OutOfRange)?])?,
                2 => writer.write_raw(
                    &u16::try_from(payload.len())
                        .map_err(|_| Error::OutOfRange)?
                        .to_le_bytes(),
                )?,
                4 => writer.write_raw(
                    &u32::try_from(payload.len())
                        .map_err(|_| Error::OutOfRange)?
                        .to_le_bytes(),
                )?,
                8 => writer.write_raw(&(payload.len() as u64).to_le_bytes())?,
                _ => return Err(Error::Malformed),
            }

            writer.write_raw(payload)
        })
    }

    #[doc(hidden)]
    fn string_element(&mut self, utf8: bool, tag: Tag, value: &[u8]) -> Result<(), Error> {
        let value_type = match (utf8, value.len()) {
            (true, 0..=0xff) => ValueType::Utf8_1,
            (true, 0x100..=0xffff) => ValueType::Utf8_2,
            (true, 0x1_0000..=0xffff_ffff) => ValueType::Utf8_4,
            (true, _) => ValueType::Utf8_8,
            (false, 0..=0xff) => ValueType::Bytes1,
            (false, 0x100..=0xffff) => ValueType::Bytes2,
            (false, 0x1_0000..=0xffff_ffff) => ValueType::Bytes4,
            (false, _) => ValueType::Bytes8,
        };
        self.raw_element(value_type, tag, value)
    }
}

/// A writer whose complete initialized bytes can be sent without a copy.
pub trait TLVBuffer: TLVWrite {
    fn as_slice(&self) -> &[u8];
}

/// Execute a composite write atomically.
pub fn transaction<W, T>(
    writer: &mut W,
    operation: impl FnOnce(&mut W) -> Result<T, Error>,
) -> Result<T, Error>
where
    W: TLVWrite + ?Sized,
{
    let checkpoint = writer.position();
    match operation(writer) {
        Ok(value) => Ok(value),
        Err(error) => {
            writer.truncate(checkpoint);
            Err(error)
        }
    }
}

impl TLVWrite for InlineByteBuffer {
    fn position(&self) -> usize {
        self.len()
    }

    fn truncate(&mut self, position: usize) {
        assert!(position <= self.len(), "cannot roll a writer forward");
        // SAFETY: shortening the initialized prefix preserves every buffer
        // invariant and never exposes uninitialized storage.
        unsafe { self.set_len(position) };
    }

    fn write_raw(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

impl TLVBuffer for InlineByteBuffer {
    fn as_slice(&self) -> &[u8] {
        InlineByteBuffer::as_slice(self)
    }
}

/// A fixed-capacity, allocation-free writer over a caller-owned byte slice.
pub struct SliceWriter<'a> {
    bytes: &'a mut [u8],
    len: usize,
}

impl<'a> SliceWriter<'a> {
    pub const fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, len: 0 }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl TLVWrite for SliceWriter<'_> {
    fn position(&self) -> usize {
        self.len
    }

    fn truncate(&mut self, position: usize) {
        assert!(position <= self.len, "cannot roll a writer forward");
        self.len = position;
    }

    fn write_raw(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self.len.checked_add(bytes.len()).ok_or(Error::NoSpace)?;
        let target = self.bytes.get_mut(self.len..end).ok_or(Error::NoSpace)?;
        target.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

impl TLVBuffer for SliceWriter<'_> {
    fn as_slice(&self) -> &[u8] {
        SliceWriter::as_slice(self)
    }
}
