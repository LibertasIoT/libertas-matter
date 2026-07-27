// Copyright (c) 2026 Smartonlabs Inc.
// SPDX-License-Identifier: MIT

//! Allocation-backed values used by generated Matter definitions.

use alloc::{string::String, vec::Vec};
use core::ops::{Deref, DerefMut};

use crate::error::Error;

use super::{Element, FromTLV, TLVWrite, Tag, ToTLV, ValueType, transaction};

impl ToTLV for str {
    fn to_tlv<W: TLVWrite + ?Sized>(&self, tag: Tag, writer: &mut W) -> Result<(), Error> {
        writer.utf8(tag, self)
    }
}

impl ToTLV for String {
    fn to_tlv<W: TLVWrite + ?Sized>(&self, tag: Tag, writer: &mut W) -> Result<(), Error> {
        writer.utf8(tag, self)
    }
}

impl<'a> FromTLV<'a> for String {
    fn from_tlv(element: &Element<'a>) -> Result<Self, Error> {
        Ok(String::from(element.utf8()?))
    }
}

impl<T: ToTLV> ToTLV for [T] {
    fn to_tlv<W: TLVWrite + ?Sized>(&self, tag: Tag, writer: &mut W) -> Result<(), Error> {
        transaction(writer, |writer| {
            writer.start_array(tag)?;
            let mut index = 0;
            while index < self.len() {
                self[index].to_tlv(Tag::Anonymous, writer)?;
                index += 1;
            }
            writer.end_container()
        })
    }
}

impl<T: ToTLV> ToTLV for Vec<T> {
    fn to_tlv<W: TLVWrite + ?Sized>(&self, tag: Tag, writer: &mut W) -> Result<(), Error> {
        self.as_slice().to_tlv(tag, writer)
    }
}

impl<'a, T: FromTLV<'a>> FromTLV<'a> for Vec<T> {
    fn from_tlv(element: &Element<'a>) -> Result<Self, Error> {
        if element.value_type() != ValueType::Array {
            return Err(Error::TypeMismatch);
        }
        let mut values = Vec::new();
        let mut reader = element.children()?;
        while let Some(value) = reader.read_element()? {
            values.push(T::from_tlv(&value)?);
        }
        Ok(values)
    }
}

/// Owned Matter octet string.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct MatterBytes(pub Vec<u8>);

impl MatterBytes {
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl Deref for MatterBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for MatterBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ToTLV for MatterBytes {
    fn to_tlv<W: TLVWrite + ?Sized>(&self, tag: Tag, writer: &mut W) -> Result<(), Error> {
        writer.bytes(tag, &self.0)
    }
}

impl<'a> FromTLV<'a> for MatterBytes {
    fn from_tlv(element: &Element<'a>) -> Result<Self, Error> {
        Ok(Self(Vec::from(element.bytes()?)))
    }
}

/// An owned schema-opaque complete TLV element.
///
/// Re-encoding preserves its type and value bytes while replacing its tag with
/// the tag selected by the enclosing schema.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct MatterTlv(pub Vec<u8>);

impl MatterTlv {
    pub const fn new(encoded: Vec<u8>) -> Self {
        Self(encoded)
    }

    pub fn as_element(&self) -> Result<Element<'_>, Error> {
        Element::from_bytes(&self.0)
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl ToTLV for MatterTlv {
    fn to_tlv<W: TLVWrite + ?Sized>(&self, tag: Tag, writer: &mut W) -> Result<(), Error> {
        let element = self.as_element()?;
        writer.raw_element(element.value_type(), tag, element.value_bytes())
    }
}

impl<'a> FromTLV<'a> for MatterTlv {
    fn from_tlv(element: &Element<'a>) -> Result<Self, Error> {
        Ok(Self(Vec::from(element.encoded())))
    }
}

/// Generated definition alias for owned UTF-8 strings.
pub type MatterString = String;

/// Generated definition alias for owned Matter arrays.
pub type MatterList<T> = Vec<T>;
