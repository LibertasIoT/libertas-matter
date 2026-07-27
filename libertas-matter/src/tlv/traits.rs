// Copyright (c) 2026 Smartonlabs Inc.
// SPDX-License-Identifier: MIT

//! Direct serialization and borrowed decoding traits.

use crate::error::Error;

use super::{Element, TLVWrite, Tag, ValueType};

/// Encode a Rust value at a caller-selected Matter tag.
pub trait ToTLV {
    fn to_tlv<W: TLVWrite + ?Sized>(&self, tag: Tag, writer: &mut W) -> Result<(), Error>;

    /// Encode a non-null member of a nullable Matter field.
    fn nullable_to_tlv<W: TLVWrite + ?Sized>(&self, tag: Tag, writer: &mut W) -> Result<(), Error> {
        self.to_tlv(tag, writer)
    }
}

/// Decode a Rust value from one borrowed Matter element.
pub trait FromTLV<'a>: Sized {
    fn from_tlv(element: &Element<'a>) -> Result<Self, Error>;

    /// Decode the non-null member domain of a nullable Matter field.
    fn nullable_from_tlv(element: &Element<'a>) -> Result<Self, Error> {
        Self::from_tlv(element)
    }
}

/// A present Matter value that is explicitly either null or non-null.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub enum Nullable<T> {
    #[default]
    Null,
    Value(T),
}

impl<T> Nullable<T> {
    pub const fn null() -> Self {
        Self::Null
    }

    pub const fn some(value: T) -> Self {
        Self::Value(value)
    }

    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    pub const fn as_ref(&self) -> Nullable<&T> {
        match self {
            Self::Null => Nullable::Null,
            Self::Value(value) => Nullable::Value(value),
        }
    }

    pub fn into_option(self) -> Option<T> {
        match self {
            Self::Null => None,
            Self::Value(value) => Some(value),
        }
    }
}

impl<T> From<Option<T>> for Nullable<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(value) => Self::Value(value),
            None => Self::Null,
        }
    }
}

impl<T: ToTLV> ToTLV for Nullable<T> {
    fn to_tlv<W: TLVWrite + ?Sized>(&self, tag: Tag, writer: &mut W) -> Result<(), Error> {
        match self {
            Self::Null => writer.null(tag),
            Self::Value(value) => value.nullable_to_tlv(tag, writer),
        }
    }
}

impl<'a, T: FromTLV<'a>> FromTLV<'a> for Nullable<T> {
    fn from_tlv(element: &Element<'a>) -> Result<Self, Error> {
        if element.is_null() {
            Ok(Self::Null)
        } else {
            T::nullable_from_tlv(element).map(Self::Value)
        }
    }
}

impl<T: ToTLV> ToTLV for Option<T> {
    fn to_tlv<W: TLVWrite + ?Sized>(&self, tag: Tag, writer: &mut W) -> Result<(), Error> {
        match self {
            Some(value) => value.to_tlv(tag, writer),
            None => Ok(()),
        }
    }
}

impl<'a, T: FromTLV<'a>> FromTLV<'a> for Option<T> {
    fn from_tlv(element: &Element<'a>) -> Result<Self, Error> {
        T::from_tlv(element).map(Some)
    }
}

macro_rules! integer_impl {
    ($type:ty, $write:ident, $read:ident, $null:expr) => {
        impl ToTLV for $type {
            fn to_tlv<W: TLVWrite + ?Sized>(&self, tag: Tag, writer: &mut W) -> Result<(), Error> {
                writer.$write(tag, *self)
            }

            fn nullable_to_tlv<W: TLVWrite + ?Sized>(
                &self,
                tag: Tag,
                writer: &mut W,
            ) -> Result<(), Error> {
                if *self == $null {
                    Err(Error::Constraint)
                } else {
                    writer.$write(tag, *self)
                }
            }
        }

        impl<'a> FromTLV<'a> for $type {
            fn from_tlv(element: &Element<'a>) -> Result<Self, Error> {
                element.$read()
            }

            fn nullable_from_tlv(element: &Element<'a>) -> Result<Self, Error> {
                let value = element.$read()?;
                if value == $null {
                    Err(Error::Constraint)
                } else {
                    Ok(value)
                }
            }
        }
    };
}

integer_impl!(i8, i8, i8, i8::MIN);
integer_impl!(i16, i16, i16, i16::MIN);
integer_impl!(i32, i32, i32, i32::MIN);
integer_impl!(i64, i64, i64, i64::MIN);
integer_impl!(u8, u8, u8, u8::MAX);
integer_impl!(u16, u16, u16, u16::MAX);
integer_impl!(u32, u32, u32, u32::MAX);
integer_impl!(u64, u64, u64, u64::MAX);

impl ToTLV for bool {
    fn to_tlv<W: TLVWrite + ?Sized>(&self, tag: Tag, writer: &mut W) -> Result<(), Error> {
        writer.bool(tag, *self)
    }
}

impl FromTLV<'_> for bool {
    fn from_tlv(element: &Element<'_>) -> Result<Self, Error> {
        element.bool()
    }
}

impl ToTLV for f32 {
    fn to_tlv<W: TLVWrite + ?Sized>(&self, tag: Tag, writer: &mut W) -> Result<(), Error> {
        writer.f32(tag, *self)
    }
}

impl FromTLV<'_> for f32 {
    fn from_tlv(element: &Element<'_>) -> Result<Self, Error> {
        element.f32()
    }
}

impl ToTLV for f64 {
    fn to_tlv<W: TLVWrite + ?Sized>(&self, tag: Tag, writer: &mut W) -> Result<(), Error> {
        writer.f64(tag, *self)
    }
}

impl FromTLV<'_> for f64 {
    fn from_tlv(element: &Element<'_>) -> Result<Self, Error> {
        element.f64()
    }
}

impl<T: ToTLV + ?Sized> ToTLV for &T {
    fn to_tlv<W: TLVWrite + ?Sized>(&self, tag: Tag, writer: &mut W) -> Result<(), Error> {
        (*self).to_tlv(tag, writer)
    }
}

impl ToTLV for () {
    fn to_tlv<W: TLVWrite + ?Sized>(&self, tag: Tag, writer: &mut W) -> Result<(), Error> {
        super::transaction(writer, |writer| {
            writer.start_struct(tag)?;
            writer.end_container()
        })
    }
}

impl FromTLV<'_> for () {
    fn from_tlv(element: &Element<'_>) -> Result<Self, Error> {
        if element.value_type() != ValueType::Structure
            || element.children()?.read_element()?.is_some()
        {
            Err(Error::TypeMismatch)
        } else {
            Ok(())
        }
    }
}
