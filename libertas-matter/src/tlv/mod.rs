// Copyright (c) 2026 Smartonlabs Inc.
// SPDX-License-Identifier: MIT

//! Matter tag-length-value encoding.

mod read;
mod traits;
mod write;

#[cfg(feature = "alloc")]
mod owned;

pub use read::{Element, Reader};
pub use traits::{FromTLV, Nullable, ToTLV};
pub use write::{SliceWriter, TLVBuffer, TLVWrite, transaction};

#[cfg(feature = "alloc")]
pub use owned::{MatterBytes, MatterList, MatterString, MatterTlv};

use crate::error::Error;

/// Matter TLV tag controls and payloads.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Tag {
    Anonymous,
    Context(u8),
    CommonProfile16(u16),
    CommonProfile32(u32),
    ImplicitProfile16(u16),
    ImplicitProfile32(u32),
    FullyQualified16 {
        vendor_id: u16,
        profile_number: u16,
        tag: u16,
    },
    FullyQualified32 {
        vendor_id: u16,
        profile_number: u16,
        tag: u32,
    },
}

impl Tag {
    pub(crate) fn encode(self, output: &mut [u8; 8]) -> (u8, usize) {
        match self {
            Self::Anonymous => (0, 0),
            Self::Context(tag) => {
                output[0] = tag;
                (1, 1)
            }
            Self::CommonProfile16(tag) => {
                output[..2].copy_from_slice(&tag.to_le_bytes());
                (2, 2)
            }
            Self::CommonProfile32(tag) => {
                output[..4].copy_from_slice(&tag.to_le_bytes());
                (3, 4)
            }
            Self::ImplicitProfile16(tag) => {
                output[..2].copy_from_slice(&tag.to_le_bytes());
                (4, 2)
            }
            Self::ImplicitProfile32(tag) => {
                output[..4].copy_from_slice(&tag.to_le_bytes());
                (5, 4)
            }
            Self::FullyQualified16 {
                vendor_id,
                profile_number,
                tag,
            } => {
                output[..2].copy_from_slice(&vendor_id.to_le_bytes());
                output[2..4].copy_from_slice(&profile_number.to_le_bytes());
                output[4..6].copy_from_slice(&tag.to_le_bytes());
                (6, 6)
            }
            Self::FullyQualified32 {
                vendor_id,
                profile_number,
                tag,
            } => {
                output[..2].copy_from_slice(&vendor_id.to_le_bytes());
                output[2..4].copy_from_slice(&profile_number.to_le_bytes());
                output[4..8].copy_from_slice(&tag.to_le_bytes());
                (7, 8)
            }
        }
    }

    pub(crate) fn decode(control: u8, bytes: &[u8]) -> Result<(Self, usize), Error> {
        Ok(match control {
            0 => (Self::Anonymous, 0),
            1 => (Self::Context(*bytes.first().ok_or(Error::Truncated)?), 1),
            2 => (
                Self::CommonProfile16(u16::from_le_bytes(read_array(bytes)?)),
                2,
            ),
            3 => (
                Self::CommonProfile32(u32::from_le_bytes(read_array(bytes)?)),
                4,
            ),
            4 => (
                Self::ImplicitProfile16(u16::from_le_bytes(read_array(bytes)?)),
                2,
            ),
            5 => (
                Self::ImplicitProfile32(u32::from_le_bytes(read_array(bytes)?)),
                4,
            ),
            6 => (
                Self::FullyQualified16 {
                    vendor_id: u16::from_le_bytes(read_array(bytes)?),
                    profile_number: u16::from_le_bytes(read_array(&bytes[2..])?),
                    tag: u16::from_le_bytes(read_array(&bytes[4..])?),
                },
                6,
            ),
            7 => (
                Self::FullyQualified32 {
                    vendor_id: u16::from_le_bytes(read_array(bytes)?),
                    profile_number: u16::from_le_bytes(read_array(&bytes[2..])?),
                    tag: u32::from_le_bytes(read_array(&bytes[4..])?),
                },
                8,
            ),
            _ => return Err(Error::Malformed),
        })
    }
}

/// Low five bits of a Matter TLV control byte.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ValueType {
    Signed8 = 0,
    Signed16 = 1,
    Signed32 = 2,
    Signed64 = 3,
    Unsigned8 = 4,
    Unsigned16 = 5,
    Unsigned32 = 6,
    Unsigned64 = 7,
    BooleanFalse = 8,
    BooleanTrue = 9,
    Float32 = 10,
    Float64 = 11,
    Utf8_1 = 12,
    Utf8_2 = 13,
    Utf8_4 = 14,
    Utf8_8 = 15,
    Bytes1 = 16,
    Bytes2 = 17,
    Bytes4 = 18,
    Bytes8 = 19,
    Null = 20,
    Structure = 21,
    Array = 22,
    List = 23,
    EndOfContainer = 24,
}

impl ValueType {
    pub const fn fixed_width(self) -> Option<usize> {
        Some(match self {
            Self::Signed8 | Self::Unsigned8 => 1,
            Self::Signed16 | Self::Unsigned16 => 2,
            Self::Signed32 | Self::Unsigned32 | Self::Float32 => 4,
            Self::Signed64 | Self::Unsigned64 | Self::Float64 => 8,
            Self::Utf8_1
            | Self::Utf8_2
            | Self::Utf8_4
            | Self::Utf8_8
            | Self::Bytes1
            | Self::Bytes2
            | Self::Bytes4
            | Self::Bytes8 => return None,
            Self::BooleanFalse
            | Self::BooleanTrue
            | Self::Null
            | Self::Structure
            | Self::Array
            | Self::List
            | Self::EndOfContainer => 0,
        })
    }

    pub const fn length_width(self) -> usize {
        match self {
            Self::Utf8_1 | Self::Bytes1 => 1,
            Self::Utf8_2 | Self::Bytes2 => 2,
            Self::Utf8_4 | Self::Bytes4 => 4,
            Self::Utf8_8 | Self::Bytes8 => 8,
            _ => 0,
        }
    }

    pub const fn is_container_start(self) -> bool {
        matches!(self, Self::Structure | Self::Array | Self::List)
    }

    pub const fn is_utf8(self) -> bool {
        matches!(
            self,
            Self::Utf8_1 | Self::Utf8_2 | Self::Utf8_4 | Self::Utf8_8
        )
    }

    pub const fn is_bytes(self) -> bool {
        matches!(
            self,
            Self::Bytes1 | Self::Bytes2 | Self::Bytes4 | Self::Bytes8
        )
    }
}

impl TryFrom<u8> for ValueType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::Signed8,
            1 => Self::Signed16,
            2 => Self::Signed32,
            3 => Self::Signed64,
            4 => Self::Unsigned8,
            5 => Self::Unsigned16,
            6 => Self::Unsigned32,
            7 => Self::Unsigned64,
            8 => Self::BooleanFalse,
            9 => Self::BooleanTrue,
            10 => Self::Float32,
            11 => Self::Float64,
            12 => Self::Utf8_1,
            13 => Self::Utf8_2,
            14 => Self::Utf8_4,
            15 => Self::Utf8_8,
            16 => Self::Bytes1,
            17 => Self::Bytes2,
            18 => Self::Bytes4,
            19 => Self::Bytes8,
            20 => Self::Null,
            21 => Self::Structure,
            22 => Self::Array,
            23 => Self::List,
            24 => Self::EndOfContainer,
            _ => return Err(Error::Malformed),
        })
    }
}

fn read_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes
        .get(..N)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}

/// Compatibility aliases for earlier Libertas releases.
pub type TLVElement<'a> = Element<'a>;
pub type TLVTag = Tag;
