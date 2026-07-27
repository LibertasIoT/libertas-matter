// Copyright (c) 2026 Smartonlabs Inc.
// SPDX-License-Identifier: MIT

//! Errors returned by TLV and Libertas frame operations.

use core::fmt;

/// A compact error suitable for `no_std` callers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Input ended before an element was complete.
    Truncated,
    /// A control byte, tag, length, or container boundary is malformed.
    Malformed,
    /// The element has a different TLV type than requested.
    TypeMismatch,
    /// A required context-tagged field is absent.
    MissingField(u8),
    /// A numeric value cannot be represented by the requested Rust type.
    OutOfRange,
    /// A schema constraint was violated.
    Constraint,
    /// The writer has insufficient capacity.
    NoSpace,
    /// A decoded string is not UTF-8.
    InvalidUtf8,
    /// A generated path does not identify the requested cluster or item.
    PathMismatch,
    /// The operation is not allowed by the generated definition.
    UnsupportedAccess,
    /// A generated command has no response payload.
    NoCommandResponse,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(tag) => write!(formatter, "missing context tag {tag}"),
            _ => write!(formatter, "{self:?}"),
        }
    }
}

impl core::error::Error for Error {}

impl From<core::str::Utf8Error> for Error {
    fn from(_: core::str::Utf8Error) -> Self {
        Self::InvalidUtf8
    }
}
