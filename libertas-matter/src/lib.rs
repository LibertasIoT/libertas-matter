// Copyright (c) 2026 Smartonlabs Inc.
// SPDX-License-Identifier: MIT

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unreachable_pub)]
#![deny(unnameable_types)]

//! Matter wire support for Libertas applications.
//!
//! The crate implements Matter TLV and the endpoint-free frame contract used
//! between a Libertas application and `libertasd`. It is not a Matter
//! transport, commissioner, or standalone node stack.

#[cfg(feature = "alloc")]
extern crate alloc;
extern crate self as libertas_matter;
#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod frame;
pub mod tlv;

#[cfg(feature = "alloc")]
mod batch;
#[cfg(feature = "alloc")]
mod bridge;
#[cfg(feature = "alloc")]
mod model;

pub use libertas::{InlineByteBuffer, LibertasDevice, LibertasTransId};
pub use libertas_matter_consts as consts;
pub use libertas_matter_macros::{
    FromTLV, ToTLV, matter_attribute, matter_attributes, matter_command, matter_commands,
    matter_event, matter_events, matter_tlv,
};

#[cfg(feature = "alloc")]
pub use batch::*;
#[cfg(feature = "alloc")]
pub use model::*;

/// Generated Matter schema definitions.
#[cfg(feature = "alloc")]
#[allow(non_snake_case, non_upper_case_globals, dead_code)]
pub mod definitions {
    libertas_matter_consts::matter_definitions!(libertas_matter);
}
