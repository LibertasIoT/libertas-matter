// Copyright (c) 2026 Smartonlabs Inc.
// SPDX-License-Identifier: MIT

//! Typed generated definitions bound to Libertas logical devices.

use crate::{
    InlineByteBuffer, LibertasDevice, LibertasTransId,
    bridge::{send_response, send_tlv_request},
    error::Error,
    frame::{self, InvokeResponse, Operation, Report},
    tlv::{FromTLV, TLVBuffer, ToTLV},
};

/// A payload whose decoded representation owns all borrowed wire data.
pub trait MatterPayload: ToTLV + for<'a> FromTLV<'a> {}

impl<T> MatterPayload for T where T: ToTLV + for<'a> FromTLV<'a> {}

pub trait MatterAttribute: MatterPayload {
    const CLUSTER_ID: u32;
    const ID: u32;
    const READABLE: bool;
    const WRITABLE: bool;
}

pub trait MatterCommand: MatterPayload {
    type Response: MatterPayload;

    const CLUSTER_ID: u32;
    const ID: u32;
    const RESPONSE_ID: Option<u32>;
}

pub trait MatterEvent: MatterPayload {
    const CLUSTER_ID: u32;
    const ID: u32;
}

pub type MatterStatus = frame::Status;
pub type MatterEventTimestamp = frame::EventTimestamp;
pub type MatterEventMetadata = frame::EventMetadata;

#[derive(Clone, Debug, PartialEq)]
pub enum MatterResponse<T> {
    Data(T),
    Status(MatterStatus),
}

/// Interaction Model status byte values used by the bridge.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum IMStatusCode {
    Success = 0x00,
    Failure = 0x01,
    InvalidSubscription = 0x7d,
    UnsupportedAccess = 0x7e,
    UnsupportedEndpoint = 0x7f,
    InvalidAction = 0x80,
    UnsupportedCommand = 0x81,
    InvalidCommand = 0x85,
    UnsupportedAttribute = 0x86,
    ConstraintError = 0x87,
    UnsupportedWrite = 0x88,
    ResourceExhausted = 0x89,
    NotFound = 0x8b,
    UnreportableAttribute = 0x8c,
    InvalidDataType = 0x8d,
    UnsupportedRead = 0x8f,
    DataVersionMismatch = 0x92,
    Timeout = 0x94,
    Busy = 0x9c,
    UnsupportedCluster = 0xc3,
    NoUpstreamSubscription = 0xc5,
    NeedsTimedInteraction = 0xc6,
    UnsupportedEvent = 0xc7,
    PathsExhausted = 0xc8,
    TimedRequestMismatch = 0xc9,
    FailSafeRequired = 0xca,
}

impl From<IMStatusCode> for MatterStatus {
    fn from(status: IMStatusCode) -> Self {
        Self {
            status: status as u8,
            cluster_status: None,
        }
    }
}

/// A Libertas logical device. The host supplies the physical Matter endpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct MatterDevice {
    id: LibertasDevice,
}

impl MatterDevice {
    pub const fn new(id: LibertasDevice) -> Self {
        Self { id }
    }

    pub const fn id(self) -> LibertasDevice {
        self.id
    }

    pub fn write_attribute<A: MatterAttribute>(self, value: &A) -> Result<LibertasTransId, Error> {
        let mut buffer = InlineByteBuffer::new();
        self.write_attribute_with_buffer(value, &mut buffer)
    }

    pub fn write_attribute_with_buffer<A: MatterAttribute, B: TLVBuffer + ?Sized>(
        self,
        value: &A,
        buffer: &mut B,
    ) -> Result<LibertasTransId, Error> {
        if !A::WRITABLE {
            return Err(Error::UnsupportedAccess);
        }
        encode_attribute_write(value, buffer)?;
        Ok(send_tlv_request(
            self.id,
            Operation::WriteRequest,
            buffer.as_slice(),
        ))
    }

    pub fn invoke<C: MatterCommand>(self, command: &C) -> Result<LibertasTransId, Error> {
        let mut buffer = InlineByteBuffer::new();
        self.invoke_with_buffer(command, &mut buffer)
    }

    pub fn invoke_with_buffer<C: MatterCommand, B: TLVBuffer + ?Sized>(
        self,
        command: &C,
        buffer: &mut B,
    ) -> Result<LibertasTransId, Error> {
        encode_command(command, buffer)?;
        Ok(send_tlv_request(
            self.id,
            Operation::InvokeRequest,
            buffer.as_slice(),
        ))
    }
}

impl From<LibertasDevice> for MatterDevice {
    fn from(id: LibertasDevice) -> Self {
        Self::new(id)
    }
}

impl From<MatterDevice> for LibertasDevice {
    fn from(device: MatterDevice) -> Self {
        device.id
    }
}

/// Routing information delivered with a virtual-device callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatterRequestContext {
    pub device: MatterDevice,
    pub transaction_id: LibertasTransId,
    pub peer: u32,
}

impl MatterRequestContext {
    pub const fn new(device: LibertasDevice, transaction_id: LibertasTransId, peer: u32) -> Self {
        Self {
            device: MatterDevice::new(device),
            transaction_id,
            peer,
        }
    }

    pub fn respond_command<C: MatterCommand>(self, response: &C::Response) -> Result<(), Error> {
        let mut buffer = InlineByteBuffer::new();
        self.respond_command_with_buffer::<C, _>(response, &mut buffer)
    }

    pub fn respond_command_with_buffer<C: MatterCommand, B: TLVBuffer + ?Sized>(
        self,
        response: &C::Response,
        buffer: &mut B,
    ) -> Result<(), Error> {
        buffer.truncate(0);
        let response_id = C::RESPONSE_ID.ok_or(Error::NoCommandResponse)?;
        frame::encode_command_response(buffer, C::CLUSTER_ID, response_id, response)?;
        send_response(
            self.device.id,
            self.transaction_id,
            self.peer,
            Operation::InvokeResponse,
            buffer.as_slice(),
        );
        Ok(())
    }

    pub fn respond_command_status<C: MatterCommand>(
        self,
        status: MatterStatus,
    ) -> Result<(), Error> {
        let mut buffer = InlineByteBuffer::new();
        self.respond_command_status_with_buffer::<C, _>(status, &mut buffer)
    }

    pub fn respond_command_status_with_buffer<C: MatterCommand, B: TLVBuffer + ?Sized>(
        self,
        status: MatterStatus,
        buffer: &mut B,
    ) -> Result<(), Error> {
        buffer.truncate(0);
        frame::encode_command_status(buffer, C::CLUSTER_ID, C::ID, status)?;
        send_response(
            self.device.id,
            self.transaction_id,
            self.peer,
            Operation::InvokeResponse,
            buffer.as_slice(),
        );
        Ok(())
    }

    pub fn respond_attribute<A: MatterAttribute>(self, value: &A) -> Result<(), Error> {
        let mut buffer = InlineByteBuffer::new();
        self.respond_attribute_with_buffer(value, &mut buffer)
    }

    pub fn respond_attribute_with_buffer<A: MatterAttribute, B: TLVBuffer + ?Sized>(
        self,
        value: &A,
        buffer: &mut B,
    ) -> Result<(), Error> {
        encode_attribute_report(value, buffer)?;
        send_response(
            self.device.id,
            self.transaction_id,
            self.peer,
            Operation::ReportData,
            buffer.as_slice(),
        );
        Ok(())
    }

    pub fn respond_event<E: MatterEvent>(
        self,
        value: &E,
        metadata: MatterEventMetadata,
    ) -> Result<(), Error> {
        let mut buffer = InlineByteBuffer::new();
        self.respond_event_with_buffer(value, metadata, &mut buffer)
    }

    pub fn respond_event_with_buffer<E: MatterEvent, B: TLVBuffer + ?Sized>(
        self,
        value: &E,
        metadata: MatterEventMetadata,
        buffer: &mut B,
    ) -> Result<(), Error> {
        encode_event_report(value, metadata, buffer)?;
        send_response(
            self.device.id,
            self.transaction_id,
            self.peer,
            Operation::ReportData,
            buffer.as_slice(),
        );
        Ok(())
    }

    pub fn respond_write_status<A: MatterAttribute>(
        self,
        status: MatterStatus,
    ) -> Result<(), Error> {
        let mut buffer = InlineByteBuffer::new();
        self.respond_write_status_with_buffer::<A, _>(status, &mut buffer)
    }

    pub fn respond_write_status_with_buffer<A: MatterAttribute, B: TLVBuffer + ?Sized>(
        self,
        status: MatterStatus,
        buffer: &mut B,
    ) -> Result<(), Error> {
        buffer.truncate(0);
        frame::encode_write_status(buffer, A::CLUSTER_ID, A::ID, status)?;
        send_response(
            self.device.id,
            self.transaction_id,
            self.peer,
            Operation::WriteResponse,
            buffer.as_slice(),
        );
        Ok(())
    }

    pub fn respond_status(self, status: IMStatusCode) {
        send_response(
            self.device.id,
            self.transaction_id,
            self.peer,
            Operation::StatusResponse,
            &[status as u8],
        );
    }
}

pub fn encode_command<C: MatterCommand, B: TLVBuffer + ?Sized>(
    command: &C,
    buffer: &mut B,
) -> Result<(), Error> {
    buffer.truncate(0);
    frame::encode_command_request(buffer, C::CLUSTER_ID, C::ID, command)
}

pub fn decode_command<C: MatterCommand>(encoded: &[u8]) -> Result<C, Error> {
    let command = frame::decode_command_request(encoded)?;
    if command.cluster_id != C::CLUSTER_ID || command.command_id != C::ID {
        return Err(Error::PathMismatch);
    }
    C::from_tlv(&command.fields.ok_or(Error::MissingField(1))?)
}

pub fn encode_attribute_write<A: MatterAttribute, B: TLVBuffer + ?Sized>(
    value: &A,
    buffer: &mut B,
) -> Result<(), Error> {
    buffer.truncate(0);
    frame::encode_attribute_write(buffer, A::CLUSTER_ID, A::ID, value)
}

pub fn decode_attribute_write<A: MatterAttribute>(encoded: &[u8]) -> Result<A, Error> {
    if !A::WRITABLE {
        return Err(Error::UnsupportedAccess);
    }
    let value = frame::decode_attribute_write(encoded, A::CLUSTER_ID, A::ID)?;
    A::from_tlv(&value)
}

pub fn decode_write_response<A: MatterAttribute>(encoded: &[u8]) -> Result<MatterStatus, Error> {
    frame::decode_write_status(encoded, A::CLUSTER_ID, A::ID)
}

pub fn decode_command_response<C: MatterCommand>(
    encoded: &[u8],
) -> Result<MatterResponse<C::Response>, Error> {
    match frame::decode_invoke_response(encoded)? {
        InvokeResponse::Command(command) => {
            if command.cluster_id != C::CLUSTER_ID || Some(command.command_id) != C::RESPONSE_ID {
                return Err(Error::PathMismatch);
            }
            Ok(MatterResponse::Data(C::Response::from_tlv(
                &command.fields.ok_or(Error::MissingField(1))?,
            )?))
        }
        InvokeResponse::Status {
            cluster_id,
            command_id,
            status,
        } => {
            if cluster_id != C::CLUSTER_ID || command_id != C::ID {
                return Err(Error::PathMismatch);
            }
            Ok(MatterResponse::Status(status))
        }
    }
}

pub fn decode_attribute_report<A: MatterAttribute>(
    encoded: &[u8],
) -> Result<MatterResponse<A>, Error> {
    match frame::decode_attribute_report(encoded, A::CLUSTER_ID, A::ID)? {
        Report::Data(value) => Ok(MatterResponse::Data(A::from_tlv(&value)?)),
        Report::Status(status) => Ok(MatterResponse::Status(status)),
    }
}

pub fn decode_event_report<E: MatterEvent>(encoded: &[u8]) -> Result<MatterResponse<E>, Error> {
    match frame::decode_event_report(encoded, E::CLUSTER_ID, E::ID)? {
        Report::Data(value) => Ok(MatterResponse::Data(E::from_tlv(&value)?)),
        Report::Status(status) => Ok(MatterResponse::Status(status)),
    }
}

pub fn encode_event_report<E: MatterEvent, B: TLVBuffer + ?Sized>(
    value: &E,
    metadata: MatterEventMetadata,
    buffer: &mut B,
) -> Result<(), Error> {
    buffer.truncate(0);
    frame::encode_event_report(buffer, E::CLUSTER_ID, E::ID, metadata, value)
}

fn encode_attribute_report<A: MatterAttribute, B: TLVBuffer + ?Sized>(
    value: &A,
    buffer: &mut B,
) -> Result<(), Error> {
    buffer.truncate(0);
    frame::encode_attribute_report(buffer, A::CLUSTER_ID, A::ID, value)
}
