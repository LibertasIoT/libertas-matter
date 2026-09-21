// Copyright (c) 2026 Smartonlabs Inc.
// SPDX-License-Identifier: MIT

//! Bounded, zero-copy batch operations.

use core::{marker::PhantomData, slice};

use crate::{
    bridge::{send_changed, send_read, send_subscribe, send_tlv_request},
    error::Error,
    frame::{self, Operation},
    model::{MatterAttribute, MatterDevice, MatterEvent},
    tlv::TLVBuffer,
    LibertasDevice, LibertasTransId,
};

/// Fixed-capacity typed paths for one cluster in a read request.
///
/// The capacity is selected by the application and consumes exactly four
/// bytes per attribute or event plus a small header. No allocation occurs.
pub struct MatterReadCluster<const ATTRIBUTES: usize, const EVENTS: usize> {
    cluster_id: u32,
    attribute_count: u16,
    event_count: u16,
    attributes: [u32; ATTRIBUTES],
    events: [u32; EVENTS],
}

impl<const ATTRIBUTES: usize, const EVENTS: usize> MatterReadCluster<ATTRIBUTES, EVENTS> {
    pub const fn new(cluster_id: u32) -> Self {
        Self {
            cluster_id,
            attribute_count: 0,
            event_count: 0,
            attributes: [0; ATTRIBUTES],
            events: [0; EVENTS],
        }
    }

    pub const fn for_attribute<A: MatterAttribute>() -> Self {
        Self::new(A::CLUSTER_ID)
    }

    pub const fn for_event<E: MatterEvent>() -> Self {
        Self::new(E::CLUSTER_ID)
    }

    pub fn add_attribute<A: MatterAttribute>(&mut self) -> Result<&mut Self, Error> {
        if !A::READABLE {
            return Err(Error::UnsupportedAccess);
        }
        if A::CLUSTER_ID != self.cluster_id {
            return Err(Error::PathMismatch);
        }
        let index = usize::from(self.attribute_count);
        let next = self.attribute_count.checked_add(1).ok_or(Error::NoSpace)?;
        *self.attributes.get_mut(index).ok_or(Error::NoSpace)? = A::ID;
        self.attribute_count = next;
        Ok(self)
    }

    pub fn add_event<E: MatterEvent>(&mut self) -> Result<&mut Self, Error> {
        if E::CLUSTER_ID != self.cluster_id {
            return Err(Error::PathMismatch);
        }
        let index = usize::from(self.event_count);
        let next = self.event_count.checked_add(1).ok_or(Error::NoSpace)?;
        *self.events.get_mut(index).ok_or(Error::NoSpace)? = E::ID;
        self.event_count = next;
        Ok(self)
    }

    pub const fn cluster_id(&self) -> u32 {
        self.cluster_id
    }

    pub fn attributes(&self) -> &[u32] {
        &self.attributes[..usize::from(self.attribute_count)]
    }

    pub fn events(&self) -> &[u32] {
        &self.events[..usize::from(self.event_count)]
    }

    pub fn request(&self) -> Result<MatterReadRequest<'_>, Error> {
        MatterReadRequest::new(self.cluster_id, self.attributes(), self.events())
    }
}

/// Borrowed read-cluster descriptor sent directly through the native ABI.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct MatterReadRequest<'a> {
    pub(crate) cluster_id: u32,
    pub(crate) attributes: *const u32,
    pub(crate) attributes_len: usize,
    pub(crate) events: *const u32,
    pub(crate) events_len: usize,
    lifetime: PhantomData<&'a [u32]>,
}

impl<'a> MatterReadRequest<'a> {
    fn new(cluster_id: u32, attributes: &'a [u32], events: &'a [u32]) -> Result<Self, Error> {
        if attributes.is_empty() && events.is_empty() {
            return Err(Error::Constraint);
        }
        Ok(Self::from_slices(cluster_id, attributes, events))
    }

    fn from_slices(cluster_id: u32, attributes: &'a [u32], events: &'a [u32]) -> Self {
        Self {
            cluster_id,
            attributes: attributes.as_ptr(),
            attributes_len: attributes.len(),
            events: events.as_ptr(),
            events_len: events.len(),
            lifetime: PhantomData,
        }
    }
}

impl MatterDevice {
    /// Send one read request containing every supplied cluster path.
    pub fn read_batch(self, clusters: &[MatterReadRequest<'_>]) -> Result<LibertasTransId, Error> {
        if clusters.is_empty() {
            return Err(Error::Constraint);
        }
        Ok(send_read(self.id(), clusters))
    }

    pub fn read_attribute<A: MatterAttribute>(self) -> Result<LibertasTransId, Error> {
        if !A::READABLE {
            return Err(Error::UnsupportedAccess);
        }
        let attributes = [A::ID];
        let request = MatterReadRequest::from_slices(A::CLUSTER_ID, &attributes, &[]);
        Ok(send_read(self.id(), slice::from_ref(&request)))
    }

    pub fn read_event<E: MatterEvent>(self) -> LibertasTransId {
        let events = [E::ID];
        let request = MatterReadRequest::from_slices(E::CLUSTER_ID, &[], &events);
        send_read(self.id(), slice::from_ref(&request))
    }

    /// Notify the host of several changed paths in one operation.
    pub fn changed_batch(
        self,
        peer: libertas::LibertasPeer,
        clusters: &[MatterReadRequest<'_>],
    ) -> Result<LibertasTransId, Error> {
        if clusters.is_empty() {
            return Err(Error::Constraint);
        }
        Ok(send_changed(self.id(), peer, clusters))
    }

    pub fn attribute_changed<A: MatterAttribute>(
        self,
        peer: libertas::LibertasPeer,
    ) -> Result<LibertasTransId, Error> {
        if !A::READABLE {
            return Err(Error::UnsupportedAccess);
        }
        let attributes = [A::ID];
        let request = MatterReadRequest::from_slices(A::CLUSTER_ID, &attributes, &[]);
        Ok(send_changed(self.id(), peer, slice::from_ref(&request)))
    }

    pub fn event_changed<E: MatterEvent>(self, peer: libertas::LibertasPeer) -> LibertasTransId {
        let events = [E::ID];
        let request = MatterReadRequest::from_slices(E::CLUSTER_ID, &[], &events);
        send_changed(self.id(), peer, slice::from_ref(&request))
    }

    /// Begin a heterogeneous attribute write that uses caller-owned storage.
    pub fn write_batch<'a, B: TLVBuffer + ?Sized>(
        self,
        buffer: &'a mut B,
    ) -> Result<MatterWriteBatch<'a, B>, Error> {
        MatterWriteBatch::new(self, buffer)
    }
}

/// Direct heterogeneous write encoder for one logical device.
///
/// Entries are serialized as they are added, so attribute values are never
/// retained or copied. Dropping an unfinished batch rolls the buffer back to
/// empty.
pub struct MatterWriteBatch<'a, B: TLVBuffer + ?Sized> {
    device: MatterDevice,
    buffer: &'a mut B,
    entries: u16,
    complete: bool,
}

impl<'a, B: TLVBuffer + ?Sized> MatterWriteBatch<'a, B> {
    fn new(device: MatterDevice, buffer: &'a mut B) -> Result<Self, Error> {
        buffer.truncate(0);
        frame::start_attribute_write_batch(buffer)?;
        Ok(Self {
            device,
            buffer,
            entries: 0,
            complete: false,
        })
    }

    pub fn attribute<A: MatterAttribute>(&mut self, value: &A) -> Result<&mut Self, Error> {
        if !A::WRITABLE {
            return Err(Error::UnsupportedAccess);
        }
        let next = self.entries.checked_add(1).ok_or(Error::OutOfRange)?;
        frame::write_attribute_batch_entry(buffer_mut(self), A::CLUSTER_ID, A::ID, value)?;
        self.entries = next;
        Ok(self)
    }

    pub const fn len(&self) -> usize {
        self.entries as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.entries == 0
    }

    /// Finish encoding without sending, leaving the complete frame in the
    /// caller's buffer.
    pub fn finish_encoding(mut self) -> Result<(), Error> {
        self.finish()?;
        Ok(())
    }

    /// Finish the frame and send exactly one write request.
    pub fn send(mut self) -> Result<LibertasTransId, Error> {
        self.finish()?;
        Ok(send_tlv_request(
            self.device.id(),
            Operation::WriteRequest,
            self.buffer.as_slice(),
        ))
    }

    fn finish(&mut self) -> Result<(), Error> {
        if self.entries == 0 {
            return Err(Error::Constraint);
        }
        frame::finish_attribute_write_batch(self.buffer)?;
        self.complete = true;
        Ok(())
    }
}

fn buffer_mut<'a, B: TLVBuffer + ?Sized>(batch: &'a mut MatterWriteBatch<'_, B>) -> &'a mut B {
    batch.buffer
}

impl<B: TLVBuffer + ?Sized> Drop for MatterWriteBatch<'_, B> {
    fn drop(&mut self) {
        if !self.complete {
            self.buffer.truncate(0);
        }
    }
}

/// Typed event entry stored directly in a native subscription request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct MatterEventSubscription {
    pub(crate) event_id: u32,
    pub(crate) urgent: bool,
}

impl MatterEventSubscription {
    const EMPTY: Self = Self {
        event_id: 0,
        urgent: false,
    };

    pub const fn event_id(self) -> u32 {
        self.event_id
    }

    pub const fn urgent(self) -> bool {
        self.urgent
    }
}

/// Fixed-capacity typed subscription paths for one cluster.
pub struct MatterSubscriptionCluster<const ATTRIBUTES: usize, const EVENTS: usize> {
    cluster_id: u32,
    min_interval: u16,
    max_interval: u16,
    attribute_count: u16,
    event_count: u16,
    attributes: [u32; ATTRIBUTES],
    events: [MatterEventSubscription; EVENTS],
}

impl<const ATTRIBUTES: usize, const EVENTS: usize> MatterSubscriptionCluster<ATTRIBUTES, EVENTS> {
    pub const fn new(cluster_id: u32, min_interval: u16, max_interval: u16) -> Self {
        Self {
            cluster_id,
            min_interval,
            max_interval,
            attribute_count: 0,
            event_count: 0,
            attributes: [0; ATTRIBUTES],
            events: [MatterEventSubscription::EMPTY; EVENTS],
        }
    }

    pub const fn for_attribute<A: MatterAttribute>(min_interval: u16, max_interval: u16) -> Self {
        Self::new(A::CLUSTER_ID, min_interval, max_interval)
    }

    pub const fn for_event<E: MatterEvent>(min_interval: u16, max_interval: u16) -> Self {
        Self::new(E::CLUSTER_ID, min_interval, max_interval)
    }

    pub fn add_attribute<A: MatterAttribute>(&mut self) -> Result<&mut Self, Error> {
        if !A::READABLE {
            return Err(Error::UnsupportedAccess);
        }
        if A::CLUSTER_ID != self.cluster_id {
            return Err(Error::PathMismatch);
        }
        if self.attributes().contains(&A::ID) {
            return Err(Error::Constraint);
        }
        let index = usize::from(self.attribute_count);
        let next = self.attribute_count.checked_add(1).ok_or(Error::NoSpace)?;
        *self.attributes.get_mut(index).ok_or(Error::NoSpace)? = A::ID;
        self.attribute_count = next;
        Ok(self)
    }

    pub fn add_event<E: MatterEvent>(&mut self, urgent: bool) -> Result<&mut Self, Error> {
        if E::CLUSTER_ID != self.cluster_id {
            return Err(Error::PathMismatch);
        }
        if self.events().iter().any(|event| event.event_id == E::ID) {
            return Err(Error::Constraint);
        }
        let index = usize::from(self.event_count);
        let next = self.event_count.checked_add(1).ok_or(Error::NoSpace)?;
        *self.events.get_mut(index).ok_or(Error::NoSpace)? = MatterEventSubscription {
            event_id: E::ID,
            urgent,
        };
        self.event_count = next;
        Ok(self)
    }

    pub const fn cluster_id(&self) -> u32 {
        self.cluster_id
    }

    pub const fn min_interval(&self) -> u16 {
        self.min_interval
    }

    pub const fn max_interval(&self) -> u16 {
        self.max_interval
    }

    pub fn attributes(&self) -> &[u32] {
        &self.attributes[..usize::from(self.attribute_count)]
    }

    pub fn events(&self) -> &[MatterEventSubscription] {
        &self.events[..usize::from(self.event_count)]
    }

    pub fn request(&self) -> Result<MatterClusterSubscription<'_>, Error> {
        if self.min_interval > self.max_interval {
            return Err(Error::Constraint);
        }
        let attributes = self.attributes();
        let events = self.events();
        if attributes.is_empty() && events.is_empty() {
            return Err(Error::Constraint);
        }
        Ok(MatterClusterSubscription {
            cluster_id: self.cluster_id,
            min_interval: self.min_interval,
            max_interval: self.max_interval,
            attributes: attributes.as_ptr(),
            attributes_len: attributes.len(),
            events: events.as_ptr(),
            events_len: events.len(),
            lifetime: PhantomData,
        })
    }
}

/// Borrowed cluster descriptor for a subscription.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct MatterClusterSubscription<'a> {
    pub(crate) cluster_id: u32,
    pub(crate) min_interval: u16,
    pub(crate) max_interval: u16,
    pub(crate) attributes: *const u32,
    pub(crate) attributes_len: usize,
    pub(crate) events: *const MatterEventSubscription,
    pub(crate) events_len: usize,
    lifetime: PhantomData<&'a ()>,
}

/// One device entry in a task-wide [`MatterSubscriptionBatch`].
///
/// A device entry cannot be sent independently. Its device ID must be nonzero,
/// it must contain at least one cluster, and each cluster ID must occur only
/// once so the replacement snapshot has one deterministic policy per cluster.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct MatterDeviceSubscription<'a> {
    pub(crate) device: LibertasDevice,
    pub(crate) clusters: *const MatterClusterSubscription<'a>,
    pub(crate) clusters_len: usize,
    pub(crate) event_min: u64,
    lifetime: PhantomData<&'a [MatterClusterSubscription<'a>]>,
}

impl<'a> MatterDeviceSubscription<'a> {
    /// Create one validated device entry for a task-wide subscription batch.
    ///
    /// Returns [`Error::Constraint`] for device zero, an empty cluster slice,
    /// or duplicate cluster IDs.
    pub fn new(
        device: MatterDevice,
        clusters: &'a [MatterClusterSubscription<'a>],
    ) -> Result<Self, Error> {
        if device.id() == 0 || clusters.is_empty() {
            return Err(Error::Constraint);
        }
        for (index, cluster) in clusters.iter().enumerate() {
            if clusters[..index]
                .iter()
                .any(|previous| previous.cluster_id == cluster.cluster_id)
            {
                return Err(Error::Constraint);
            }
        }
        Ok(Self {
            device: device.id(),
            clusters: clusters.as_ptr(),
            clusters_len: clusters.len(),
            event_min: 0,
            lifetime: PhantomData,
        })
    }

    pub const fn with_event_min(mut self, event_min: u64) -> Self {
        self.event_min = event_min;
        self
    }

    pub const fn device(&self) -> LibertasDevice {
        self.device
    }

    pub const fn event_min(&self) -> u64 {
        self.event_min
    }
}

/// The complete, borrowed Matter subscription set for one App task.
///
/// Matter subscriptions can only be sent through this task-wide batch. Sending
/// a new batch replaces the task's previous Matter subscription set; there is
/// no additive or per-device subscription operation.
pub struct MatterSubscriptionBatch<'a> {
    devices: &'a [MatterDeviceSubscription<'a>],
}

impl<'a> MatterSubscriptionBatch<'a> {
    /// Validate a complete replacement snapshot for the App task.
    ///
    /// Returns [`Error::Constraint`] when the snapshot is empty or repeats a
    /// device ID. The caller's order is preserved, while uniqueness makes the
    /// resulting task subscription set unambiguous.
    pub fn new(devices: &'a [MatterDeviceSubscription<'a>]) -> Result<Self, Error> {
        if devices.is_empty() {
            return Err(Error::Constraint);
        }
        for (index, device) in devices.iter().enumerate() {
            if devices[..index]
                .iter()
                .any(|previous| previous.device == device.device)
            {
                return Err(Error::Constraint);
            }
        }
        Ok(Self { devices })
    }

    pub const fn len(&self) -> usize {
        self.devices.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Replace the App task's complete subscription set through one host call.
    ///
    /// This is the crate's only subscription send operation. Once the host
    /// accepts this batch, it invalidates the task's previous Matter
    /// subscription set before installing this complete snapshot.
    pub fn send(self) -> LibertasTransId {
        send_subscribe(self.devices)
    }
}
