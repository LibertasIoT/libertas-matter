/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#![no_std] 

//! Native Rust Implementation of Matter (Smart-Home)
//!
//! This crate implements the Matter specification that can be run on embedded devices
//! to build Matter-compatible smart-home/IoT devices.
//!
//! Currently Ethernet based transport is supported.
//!
//! # Examples
//! ```ignore
//! /// TODO: Fix once new API has stabilized a bit
//! use rs_matter::{Matter, CommissioningData};
//! use rs_matter::dm::device_types::device_type_add_on_off_light;
//! use rs_matter::dm::cluster_basic_information::BasicInfoConfig;
//! use rs_matter::sc::spake2p::VerifierData;
//!
//! # use rs_matter::dm::sdm::dev_att::{DataType, DevAttDataFetcher};
//! # use rs_matter::error::Error;
//! # pub struct DevAtt{}
//! # impl DevAttDataFetcher for DevAtt{
//! # fn get_devatt_data(&self, data_type: DataType, data: &mut [u8]) -> Result<usize, Error> { Ok(0) }
//! # }
//! # let dev_att = Box::new(DevAtt{});
//!
//! /// The commissioning data for this device
//! let comm_data = CommissioningData {
//!     verifier: VerifierData::new_with_pw(123456),
//!     discriminator: 250,
//! };
//!
//! /// The basic information about this device
//! let dev_info = BasicInfoConfig {
//!     vid: 0x8000,
//!     pid: 0xFFF1,
//!     hw_ver: 2,
//!     sw_ver: 1,
//!     sw_ver_str: "1".to_string(),
//!     serial_no: "aabbcc".to_string(),
//!     device_name: "OnOff Light".to_string(),
//! };
//!
//! /// Get the Matter Object
//! /// The dev_att is an object that implements the DevAttDataFetcher trait.
//! let mut matter = Matter::new(dev_info, dev_att, comm_data).unwrap();
//! let dm = matter.get_data_model();
//! {
//!     let mut node = dm.node.write().unwrap();
//!     /// Add our device-types
//!     let endpoint = device_type_add_on_off_light(&mut node).unwrap();
//! }
//! // Start the Matter Daemon
//! // matter.start_daemon().unwrap();
//! ```
//!
//! Start off exploring by going to the [Matter] object.

/// Re-export the `libertas_matter_macros::import` proc-macro
pub use libertas_matter_macros::import;
pub use im::{IMStatusCode, OpCode};
use libertas::*;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

// This mod MUST go first, so that the others see its macros.
pub(crate) mod fmt;

pub mod error;
pub mod im;
pub mod tlv;
pub mod utils;

/// Represents a subscription to a cluster event
/// 
/// Used to subscribe to specific events within a cluster with urgency levels.
#[repr(C)]
pub struct LibertasClusterEventSubscription {
    /// The ID of the event to subscribe to
    pub event_id: u32,
    /// Whether this event is urgent
    pub urgent: bool,
}

#[repr(C)]
struct LibertasClusterSubscribeReqRaw {
    cluster: u32,
    min_interval: u16,
    max_interval: u16,
    attributes: *const u32,
    attributes_len: usize,
    events:  *const LibertasClusterEventSubscription,
    events_len: usize,
}

#[repr(C)]
struct LibertasDeviceSubscribeReqRaw {
    device: LibertasDevice,
    cluster_subs: *const LibertasClusterSubscribeReqRaw,
    cluster_subs_len: usize,
    event_min: u64,
}

#[repr(C)]
struct LibertasClusterReadReqRaw {
    cluster: u32,
    attributes: *const u32,
    attributes_len: usize,
    events: *const u32,
    events_len: usize,
}

impl LibertasDeviceSubscribeReqRaw {
    // holder has guaranteed capacity.
    fn new(req: &LibertasDeviceSubscribeReq, holder: &mut Vec<Vec<LibertasClusterSubscribeReqRaw>>) -> Self {
        let mut clusters: Vec<LibertasClusterSubscribeReqRaw> = Vec::with_capacity(req.cluster_subs.len());
        for cur in &req.cluster_subs {
            clusters.push(LibertasClusterSubscribeReqRaw::new(cur));
        }
        holder.push(clusters);      // clusters moved
        if let Some(clusters_ref) =  holder.last() {
            Self {
                device: req.device,
                cluster_subs: clusters_ref.as_ptr(),
                cluster_subs_len: clusters_ref.len(),
                event_min: req.event_min.unwrap_or(0),
            }
        } else {
            unreachable!();
        }
    }
}

impl LibertasClusterSubscribeReqRaw {
    fn new(req: &LibertasClusterSubscribeReq) -> Self {
        Self {
            cluster: req.cluster,
            min_interval: req.min_interval,
            max_interval: req.max_interval,
            attributes: req.attributes.as_ptr(),
            attributes_len: req.attributes.len(),
            events:  req.events.as_ptr(),
            events_len: req.events.len(),
        }
    }
}

impl LibertasClusterEventSubscription {
    /// Creates a new cluster event subscription
    /// 
    /// # Arguments
    /// * `event_id` - The ID of the event to subscribe to
    /// * `urgent` - Whether this event should be treated as urgent
    pub fn new(event_id: u32, urgent: bool) -> Self {
        Self {
            event_id: event_id,
            urgent: urgent,
        }
    }
}

/// Request to subscribe to cluster attributes and events
/// 
/// Defines subscription parameters for a specific cluster, including
/// attribute IDs, event subscriptions, and polling intervals.
pub struct LibertasClusterSubscribeReq {
    /// Cluster identifier
    pub cluster: u32,
    /// Minimum polling interval in seconds
    pub min_interval: u16,
    /// Maximum polling interval in seconds
    pub max_interval: u16,
    /// List of attribute IDs to subscribe to
    pub attributes: Vec<u32>,
    /// List of events to subscribe to
    pub events: Vec<LibertasClusterEventSubscription>,
}

impl LibertasClusterSubscribeReq {
    /// Creates a new cluster subscription request
    /// 
    /// # Arguments
    /// * `cluster` - The cluster ID to subscribe to
    /// * `min_interval` - Minimum polling interval in seconds
    /// * `max_interval` - Maximum polling interval in seconds
    pub fn new(cluster: u32, min_interval: u16, max_interval: u16) -> Self {
        Self {
            cluster: cluster,
            min_interval: min_interval,
            max_interval: max_interval,
            attributes: Vec::new(),
            events: Vec::new(),
        }
    }
}

/// Request to subscribe to device cluster data and events
/// 
/// Allows subscribing to multiple clusters within a device with
/// specific attributes and events of interest.
pub struct LibertasDeviceSubscribeReq {
    /// Target device ID
    pub device: LibertasDevice,
    /// List of cluster subscription requests for this device
    pub cluster_subs: Vec<LibertasClusterSubscribeReq>,
    /// Minimum event timestamp to retrieve (optional)
    pub event_min: Option<u64>,
}

impl LibertasDeviceSubscribeReq {
    /// Creates a new device subscription request
    /// 
    /// # Arguments
    /// * `device` - The device ID to subscribe to
    pub fn new(device: LibertasDevice) -> Self {
        Self {
            device: device,
            cluster_subs: Vec::new(),
            event_min: None,
        }
    }
}

/// Request to read cluster attributes and events
/// 
/// Specifies which attributes and events to read from a specific cluster.
pub struct LibertasClusterReadReq {
    /// Cluster identifier
    pub cluster: u32,
    /// List of attribute IDs to read
    pub attributes: Vec<u32>,
    /// List of event IDs to read
    pub events: Vec<u32>,
}

impl LibertasClusterReadReq {
    /// Creates a new cluster read request
    /// 
    /// # Arguments
    /// * `cluster` - The cluster ID to read from
    pub fn new(cluster: u32) -> Self {
        Self {
            cluster: cluster,
            attributes: Vec::new(),
            events: Vec::new(),
        }
    }
}

/// Sends an invoke command to a device
/// 
/// Sends a command to a device and returns a transaction ID for tracking the response.
/// The device will invoke the specified command with the provided data.
/// 
/// # Arguments
/// * `device` - Target device ID
/// * `data` - A Matter CommandDataIB encoded byte array containing the command to invoke and its arguments. Note fields such as EndpointID shall not be specified.
/// 
/// # Returns
/// Transaction ID that can be used to correlate responses from the device
/// 
/// # Example
/// ```
/// let mut buf = LibertasUninitStackbuf::new();
/// let mut wb = WriteBuf::new(buf.as_mut_slice());
/// wb.start_list(&TLVTag::Context(FIELD_COMMAND_PATH)).unwrap();
/// wb.u16(&TLVTag::Context(FIELD_COMMAND_PATH_CLUSTER), clusterId).unwrap();
/// wb.u32(&TLVTag::Context(FIELD_COMMAND_PATH_CMD), commandId ).unwrap();
/// // Add command fields as a Matter struct here
/// wb.end_container().unwrap();
/// libertas_device_invoke_req(light, wb.as_slice());
/// ```
#[inline(always)]
pub fn libertas_device_invoke_req(device: LibertasDevice, data: &[u8]) -> u32 {
    libertas_device_send_request(device, OpCode::InvokeRequest as u8, data)
}

/// Sends a read request to a device
/// 
/// Requests the values of specific attributes and events from a device.
/// Returns a transaction ID for tracking the response.
/// 
/// # Arguments
/// * `device` - Target device ID
/// * `data` - List of cluster read requests specifying what to read
/// 
/// # Returns
/// Transaction ID that can be used to correlate responses from the device
/// 
pub fn libertas_device_read_req(device: LibertasDevice, data: &[LibertasClusterReadReq]) -> u32 {
    unsafe {
        let mut raw_list: Vec<LibertasClusterReadReqRaw> = Vec::with_capacity(data.len());
        for cur in data {
            raw_list.push(
                LibertasClusterReadReqRaw {
                    cluster: cur.cluster,
                    attributes: cur.attributes.as_ptr(),
                    attributes_len: cur.attributes.len(),
                    events: cur.events.as_ptr(),
                    events_len: cur.events.len(),
                });
        }
        let data = core::slice::from_raw_parts(
                raw_list.as_ptr() as *const u8,
                raw_list.len() * core::mem::size_of::<LibertasClusterReadReqRaw>(),
            );
        libertas_device_send_request(device, OpCode::ReadRequest as u8, data)
    }    
}


/// Sends a writerequest to a device
/// 
/// Sends write request to a device and returns a transaction ID for tracking the response.
/// The device will process the write request with the provided data.
/// 
/// # Arguments
/// * `device` - Target device ID
/// * `data` - Matter encoded binary blob containing an array of AttributeDataIB. Only Cluster and Attribute values
/// shall appear in the AttributePathIB. Note ommission of cluster ID shall be interpreted as though EnableTagCompression is on thus
/// will be filled with the last such value in the array.
/// 
/// # Returns
/// Transaction ID that can be used to correlate responses from the device.
/// 
#[inline(always)]
pub fn libertas_device_write_req(device: LibertasDevice, data: &[u8]) -> u32 {
    libertas_device_send_request(device, OpCode::WriteRequest as u8, data)
}

/// Subscribes to device attributes and events
/// 
/// Registers subscriptions to receive updates about specific device attributes
/// and events. The system will notify the application when subscribed data changes.
/// 
/// # Arguments
/// * `device_subscriptions` - List of device subscription requests
/// 
pub fn libertas_app_subscribe_req(device_subscriptions: &[LibertasDeviceSubscribeReq]) {
    unsafe {
        let mut device_list: Vec<LibertasDeviceSubscribeReqRaw> = Vec::with_capacity(device_subscriptions.len());
        let mut device_clusters: Vec<Vec<LibertasClusterSubscribeReqRaw>> = Vec::with_capacity(device_subscriptions.len());
        for cur in device_subscriptions {
            device_list.push(LibertasDeviceSubscribeReqRaw::new(cur, &mut device_clusters));
        }
        let data = core::slice::from_raw_parts(
                device_list.as_ptr() as *const u8,
                device_list.len() * core::mem::size_of::<LibertasDeviceSubscribeReqRaw>(),
            );
        libertas_device_send_request(0, OpCode::SubscribeRequest as u8, data);
    }
}

/// Sends an invoke response from a virtual device
/// 
/// Responds to an invoke request directed at a virtual device implementation.
/// 
/// # Arguments
/// * `device` - Virtual device ID
/// * `seq` - Sequence/transaction ID from the request
/// * `data` - A Matter encoded InvokeResponseIB structure. The CommandPathIB shall only include Cluster ID and Command ID.
/// 
#[inline(always)]
pub fn libertas_virtual_device_invoke_rsp(device: LibertasDevice, trans_id: u32, data: &[u8]) {
    libertas_device_send_response(device, OpCode::InvokeResponse as u8, data, trans_id);
}

/// Sends a write response from a virtual device
/// 
/// Responds to a write request directed at a virtual device implementation.
/// 
/// # Arguments
/// * `device` - Virtual device ID
/// * `seq` - Sequence/transaction ID from the request
/// * `data` - A Matter encoded array of AttributeStatusIB. Only Cluster ID and Attribute ID shall 
/// be filled in the AttributePathIB.
/// 
#[inline(always)]
pub fn libertas_virtual_device_write_rsp(device: LibertasDevice, trans_id: u32, data: &[u8]) {
    libertas_device_send_response(device, OpCode::WriteResponse as u8, data, trans_id);
}

/// Sends a status response from a virtual device
/// 
/// Responds with a status code to a request directed at a virtual device implementation.
/// 
/// # Arguments
/// * `device` - Virtual device ID
/// * `seq` - Sequence/transaction ID from the request
/// * `status` - Status code (0 = success, non-zero = error)
/// 
#[inline(always)]
pub fn libertas_virtual_device_status_rsp(device: LibertasDevice, trans_id: u32, status: IMStatusCode) {
    libertas_device_send_response(device,  OpCode::StatusResponse as u8, &[status as u8], trans_id);
}
