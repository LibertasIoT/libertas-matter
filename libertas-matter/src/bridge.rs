// Copyright (c) 2026 Smartonlabs Inc.
// SPDX-License-Identifier: MIT

//! Native Libertas ABI adaptation.

use libertas::{
    __libertas_device_send_raw_req, libertas_device_send_request, libertas_device_send_response,
};

use crate::{
    batch::{MatterDeviceSubscription, MatterReadRequest},
    frame::{Operation, PROTOCOL_MATTER},
    LibertasDevice, LibertasTransId,
};

pub(crate) fn send_tlv_request(
    device: LibertasDevice,
    operation: Operation,
    encoded: &[u8],
) -> LibertasTransId {
    libertas_device_send_request(PROTOCOL_MATTER, device, operation as u8, encoded)
}

pub(crate) fn send_response(
    device: LibertasDevice,
    transaction_id: LibertasTransId,
    peer: libertas::LibertasPeer,
    operation: Operation,
    encoded: &[u8],
) {
    libertas_device_send_response(
        PROTOCOL_MATTER,
        device,
        operation as u8,
        encoded,
        transaction_id,
        peer,
    );
}

pub(crate) fn send_read(
    device: LibertasDevice,
    clusters: &[MatterReadRequest<'_>],
) -> LibertasTransId {
    send_native_request(device, Operation::ReadRequest, 0, clusters)
}

pub(crate) fn send_changed(
    device: LibertasDevice,
    peer: libertas::LibertasPeer,
    clusters: &[MatterReadRequest<'_>],
) -> LibertasTransId {
    send_native_request(device, Operation::AttributeChanged, peer, clusters)
}

pub(crate) fn send_subscribe(devices: &[MatterDeviceSubscription<'_>]) -> LibertasTransId {
    // SubscribeRequest is never a per-device operation. Device zero is the
    // stable ABI sentinel telling libertasd that `devices` is the task's one
    // complete replacement snapshot; the host independently validates every
    // embedded device and cluster before replacing the prior snapshot.
    // An empty slice is sent with zero bytes to clear that snapshot; the host
    // must not dereference the empty slice's pointer.
    const APP_SUBSCRIPTION_BATCH_DEVICE: LibertasDevice = 0;
    send_native_request(
        APP_SUBSCRIPTION_BATCH_DEVICE,
        Operation::SubscribeRequest,
        0,
        devices,
    )
}

fn send_native_request<T>(
    device: LibertasDevice,
    operation: Operation,
    peer: libertas::LibertasPeer,
    values: &[T],
) -> LibertasTransId {
    let length = core::mem::size_of_val(values);
    __libertas_device_send_raw_req(
        PROTOCOL_MATTER,
        device,
        operation as u8,
        peer,
        values.as_ptr().cast(),
        length,
    )
}

#[cfg(all(test, target_pointer_width = "64"))]
mod abi_vectors {
    use core::mem::{align_of, offset_of, size_of};

    use crate::batch::{
        MatterClusterSubscription, MatterDeviceSubscription, MatterEventSubscription,
        MatterReadRequest,
    };

    // Frozen against the native x86_64 host ABI contract.
    #[test]
    fn native_frame_layouts_match_host() {
        assert_eq!(size_of::<MatterEventSubscription>(), 8);
        assert_eq!(align_of::<MatterEventSubscription>(), 4);
        assert_eq!(offset_of!(MatterEventSubscription, event_id), 0);
        assert_eq!(offset_of!(MatterEventSubscription, urgent), 4);

        assert_eq!(size_of::<MatterClusterSubscription<'_>>(), 40);
        assert_eq!(align_of::<MatterClusterSubscription<'_>>(), 8);
        assert_eq!(offset_of!(MatterClusterSubscription<'_>, cluster_id), 0);
        assert_eq!(offset_of!(MatterClusterSubscription<'_>, min_interval), 4);
        assert_eq!(offset_of!(MatterClusterSubscription<'_>, max_interval), 6);
        assert_eq!(offset_of!(MatterClusterSubscription<'_>, attributes), 8);
        assert_eq!(
            offset_of!(MatterClusterSubscription<'_>, attributes_len),
            16
        );
        assert_eq!(offset_of!(MatterClusterSubscription<'_>, events), 24);
        assert_eq!(offset_of!(MatterClusterSubscription<'_>, events_len), 32);

        assert_eq!(size_of::<MatterDeviceSubscription<'_>>(), 32);
        assert_eq!(align_of::<MatterDeviceSubscription<'_>>(), 8);
        assert_eq!(offset_of!(MatterDeviceSubscription<'_>, device), 0);
        assert_eq!(offset_of!(MatterDeviceSubscription<'_>, clusters), 8);
        assert_eq!(offset_of!(MatterDeviceSubscription<'_>, clusters_len), 16);
        assert_eq!(offset_of!(MatterDeviceSubscription<'_>, event_min), 24);

        assert_eq!(size_of::<MatterReadRequest<'_>>(), 40);
        assert_eq!(align_of::<MatterReadRequest<'_>>(), 8);
        assert_eq!(offset_of!(MatterReadRequest<'_>, cluster_id), 0);
        assert_eq!(offset_of!(MatterReadRequest<'_>, attributes), 8);
        assert_eq!(offset_of!(MatterReadRequest<'_>, attributes_len), 16);
        assert_eq!(offset_of!(MatterReadRequest<'_>, events), 24);
        assert_eq!(offset_of!(MatterReadRequest<'_>, events_len), 32);
    }
}
