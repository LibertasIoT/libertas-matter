// Copyright (c) 2026 Smartonlabs Inc.
// SPDX-License-Identifier: MIT

//! Frozen multi-path frames and bounded batch storage tests.

use core::mem::size_of;

use libertas_matter::{
    MatterAttribute, MatterClusterSubscription, MatterDevice, MatterDeviceSubscription,
    MatterEvent, MatterReadCluster, MatterReadRequest, MatterSubscriptionBatch,
    MatterSubscriptionCluster, decode_write_response, error::Error, tlv::SliceWriter,
};

const CLUSTER: u32 = 0x1234;

#[derive(Clone, Debug, Eq, PartialEq, libertas_matter::FromTLV, libertas_matter::ToTLV)]
struct Enabled {
    #[tagval(1)]
    enabled: bool,
}

impl MatterAttribute for Enabled {
    const CLUSTER_ID: u32 = CLUSTER;
    const ID: u32 = 0x5678;
    const READABLE: bool = true;
    const WRITABLE: bool = true;
}

#[derive(Clone, Debug, Eq, PartialEq, libertas_matter::FromTLV, libertas_matter::ToTLV)]
struct Level {
    #[tagval(1)]
    level: u8,
}

impl MatterAttribute for Level {
    const CLUSTER_ID: u32 = CLUSTER;
    const ID: u32 = 0x5679;
    const READABLE: bool = true;
    const WRITABLE: bool = true;
}

#[derive(Clone, Debug, Eq, PartialEq, libertas_matter::FromTLV, libertas_matter::ToTLV)]
struct ReadOnly(bool);

impl MatterAttribute for ReadOnly {
    const CLUSTER_ID: u32 = CLUSTER;
    const ID: u32 = 0x567a;
    const READABLE: bool = true;
    const WRITABLE: bool = false;
}

#[derive(Clone, Debug, Eq, PartialEq, libertas_matter::FromTLV, libertas_matter::ToTLV)]
struct OtherCluster(bool);

impl MatterAttribute for OtherCluster {
    const CLUSTER_ID: u32 = 0x9999;
    const ID: u32 = 1;
    const READABLE: bool = true;
    const WRITABLE: bool = true;
}

#[derive(Clone, Debug, Eq, PartialEq, libertas_matter::FromTLV, libertas_matter::ToTLV)]
struct Changed {
    #[tagval(1)]
    reason: u8,
}

impl MatterEvent for Changed {
    const CLUSTER_ID: u32 = CLUSTER;
    const ID: u32 = 0x1234;
}

const BATCH_WRITE: &[u8] = &[
    0x16, 0x15, 0x37, 0x01, 0x25, 0x03, 0x34, 0x12, 0x25, 0x04, 0x78, 0x56, 0x18, 0x35, 0x02, 0x29,
    0x01, 0x18, 0x18, 0x15, 0x37, 0x01, 0x25, 0x03, 0x34, 0x12, 0x25, 0x04, 0x79, 0x56, 0x18, 0x35,
    0x02, 0x24, 0x01, 0x07, 0x18, 0x18, 0x18,
];

const BATCH_WRITE_STATUS: &[u8] = &[
    0x16, 0x15, 0x37, 0x00, 0x25, 0x03, 0x34, 0x12, 0x25, 0x04, 0x78, 0x56, 0x18, 0x35, 0x01, 0x26,
    0x00, 0x02, 0x01, 0x00, 0x00, 0x18, 0x18, 0x15, 0x37, 0x00, 0x25, 0x03, 0x34, 0x12, 0x25, 0x04,
    0x79, 0x56, 0x18, 0x35, 0x01, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x18,
];

#[test]
fn typed_batch_write_matches_the_frozen_frame() {
    let mut storage = [0_u8; BATCH_WRITE.len()];
    let mut writer = SliceWriter::new(&mut storage);

    let mut batch = MatterDevice::new(7).write_batch(&mut writer).unwrap();
    batch.attribute(&Enabled { enabled: true }).unwrap();
    batch.attribute(&Level { level: 7 }).unwrap();
    assert_eq!(batch.len(), 2);
    batch.finish_encoding().unwrap();

    assert_eq!(writer.as_slice(), BATCH_WRITE);
}

#[test]
fn batch_write_decodes_each_typed_status_without_allocating() {
    assert_eq!(
        decode_write_response::<Enabled>(BATCH_WRITE_STATUS).unwrap(),
        0x0000_0102
    );
    assert_eq!(
        decode_write_response::<Level>(BATCH_WRITE_STATUS).unwrap(),
        0
    );
}

#[test]
fn unfinished_and_failed_batches_roll_back_the_caller_buffer() {
    let mut storage = [0_u8; 64];
    let mut writer = SliceWriter::new(&mut storage);
    {
        let mut batch = MatterDevice::new(7).write_batch(&mut writer).unwrap();
        batch.attribute(&Enabled { enabled: true }).unwrap();
        assert_eq!(
            batch.attribute(&ReadOnly(false)).map(|_| ()),
            Err(Error::UnsupportedAccess)
        );
    }
    assert!(writer.is_empty());

    let mut tiny_storage = [0_u8; 4];
    let mut tiny = SliceWriter::new(&mut tiny_storage);
    {
        let mut batch = MatterDevice::new(7).write_batch(&mut tiny).unwrap();
        assert_eq!(
            batch.attribute(&Enabled { enabled: true }).map(|_| ()),
            Err(Error::NoSpace)
        );
    }
    assert!(tiny.is_empty());
}

#[test]
fn read_clusters_are_typed_bounded_and_compact() {
    let mut cluster = MatterReadCluster::<2, 1>::for_attribute::<Enabled>();
    cluster
        .add_attribute::<Enabled>()
        .unwrap()
        .add_attribute::<Level>()
        .unwrap()
        .add_event::<Changed>()
        .unwrap();
    assert_eq!(cluster.attributes(), &[Enabled::ID, Level::ID]);
    assert_eq!(cluster.events(), &[Changed::ID]);
    assert!(cluster.request().is_ok());

    assert_eq!(
        cluster.add_attribute::<Enabled>().map(|_| ()),
        Err(Error::NoSpace)
    );
    assert_eq!(
        MatterReadCluster::<1, 0>::for_attribute::<Enabled>()
            .add_attribute::<OtherCluster>()
            .map(|_| ()),
        Err(Error::PathMismatch)
    );

    assert_eq!(size_of::<MatterReadCluster<0, 0>>(), 8);
    assert_eq!(size_of::<MatterReadCluster<4, 2>>(), 32);
}

#[test]
fn one_subscription_batch_borrows_all_devices_without_copies() {
    let mut duplicate_paths = MatterSubscriptionCluster::<2, 2>::for_attribute::<Enabled>(1, 60);
    duplicate_paths.add_attribute::<Enabled>().unwrap();
    assert_eq!(
        duplicate_paths.add_attribute::<Enabled>().map(|_| ()),
        Err(Error::Constraint)
    );
    duplicate_paths.add_event::<Changed>(true).unwrap();
    assert_eq!(
        duplicate_paths.add_event::<Changed>(false).map(|_| ()),
        Err(Error::Constraint)
    );

    let mut first_cluster = MatterSubscriptionCluster::<2, 1>::for_attribute::<Enabled>(1, 60);
    first_cluster
        .add_attribute::<Enabled>()
        .unwrap()
        .add_attribute::<Level>()
        .unwrap()
        .add_event::<Changed>(true)
        .unwrap();
    assert_eq!(first_cluster.attributes(), &[Enabled::ID, Level::ID]);
    assert_eq!(first_cluster.events()[0].event_id(), Changed::ID);
    assert!(first_cluster.events()[0].urgent());

    let mut second_cluster = MatterSubscriptionCluster::<1, 0>::for_attribute::<Enabled>(5, 300);
    second_cluster.add_attribute::<Enabled>().unwrap();

    let first_clusters = [first_cluster.request().unwrap()];
    let second_clusters = [second_cluster.request().unwrap()];
    let duplicate_clusters = [first_clusters[0], first_clusters[0]];
    assert!(matches!(
        MatterDeviceSubscription::new(MatterDevice::new(10), &duplicate_clusters),
        Err(Error::Constraint)
    ));
    assert!(matches!(
        MatterDeviceSubscription::new(MatterDevice::new(0), &first_clusters),
        Err(Error::Constraint)
    ));
    let devices = [
        MatterDeviceSubscription::new(MatterDevice::new(10), &first_clusters).unwrap(),
        MatterDeviceSubscription::new(MatterDevice::new(11), &second_clusters)
            .unwrap()
            .with_event_min(42),
    ];
    let batch = MatterSubscriptionBatch::new(&devices).unwrap();
    assert_eq!(batch.len(), 2);
    assert_eq!(devices[1].event_min(), 42);
    let duplicate_devices = [devices[0], devices[0]];
    assert!(matches!(
        MatterSubscriptionBatch::new(&duplicate_devices),
        Err(Error::Constraint)
    ));

    let mut invalid = MatterSubscriptionCluster::<1, 0>::for_attribute::<Enabled>(61, 60);
    invalid.add_attribute::<Enabled>().unwrap();
    assert!(matches!(invalid.request(), Err(Error::Constraint)));
    assert!(matches!(
        MatterSubscriptionBatch::new(&[]),
        Err(Error::Constraint)
    ));

    assert_eq!(size_of::<MatterSubscriptionCluster<0, 0>>(), 12);
    assert_eq!(size_of::<MatterSubscriptionCluster<4, 2>>(), 44);
    if cfg!(target_pointer_width = "64") {
        assert_eq!(size_of::<MatterReadRequest<'_>>(), 40);
        assert_eq!(size_of::<MatterClusterSubscription<'_>>(), 40);
        assert_eq!(size_of::<MatterDeviceSubscription<'_>>(), 32);
    }
}
