<!-- Copyright (c) 2026 Smartonlabs Inc. SPDX-License-Identifier: MIT -->

# libertas-matter

`libertas-matter` is the small Matter wire runtime used by applications hosted
by Libertas. The host daemon owns
commissioning, sessions, transport, endpoints, and device lifecycle. This
workspace provides only:

- a borrowed, allocation-free Matter TLV reader;
- direct transactional writers for fixed slices and
  `libertas::InlineByteBuffer`;
- owned decoding and the Libertas host bridge behind the `alloc` feature;
- bounded, zero-copy typed read, write, change, and app-wide subscription
  batches;
- derives that emit direct writer calls;
- generated Matter definitions and typed logical-device operations.

The crate is `no_std`; its default `alloc` feature enables generated owned
payloads and the runtime bridge.

## Workspace

- `libertas-matter/` — TLV codec, Libertas frame codec, typed bridge, and
  conformance vectors.
- `libertas-matter-macros/` — direct `ToTLV` and `FromTLV` derives plus
  generated-definition bindings.
- `libertas-matter-consts/` — generated Matter identifiers, catalogs, and
  schema definitions.

Libertas frame paths deliberately contain a cluster ID and an attribute,
command, or event ID without an endpoint. A Libertas logical device already
represents the host-routed endpoint.

## Status contract

Matter client results are a raw `u32`: bits 0-7 contain the Interaction Model
status, bits 8-15 contain the optional cluster status, and bits 16-31 contain a
Libertas Hub status. Zero is success. `frame::STATUS_SUPERSEDED`
(`0x0001_0000`) rejects a queued command that was replaced, or a retained
attribute write whose value differs from what was finally written.

Pending commands are last-command-wins per logical-device endpoint and cluster
to reduce device traffic. Only the newest request/reference per source is
retained, including the survivor: a newer surviving request replaces that
source's older displaced reference, which receives no separate response.
A burst from one peer keeps only its newest queued command; older queued
references are discarded without acknowledgement. A command already sent
remains owned by its active interaction.
A retained displaced request's nonzero completion is delayed until the surviving interaction
finishes. Every retained displaced request receives `STATUS_SUPERSEDED`;
only the surviving command receives its own success or error result.
Identical commands and the retained first `A` in an `A -> B -> A`
chain are still rejected because they were replaced.
Write supersession compares each requested value with the value finally written
by the pooled Matter interaction, with real errors taking precedence. It is
attribute-specific, so one response may mix success, `STATUS_SUPERSEDED`, and
actual Matter errors.

Virtual devices may issue only standard Matter statuses. Their response type is
`frame::StandardStatus` (`u16`). In the private Rust/Hub TLV frame, a status
structure contains exactly one context-0 `u32`; it never contains Matter's
separate context-1 cluster-status field.

## Example

```rust,ignore
use libertas_matter::{
    MatterDevice,
    definitions::OnOff::{
        attributes::{OnOff, OnTime},
        commands::Toggle,
    },
};

let light = MatterDevice::new(logical_device_id);
let read_transaction = light.read_attribute::<OnOff>()?;
let write_transaction = light.write_attribute(&OnTime(50))?;
let invoke_transaction = light.invoke(&Toggle {})?;
```

## Bounded batch operations

Batch storage is selected by the application with const generics. Attribute
and event IDs remain in caller-owned arrays and the native bridge borrows them
directly, so building or sending a batch does not allocate or copy a second
request.

```rust,ignore
use libertas_matter::{
    MatterDeviceSubscription, MatterReadCluster, MatterSubscriptionBatch,
    MatterSubscriptionCluster,
    tlv::SliceWriter,
};

// One typed read containing two attributes from the same logical device.
let mut read = MatterReadCluster::<2, 0>::for_attribute::<OnOff>();
read.add_attribute::<OnOff>()?.add_attribute::<OnTime>()?;
let read_requests = [read.request()?];
let read_transaction = light.read_batch(&read_requests)?;

// Heterogeneous values stream directly into an exactly sized caller buffer.
let mut bytes = [0_u8; 96];
let mut writer = SliceWriter::new(&mut bytes);
let mut write = light.write_batch(&mut writer)?;
write.attribute(&OnOff(true))?.attribute(&OnTime(50))?;
let write_transaction = write.send()?;

// Collect every device first, then replace the App task's complete subscription
// set with one batch send.
let mut light_subscription =
    MatterSubscriptionCluster::<2, 0>::for_attribute::<OnOff>(1, 60);
light_subscription
    .add_attribute::<OnOff>()?
    .add_attribute::<OnTime>()?;
let light_clusters = [light_subscription.request()?];
let kitchen_light = MatterDevice::new(kitchen_logical_device_id);
let devices = [
    MatterDeviceSubscription::new(light, &light_clusters)?,
    MatterDeviceSubscription::new(kitchen_light, &light_clusters)?,
];
let subscription_transaction = MatterSubscriptionBatch::new(&devices)?.send();
```

Matter subscriptions are task-wide replacement snapshots. `libertas-matter`
exposes no additive or per-device subscription send: every send must use one
`MatterSubscriptionBatch` containing the complete desired device list. A later
batch invalidates and replaces the task's earlier batch. Device IDs must be
unique within the batch, and cluster IDs must be unique within each device, so
the current subscription set is unambiguous and deterministic. Sending
`MatterSubscriptionBatch::new(&[])?.send()` clears the task's subscriptions.

Each stored attribute or read-event ID costs four bytes; each subscription
event costs eight bytes including its urgency flag. Builders return
`Error::NoSpace` at their configured capacity. Dropping an unfinished write
batch rolls its caller-owned buffer back to empty.

## Validation

The checked-in Rust tests contain literal, independently authored vectors for
every supported Matter TLV element type and every Libertas request or response
frame. Expected bytes are never generated by the Rust encoder under test.

```sh
cargo test --workspace
cargo check --workspace --all-targets --all-features
cargo check -p libertas-matter --no-default-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## License

Copyright (c) 2026 Smartonlabs Inc. Licensed under the
[MIT License](LICENSE).
