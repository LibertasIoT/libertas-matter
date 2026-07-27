<!-- Copyright (c) 2026 Smartonlabs Inc. SPDX-License-Identifier: MIT -->

# libertas-matter

`no_std` Matter TLV support and typed Matter operations for Libertas logical
devices. Owned decoding and the Libertas host bridge are available with the
default `alloc` feature. Const-generic read and subscription builders use
caller-selected fixed capacities, batch writes stream directly into a
caller-owned buffer, and the app-wide subscription is sent once for all
devices.
