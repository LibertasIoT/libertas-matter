// Copyright (c) 2026 Smartonlabs Inc.
// SPDX-License-Identifier: MIT

//! Auto-generated Matter schema constants and ID catalogs.
#![no_std]
#![forbid(unsafe_code)]
#![allow(
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    clippy::module_inception
)]
#![deny(unreachable_pub)]
pub mod attributes;
pub mod clusters;
pub mod commands;
pub mod constants;
pub mod definitions;
pub mod device_types;
pub mod events;
pub mod features;
pub mod fields;

#[cfg(test)]
mod tests {
    use super::{attributes, commands, events};

    #[test]
    fn generated_id_catalogs_include_cluster_entries() {
        assert!(
            attributes::ALL
                .iter()
                .any(|(cluster, ids)| *cluster == "OnOff"
                    && ids.iter().any(|(name, _)| *name == "OnOff"))
        );
        assert!(
            commands::ALL
                .iter()
                .any(|(cluster, ids)| *cluster == "OnOff"
                    && ids.iter().any(|(name, _)| *name == "Toggle"))
        );
        assert!(events::ALL.iter().any(|(cluster, ids)| *cluster == "Switch"
            && ids.iter().any(|(name, _)| *name == "InitialPress")));
    }
}
