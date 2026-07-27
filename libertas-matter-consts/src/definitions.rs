// Copyright (c) 2026 Smartonlabs Inc.
// SPDX-License-Identifier: MIT

//! Owned Rust definitions for the generated Matter schema.
#[macro_export]
macro_rules! matter_definitions {
    ($matter:ident) => {
pub mod ContentControl {
    pub const ID: u32 = 0x050F;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusCodeEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl StatusCodeEnum {
            pub const InvalidPINCode: Self = Self(0x2);
            pub const InvalidRating: Self = Self(0x3);
            pub const InvalidChannel: Self = Self(0x4);
            pub const ChannelAlreadyExist: Self = Self(0x5);
            pub const ChannelNotExist: Self = Self(0x6);
            pub const UnidentifiableApplication: Self = Self(0x7);
            pub const ApplicationAlreadyExist: Self = Self(0x8);
            pub const ApplicationNotExist: Self = Self(0x9);
            pub const TimeWindowAlreadyExist: Self = Self(0xA);
            pub const TimeWindowNotExist: Self = Self(0xB);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DayOfWeekBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl DayOfWeekBitmap {
            pub const Sunday: Self = Self(0x1);
            pub const Monday: Self = Self(0x2);
            pub const Tuesday: Self = Self(0x4);
            pub const Wednesday: Self = Self(0x8);
            pub const Thursday: Self = Self(0x10);
            pub const Friday: Self = Self(0x20);
            pub const Saturday: Self = Self(0x40);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AppInfoStruct {
            #[tagval(0)]
            pub CatalogVendorID: u16,
            #[tagval(1)]
            pub ApplicationID: $matter::tlv::MatterString,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BlockChannelStruct {
            #[tagval(0)]
            pub BlockChannelIndex: $matter::tlv::Nullable<u16>,
            #[tagval(1)]
            pub MajorNumber: u16,
            #[tagval(2)]
            pub MinorNumber: u16,
            #[tagval(3)]
            pub Identifier: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RatingNameStruct {
            #[tagval(0)]
            pub RatingName: $matter::tlv::MatterString,
            #[tagval(1)]
            pub RatingNameDesc: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TimePeriodStruct {
            #[tagval(0)]
            pub StartHour: u8,
            #[tagval(1)]
            pub StartMinute: u8,
            #[tagval(2)]
            pub EndHour: u8,
            #[tagval(3)]
            pub EndMinute: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TimeWindowStruct {
            #[tagval(0)]
            pub TimeWindowIndex: $matter::tlv::Nullable<u16>,
            #[tagval(1)]
            pub DayOfWeek: $matter::definitions::ContentControl::types::DayOfWeekBitmap,
            #[tagval(2)]
            pub TimePeriod: $matter::tlv::MatterList<$matter::definitions::ContentControl::types::TimePeriodStruct>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Enabled(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnDemandRatings(pub $matter::tlv::MatterList<$matter::definitions::ContentControl::types::RatingNameStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnDemandRatingThreshold(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ScheduledContentRatings(pub $matter::tlv::MatterList<$matter::definitions::ContentControl::types::RatingNameStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ScheduledContentRatingThreshold(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ScreenDailyTime(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemainingScreenTime(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BlockUnrated(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BlockChannelList(pub $matter::tlv::MatterList<$matter::definitions::ContentControl::types::BlockChannelStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BlockApplicationList(pub $matter::tlv::MatterList<$matter::definitions::ContentControl::types::AppInfoStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BlockContentTimeWindow(pub $matter::tlv::MatterList<$matter::definitions::ContentControl::types::TimeWindowStruct>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UpdatePIN {
            #[tagval(0)]
            pub OldPIN: $matter::tlv::MatterString,
            #[tagval(1)]
            pub NewPIN: $matter::tlv::MatterString,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1, response = ResetPINResponse, response_id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ResetPIN {
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ResetPINResponse {
            #[tagval(0)]
            pub PINCode: $matter::tlv::MatterString,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Enable {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Disable {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddBonusTime {
            #[tagval(0)]
            pub PINCode: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(1)]
            pub BonusTime: u32,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetScreenDailyTime {
            #[tagval(0)]
            pub ScreenTime: u32,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x7)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BlockUnratedContent {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x8)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UnblockUnratedContent {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x9)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetOnDemandRatingThreshold {
            #[tagval(0)]
            pub Rating: $matter::tlv::MatterString,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xA)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetScheduledContentRatingThreshold {
            #[tagval(0)]
            pub Rating: $matter::tlv::MatterString,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xB)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddBlockChannels {
            #[tagval(0)]
            pub Channels: $matter::tlv::MatterList<$matter::definitions::ContentControl::types::BlockChannelStruct>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xC)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveBlockChannels {
            #[tagval(0)]
            pub ChannelIndexes: $matter::tlv::MatterList<u16>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xD)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddBlockApplications {
            #[tagval(0)]
            pub Applications: $matter::tlv::MatterList<$matter::definitions::ContentControl::types::AppInfoStruct>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xE)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveBlockApplications {
            #[tagval(0)]
            pub Applications: $matter::tlv::MatterList<$matter::definitions::ContentControl::types::AppInfoStruct>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xF)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetBlockContentTimeWindow {
            #[tagval(0)]
            pub TimeWindow: $matter::definitions::ContentControl::types::TimeWindowStruct,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x10)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveBlockContentTimeWindow {
            #[tagval(0)]
            pub TimeWindowIndexes: $matter::tlv::MatterList<u16>,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemainingScreenTimeExpired {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnteringBlockContentTimeWindow {
        }
    }
}
pub mod MicrowaveOvenControl {
    pub const ID: u32 = 0x005F;
    pub mod types {
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CookTime(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxCookTime(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PowerSetting(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinPower(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxPower(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PowerStep(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedWatts(pub $matter::tlv::MatterList<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SelectedWattIndex(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WattRating(pub u16);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetCookingParameters {
            #[tagval(0)]
            pub CookMode: core::option::Option<u8>,
            #[tagval(1)]
            pub CookTime: core::option::Option<u32>,
            #[tagval(2)]
            pub PowerSetting: core::option::Option<u8>,
            #[tagval(3)]
            pub WattSettingIndex: core::option::Option<u8>,
            #[tagval(4)]
            pub StartAfterSetting: core::option::Option<bool>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddMoreTime {
            #[tagval(0)]
            pub TimeToAdd: u32,
        }
    }
    pub mod events {
    }
}
pub mod Switch {
    pub const ID: u32 = 0x003B;
    pub mod types {
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfPositions(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentPosition(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MultiPressMax(pub u8);
    }
    pub mod commands {
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SwitchLatched {
            #[tagval(0)]
            pub NewPosition: u8,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct InitialPress {
            #[tagval(0)]
            pub NewPosition: u8,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LongPress {
            #[tagval(0)]
            pub NewPosition: u8,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ShortRelease {
            #[tagval(0)]
            pub PreviousPosition: u8,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LongRelease {
            #[tagval(0)]
            pub PreviousPosition: u8,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MultiPressOngoing {
            #[tagval(0)]
            pub NewPosition: u8,
            #[tagval(1)]
            pub CurrentNumberOfPressesCounted: u8,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x6)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MultiPressComplete {
            #[tagval(0)]
            pub PreviousPosition: u8,
            #[tagval(1)]
            pub TotalNumberOfPressesCounted: u8,
        }
    }
}
pub mod UserLabel {
    pub const ID: u32 = 0x0041;
    pub mod types {
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LabelStruct {
            #[tagval(0)]
            pub Label: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Value: $matter::tlv::MatterString,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LabelList(pub $matter::tlv::MatterList<$matter::definitions::UserLabel::types::LabelStruct>);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod WaterHeaterManagement {
    pub const ID: u32 = 0x0094;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct BoostStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl BoostStateEnum {
            pub const Inactive: Self = Self(0x0);
            pub const Active: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct WaterHeaterHeatSourceBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl WaterHeaterHeatSourceBitmap {
            pub const ImmersionElement1: Self = Self(0x1);
            pub const ImmersionElement2: Self = Self(0x2);
            pub const HeatPump: Self = Self(0x4);
            pub const Boiler: Self = Self(0x8);
            pub const Other: Self = Self(0x10);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WaterHeaterBoostInfoStruct {
            #[tagval(0)]
            pub Duration: u32,
            #[tagval(1)]
            pub OneShot: core::option::Option<bool>,
            #[tagval(2)]
            pub EmergencyBoost: core::option::Option<bool>,
            #[tagval(3)]
            pub TemporarySetpoint: core::option::Option<i16>,
            #[tagval(4)]
            pub TargetPercentage: u8,
            #[tagval(5)]
            pub TargetReheat: core::option::Option<u8>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HeaterTypes(pub $matter::definitions::WaterHeaterManagement::types::WaterHeaterHeatSourceBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HeatDemand(pub $matter::definitions::WaterHeaterManagement::types::WaterHeaterHeatSourceBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TankVolume(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EstimatedHeatRequired(pub i64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TankPercentage(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BoostState(pub $matter::definitions::WaterHeaterManagement::types::BoostStateEnum);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Boost {
            #[tagval(0)]
            pub BoostInfo: $matter::definitions::WaterHeaterManagement::types::WaterHeaterBoostInfoStruct,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CancelBoost {
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BoostStarted {
            #[tagval(0)]
            pub BoostInfo: $matter::definitions::WaterHeaterManagement::types::WaterHeaterBoostInfoStruct,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BoostEnded {
        }
    }
}
pub mod EthernetNetworkDiagnostics {
    pub const ID: u32 = 0x0037;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct PHYRateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl PHYRateEnum {
            pub const Rate10M: Self = Self(0x0);
            pub const Rate100M: Self = Self(0x1);
            pub const Rate1G: Self = Self(0x2);
            pub const Rate2_5G: Self = Self(0x3);
            pub const Rate5G: Self = Self(0x4);
            pub const Rate10G: Self = Self(0x5);
            pub const Rate40G: Self = Self(0x6);
            pub const Rate100G: Self = Self(0x7);
            pub const Rate200G: Self = Self(0x8);
            pub const Rate400G: Self = Self(0x9);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PHYRate(pub $matter::tlv::Nullable<$matter::definitions::EthernetNetworkDiagnostics::types::PHYRateEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FullDuplex(pub $matter::tlv::Nullable<bool>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PacketRxCount(pub u64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PacketTxCount(pub u64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TxErrCount(pub u64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CollisionCount(pub u64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OverrunCount(pub u64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CarrierDetect(pub $matter::tlv::Nullable<bool>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TimeSinceReset(pub u64);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ResetCounts {
        }
    }
    pub mod events {
    }
}
pub mod ContentLauncher {
    pub const ID: u32 = 0x050A;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MetricTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MetricTypeEnum {
            pub const Pixels: Self = Self(0x0);
            pub const Percentage: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ParameterEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ParameterEnum {
            pub const Actor: Self = Self(0x0);
            pub const Channel: Self = Self(0x1);
            pub const Character: Self = Self(0x2);
            pub const Director: Self = Self(0x3);
            pub const Event: Self = Self(0x4);
            pub const Franchise: Self = Self(0x5);
            pub const Genre: Self = Self(0x6);
            pub const League: Self = Self(0x7);
            pub const Popularity: Self = Self(0x8);
            pub const Provider: Self = Self(0x9);
            pub const Sport: Self = Self(0xA);
            pub const SportsTeam: Self = Self(0xB);
            pub const Type: Self = Self(0xC);
            pub const Video: Self = Self(0xD);
            pub const Season: Self = Self(0xE);
            pub const Episode: Self = Self(0xF);
            pub const Any: Self = Self(0x10);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl StatusEnum {
            pub const Success: Self = Self(0x0);
            pub const URLNotAvailable: Self = Self(0x1);
            pub const AuthFailed: Self = Self(0x2);
            pub const TextTrackNotAvailable: Self = Self(0x3);
            pub const AudioTrackNotAvailable: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct SupportedProtocolsBitmap(pub u32);
        #[allow(non_upper_case_globals)]
        impl SupportedProtocolsBitmap {
            pub const DASH: Self = Self(0x1);
            pub const HLS: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AdditionalInfoStruct {
            #[tagval(0)]
            pub Name: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Value: $matter::tlv::MatterString,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BrandingInformationStruct {
            #[tagval(0)]
            pub ProviderName: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Background: core::option::Option<$matter::definitions::ContentLauncher::types::StyleInformationStruct>,
            #[tagval(2)]
            pub Logo: core::option::Option<$matter::definitions::ContentLauncher::types::StyleInformationStruct>,
            #[tagval(3)]
            pub ProgressBar: core::option::Option<$matter::definitions::ContentLauncher::types::StyleInformationStruct>,
            #[tagval(4)]
            pub Splash: core::option::Option<$matter::definitions::ContentLauncher::types::StyleInformationStruct>,
            #[tagval(5)]
            pub WaterMark: core::option::Option<$matter::definitions::ContentLauncher::types::StyleInformationStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ContentSearchStruct {
            #[tagval(0)]
            pub ParameterList: $matter::tlv::MatterList<$matter::definitions::ContentLauncher::types::ParameterStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DimensionStruct {
            #[tagval(0)]
            pub Width: f64,
            #[tagval(1)]
            pub Height: f64,
            #[tagval(2)]
            pub Metric: $matter::definitions::ContentLauncher::types::MetricTypeEnum,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ParameterStruct {
            #[tagval(0)]
            pub Type: $matter::definitions::ContentLauncher::types::ParameterEnum,
            #[tagval(1)]
            pub Value: $matter::tlv::MatterString,
            #[tagval(2)]
            pub ExternalIDList: core::option::Option<$matter::tlv::MatterList<$matter::definitions::ContentLauncher::types::AdditionalInfoStruct>>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PlaybackPreferencesStruct {
            #[tagval(0)]
            pub PlaybackPosition: core::option::Option<$matter::tlv::Nullable<u64>>,
            #[tagval(1)]
            pub TextTrack: core::option::Option<$matter::tlv::Nullable<$matter::definitions::ContentLauncher::types::TrackPreferenceStruct>>,
            #[tagval(2)]
            pub AudioTracks: core::option::Option<$matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::ContentLauncher::types::TrackPreferenceStruct>>>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StyleInformationStruct {
            #[tagval(0)]
            pub ImageURL: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(1)]
            pub Color: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub Size: core::option::Option<$matter::definitions::ContentLauncher::types::DimensionStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TrackPreferenceStruct {
            #[tagval(0)]
            pub LanguageCode: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Characteristics: core::option::Option<$matter::tlv::Nullable<$matter::tlv::MatterList<u8>>>,
            #[tagval(2)]
            pub AudioOutputIndex: core::option::Option<$matter::tlv::Nullable<u8>>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AcceptHeader(pub $matter::tlv::MatterList<$matter::tlv::MatterString>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedStreamingProtocols(pub $matter::definitions::ContentLauncher::types::SupportedProtocolsBitmap);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = LauncherResponse, response_id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LaunchContent {
            #[tagval(0)]
            pub Search: $matter::definitions::ContentLauncher::types::ContentSearchStruct,
            #[tagval(1)]
            pub AutoPlay: bool,
            #[tagval(2)]
            pub Data: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(3)]
            pub PlaybackPreferences: core::option::Option<$matter::definitions::ContentLauncher::types::PlaybackPreferencesStruct>,
            #[tagval(4)]
            pub UseCurrentContext: core::option::Option<bool>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1, response = LauncherResponse, response_id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LaunchURL {
            #[tagval(0)]
            pub ContentURL: $matter::tlv::MatterString,
            #[tagval(1)]
            pub DisplayString: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub BrandingInformation: core::option::Option<$matter::definitions::ContentLauncher::types::BrandingInformationStruct>,
            #[tagval(3)]
            pub PlaybackPreferences: core::option::Option<$matter::definitions::ContentLauncher::types::PlaybackPreferencesStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LauncherResponse {
            #[tagval(0)]
            pub Status: $matter::definitions::ContentLauncher::types::StatusEnum,
            #[tagval(1)]
            pub Data: core::option::Option<$matter::tlv::MatterString>,
        }
    }
    pub mod events {
    }
}
pub mod GeneralDiagnostics {
    pub const ID: u32 = 0x0033;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct BootReasonEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl BootReasonEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const PowerOnReboot: Self = Self(0x1);
            pub const BrownOutReset: Self = Self(0x2);
            pub const SoftwareWatchdogReset: Self = Self(0x3);
            pub const HardwareWatchdogReset: Self = Self(0x4);
            pub const SoftwareUpdateCompleted: Self = Self(0x5);
            pub const SoftwareReset: Self = Self(0x6);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct HardwareFaultEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl HardwareFaultEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const Radio: Self = Self(0x1);
            pub const Sensor: Self = Self(0x2);
            pub const ResettableOverTemp: Self = Self(0x3);
            pub const NonResettableOverTemp: Self = Self(0x4);
            pub const PowerSource: Self = Self(0x5);
            pub const VisualDisplayFault: Self = Self(0x6);
            pub const AudioOutputFault: Self = Self(0x7);
            pub const UserInterfaceFault: Self = Self(0x8);
            pub const NonVolatileMemoryError: Self = Self(0x9);
            pub const TamperDetected: Self = Self(0xA);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct InterfaceTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl InterfaceTypeEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const WiFi: Self = Self(0x1);
            pub const Ethernet: Self = Self(0x2);
            pub const Cellular: Self = Self(0x3);
            pub const Thread: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct NetworkFaultEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl NetworkFaultEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const HardwareFailure: Self = Self(0x1);
            pub const NetworkJammed: Self = Self(0x2);
            pub const ConnectionFailed: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct RadioFaultEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl RadioFaultEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const WiFiFault: Self = Self(0x1);
            pub const CellularFault: Self = Self(0x2);
            pub const ThreadFault: Self = Self(0x3);
            pub const NFCFault: Self = Self(0x4);
            pub const BLEFault: Self = Self(0x5);
            pub const EthernetFault: Self = Self(0x6);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NetworkInterface {
            #[tagval(0)]
            pub Name: $matter::tlv::MatterString,
            #[tagval(1)]
            pub IsOperational: bool,
            #[tagval(2)]
            pub OffPremiseServicesReachableIPv4: $matter::tlv::Nullable<bool>,
            #[tagval(3)]
            pub OffPremiseServicesReachableIPv6: $matter::tlv::Nullable<bool>,
            #[tagval(4)]
            pub HardwareAddress: $matter::tlv::MatterBytes,
            #[tagval(5)]
            pub IPv4Addresses: $matter::tlv::MatterList<$matter::tlv::MatterBytes>,
            #[tagval(6)]
            pub IPv6Addresses: $matter::tlv::MatterList<$matter::tlv::MatterBytes>,
            #[tagval(7)]
            pub Type: $matter::definitions::GeneralDiagnostics::types::InterfaceTypeEnum,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NetworkInterfaces(pub $matter::tlv::MatterList<$matter::definitions::GeneralDiagnostics::types::NetworkInterface>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RebootCount(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UpTime(pub u64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TotalOperationalHours(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BootReason(pub $matter::definitions::GeneralDiagnostics::types::BootReasonEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveHardwareFaults(pub $matter::tlv::MatterList<$matter::definitions::GeneralDiagnostics::types::HardwareFaultEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveRadioFaults(pub $matter::tlv::MatterList<$matter::definitions::GeneralDiagnostics::types::RadioFaultEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveNetworkFaults(pub $matter::tlv::MatterList<$matter::definitions::GeneralDiagnostics::types::NetworkFaultEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TestEventTriggersEnabled(pub bool);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TestEventTrigger {
            #[tagval(0)]
            pub EnableKey: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub EventTrigger: u64,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1, response = TimeSnapshotResponse, response_id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TimeSnapshot {
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TimeSnapshotResponse {
            #[tagval(0)]
            pub SystemTimeMs: u64,
            #[tagval(1)]
            pub PosixTimeMs: $matter::tlv::Nullable<u64>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3, response = PayloadTestResponse, response_id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PayloadTestRequest {
            #[tagval(0)]
            pub EnableKey: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub Value: u8,
            #[tagval(2)]
            pub Count: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PayloadTestResponse {
            #[tagval(0)]
            pub Payload: $matter::tlv::MatterBytes,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HardwareFaultChange {
            #[tagval(0)]
            pub Current: $matter::tlv::MatterList<$matter::definitions::GeneralDiagnostics::types::HardwareFaultEnum>,
            #[tagval(1)]
            pub Previous: $matter::tlv::MatterList<$matter::definitions::GeneralDiagnostics::types::HardwareFaultEnum>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RadioFaultChange {
            #[tagval(0)]
            pub Current: $matter::tlv::MatterList<$matter::definitions::GeneralDiagnostics::types::RadioFaultEnum>,
            #[tagval(1)]
            pub Previous: $matter::tlv::MatterList<$matter::definitions::GeneralDiagnostics::types::RadioFaultEnum>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NetworkFaultChange {
            #[tagval(0)]
            pub Current: $matter::tlv::MatterList<$matter::definitions::GeneralDiagnostics::types::NetworkFaultEnum>,
            #[tagval(1)]
            pub Previous: $matter::tlv::MatterList<$matter::definitions::GeneralDiagnostics::types::NetworkFaultEnum>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BootReason {
            #[tagval(0)]
            pub BootReason: $matter::definitions::GeneralDiagnostics::types::BootReasonEnum,
        }
    }
}
pub mod FormaldehydeConcentrationMeasurement {
    pub const ID: u32 = 0x042B;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LevelValueEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl LevelValueEnum {
            pub const Unknown: Self = Self(0x0);
            pub const Low: Self = Self(0x1);
            pub const Medium: Self = Self(0x2);
            pub const High: Self = Self(0x3);
            pub const Critical: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementMediumEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementMediumEnum {
            pub const Air: Self = Self(0x0);
            pub const Water: Self = Self(0x1);
            pub const Soil: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementUnitEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementUnitEnum {
            pub const PPM: Self = Self(0x0);
            pub const PPB: Self = Self(0x1);
            pub const PPT: Self = Self(0x2);
            pub const MGM3: Self = Self(0x3);
            pub const UGM3: Self = Self(0x4);
            pub const NGM3: Self = Self(0x5);
            pub const PM3: Self = Self(0x6);
            pub const BQM3: Self = Self(0x7);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Uncertainty(pub f32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementUnit(pub $matter::definitions::FormaldehydeConcentrationMeasurement::types::MeasurementUnitEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementMedium(pub $matter::definitions::FormaldehydeConcentrationMeasurement::types::MeasurementMediumEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LevelValue(pub $matter::definitions::FormaldehydeConcentrationMeasurement::types::LevelValueEnum);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod ICDManagement {
    pub const ID: u32 = 0x0046;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ClientTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ClientTypeEnum {
            pub const Permanent: Self = Self(0x0);
            pub const Ephemeral: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OperatingModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl OperatingModeEnum {
            pub const SIT: Self = Self(0x0);
            pub const LIT: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct UserActiveModeTriggerBitmap(pub u32);
        #[allow(non_upper_case_globals)]
        impl UserActiveModeTriggerBitmap {
            pub const PowerCycle: Self = Self(0x1);
            pub const SettingsMenu: Self = Self(0x2);
            pub const CustomInstruction: Self = Self(0x4);
            pub const DeviceManual: Self = Self(0x8);
            pub const ActuateSensor: Self = Self(0x10);
            pub const ActuateSensorSeconds: Self = Self(0x20);
            pub const ActuateSensorTimes: Self = Self(0x40);
            pub const ActuateSensorLightsBlink: Self = Self(0x80);
            pub const ResetButton: Self = Self(0x100);
            pub const ResetButtonLightsBlink: Self = Self(0x200);
            pub const ResetButtonSeconds: Self = Self(0x400);
            pub const ResetButtonTimes: Self = Self(0x800);
            pub const SetupButton: Self = Self(0x1000);
            pub const SetupButtonSeconds: Self = Self(0x2000);
            pub const SetupButtonLightsBlink: Self = Self(0x4000);
            pub const SetupButtonTimes: Self = Self(0x8000);
            pub const AppDefinedButton: Self = Self(0x10000);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MonitoringRegistrationStruct {
            #[tagval(1)]
            pub CheckInNodeID: u64,
            #[tagval(2)]
            pub MonitoredSubject: u64,
            #[tagval(4)]
            pub ClientType: $matter::definitions::ICDManagement::types::ClientTypeEnum,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct IdleModeDuration(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveModeDuration(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveModeThreshold(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RegisteredClients(pub $matter::tlv::MatterList<$matter::definitions::ICDManagement::types::MonitoringRegistrationStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ICDCounter(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ClientsSupportedPerFabric(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UserActiveModeTriggerHint(pub $matter::definitions::ICDManagement::types::UserActiveModeTriggerBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UserActiveModeTriggerInstruction(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperatingMode(pub $matter::definitions::ICDManagement::types::OperatingModeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaximumCheckInBackoff(pub u32);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = RegisterClientResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RegisterClient {
            #[tagval(0)]
            pub CheckInNodeID: u64,
            #[tagval(1)]
            pub MonitoredSubject: u64,
            #[tagval(2)]
            pub Key: $matter::tlv::MatterBytes,
            #[tagval(3)]
            pub VerificationKey: core::option::Option<$matter::tlv::MatterBytes>,
            #[tagval(4)]
            pub ClientType: $matter::definitions::ICDManagement::types::ClientTypeEnum,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RegisterClientResponse {
            #[tagval(0)]
            pub ICDCounter: u32,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UnregisterClient {
            #[tagval(0)]
            pub CheckInNodeID: u64,
            #[tagval(1)]
            pub VerificationKey: core::option::Option<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3, response = StayActiveResponse, response_id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StayActiveRequest {
            #[tagval(0)]
            pub StayActiveDuration: u32,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StayActiveResponse {
            #[tagval(0)]
            pub PromisedActiveDuration: u32,
        }
    }
    pub mod events {
    }
}
pub mod NetworkCommissioning {
    pub const ID: u32 = 0x0031;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct NetworkCommissioningStatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl NetworkCommissioningStatusEnum {
            pub const Success: Self = Self(0x0);
            pub const OutOfRange: Self = Self(0x1);
            pub const BoundsExceeded: Self = Self(0x2);
            pub const NetworkIDNotFound: Self = Self(0x3);
            pub const DuplicateNetworkID: Self = Self(0x4);
            pub const NetworkNotFound: Self = Self(0x5);
            pub const RegulatoryError: Self = Self(0x6);
            pub const AuthFailure: Self = Self(0x7);
            pub const UnsupportedSecurity: Self = Self(0x8);
            pub const OtherConnectionFailure: Self = Self(0x9);
            pub const IPV6Failed: Self = Self(0xA);
            pub const IPBindFailed: Self = Self(0xB);
            pub const UnknownError: Self = Self(0xC);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct WiFiBandEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl WiFiBandEnum {
            pub const _2G4: Self = Self(0x0);
            pub const _3G65: Self = Self(0x1);
            pub const _5G: Self = Self(0x2);
            pub const _6G: Self = Self(0x3);
            pub const _60G: Self = Self(0x4);
            pub const _1G: Self = Self(0x5);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ThreadCapabilitiesBitmap(pub u16);
        #[allow(non_upper_case_globals)]
        impl ThreadCapabilitiesBitmap {
            pub const IsBorderRouterCapable: Self = Self(0x1);
            pub const IsRouterCapable: Self = Self(0x2);
            pub const IsSleepyEndDeviceCapable: Self = Self(0x4);
            pub const IsFullThreadDevice: Self = Self(0x8);
            pub const IsSynchronizedSleepyEndDeviceCapable: Self = Self(0x10);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct WiFiSecurityBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl WiFiSecurityBitmap {
            pub const Unencrypted: Self = Self(0x1);
            pub const WEP: Self = Self(0x2);
            pub const WPAPERSONAL: Self = Self(0x4);
            pub const WPA2PERSONAL: Self = Self(0x8);
            pub const WPA3PERSONAL: Self = Self(0x10);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NetworkInfoStruct {
            #[tagval(0)]
            pub NetworkID: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub Connected: bool,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ThreadInterfaceScanResultStruct {
            #[tagval(0)]
            pub PanId: core::option::Option<u16>,
            #[tagval(1)]
            pub ExtendedPanId: core::option::Option<u64>,
            #[tagval(2)]
            pub NetworkName: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(3)]
            pub Channel: core::option::Option<u16>,
            #[tagval(4)]
            pub Version: core::option::Option<u8>,
            #[tagval(5)]
            pub ExtendedAddress: core::option::Option<$matter::tlv::MatterBytes>,
            #[tagval(6)]
            pub RSSI: core::option::Option<i8>,
            #[tagval(7)]
            pub LQI: core::option::Option<u8>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WiFiInterfaceScanResultStruct {
            #[tagval(0)]
            pub Security: core::option::Option<$matter::definitions::NetworkCommissioning::types::WiFiSecurityBitmap>,
            #[tagval(1)]
            pub SSID: core::option::Option<$matter::tlv::MatterBytes>,
            #[tagval(2)]
            pub BSSID: core::option::Option<$matter::tlv::MatterBytes>,
            #[tagval(3)]
            pub Channel: core::option::Option<u16>,
            #[tagval(4)]
            pub WiFiBand: core::option::Option<$matter::definitions::NetworkCommissioning::types::WiFiBandEnum>,
            #[tagval(5)]
            pub RSSI: core::option::Option<i8>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxNetworks(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Networks(pub $matter::tlv::MatterList<$matter::definitions::NetworkCommissioning::types::NetworkInfoStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ScanMaxTimeSeconds(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ConnectMaxTimeSeconds(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct InterfaceEnabled(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LastNetworkingStatus(pub $matter::tlv::Nullable<$matter::definitions::NetworkCommissioning::types::NetworkCommissioningStatusEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LastNetworkID(pub $matter::tlv::Nullable<$matter::tlv::MatterBytes>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LastConnectErrorValue(pub $matter::tlv::Nullable<i32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedWiFiBands(pub $matter::tlv::MatterList<$matter::definitions::NetworkCommissioning::types::WiFiBandEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedThreadFeatures(pub $matter::definitions::NetworkCommissioning::types::ThreadCapabilitiesBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ThreadVersion(pub u16);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = ScanNetworksResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ScanNetworks {
            #[tagval(0)]
            pub SSID: core::option::Option<$matter::tlv::Nullable<$matter::tlv::MatterBytes>>,
            #[tagval(1)]
            pub Breadcrumb: core::option::Option<u64>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ScanNetworksResponse {
            #[tagval(0)]
            pub NetworkingStatus: $matter::definitions::NetworkCommissioning::types::NetworkCommissioningStatusEnum,
            #[tagval(1)]
            pub DebugText: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub WiFiScanResults: core::option::Option<$matter::tlv::MatterList<$matter::definitions::NetworkCommissioning::types::WiFiInterfaceScanResultStruct>>,
            #[tagval(3)]
            pub ThreadScanResults: core::option::Option<$matter::tlv::MatterList<$matter::definitions::NetworkCommissioning::types::ThreadInterfaceScanResultStruct>>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = NetworkConfigResponse, response_id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddOrUpdateWiFiNetwork {
            #[tagval(0)]
            pub SSID: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub Credentials: $matter::tlv::MatterBytes,
            #[tagval(2)]
            pub Breadcrumb: core::option::Option<u64>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3, response = NetworkConfigResponse, response_id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddOrUpdateThreadNetwork {
            #[tagval(0)]
            pub OperationalDataset: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub Breadcrumb: core::option::Option<u64>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4, response = NetworkConfigResponse, response_id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveNetwork {
            #[tagval(0)]
            pub NetworkID: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub Breadcrumb: core::option::Option<u64>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NetworkConfigResponse {
            #[tagval(0)]
            pub NetworkingStatus: $matter::definitions::NetworkCommissioning::types::NetworkCommissioningStatusEnum,
            #[tagval(1)]
            pub DebugText: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub NetworkIndex: u8,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6, response = ConnectNetworkResponse, response_id = 0x7)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ConnectNetwork {
            #[tagval(0)]
            pub NetworkID: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub Breadcrumb: core::option::Option<u64>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ConnectNetworkResponse {
            #[tagval(0)]
            pub NetworkingStatus: $matter::definitions::NetworkCommissioning::types::NetworkCommissioningStatusEnum,
            #[tagval(1)]
            pub DebugText: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub ErrorValue: $matter::tlv::Nullable<i32>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x8, response = NetworkConfigResponse, response_id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ReorderNetwork {
            #[tagval(0)]
            pub NetworkID: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub NetworkIndex: u8,
            #[tagval(2)]
            pub Breadcrumb: core::option::Option<u64>,
        }
    }
    pub mod events {
    }
}
pub mod TimeSynchronization {
    pub const ID: u32 = 0x0038;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct GranularityEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl GranularityEnum {
            pub const NoTimeGranularity: Self = Self(0x0);
            pub const MinutesGranularity: Self = Self(0x1);
            pub const SecondsGranularity: Self = Self(0x2);
            pub const MillisecondsGranularity: Self = Self(0x3);
            pub const MicrosecondsGranularity: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusCodeEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl StatusCodeEnum {
            pub const TimeNotAccepted: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct TimeSourceEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl TimeSourceEnum {
            pub const None: Self = Self(0x0);
            pub const Unknown: Self = Self(0x1);
            pub const Admin: Self = Self(0x2);
            pub const NodeTimeCluster: Self = Self(0x3);
            pub const NonMatterSNTP: Self = Self(0x4);
            pub const NonMatterNTP: Self = Self(0x5);
            pub const MatterSNTP: Self = Self(0x6);
            pub const MatterNTP: Self = Self(0x7);
            pub const MixedNTP: Self = Self(0x8);
            pub const NonMatterSNTPNTS: Self = Self(0x9);
            pub const NonMatterNTPNTS: Self = Self(0xA);
            pub const MatterSNTPNTS: Self = Self(0xB);
            pub const MatterNTPNTS: Self = Self(0xC);
            pub const MixedNTPNTS: Self = Self(0xD);
            pub const CloudSource: Self = Self(0xE);
            pub const PTP: Self = Self(0xF);
            pub const GNSS: Self = Self(0x10);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct TimeZoneDatabaseEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl TimeZoneDatabaseEnum {
            pub const Full: Self = Self(0x0);
            pub const Partial: Self = Self(0x1);
            pub const None: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DSTOffsetStruct {
            #[tagval(0)]
            pub Offset: i32,
            #[tagval(1)]
            pub ValidStarting: u64,
            #[tagval(2)]
            pub ValidUntil: $matter::tlv::Nullable<u64>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FabricScopedTrustedTimeSourceStruct {
            #[tagval(0)]
            pub NodeID: u64,
            #[tagval(1)]
            pub Endpoint: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TimeZoneStruct {
            #[tagval(0)]
            pub Offset: i32,
            #[tagval(1)]
            pub ValidAt: u64,
            #[tagval(2)]
            pub Name: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TrustedTimeSourceStruct {
            #[tagval(0)]
            pub FabricIndex: u8,
            #[tagval(1)]
            pub NodeID: u64,
            #[tagval(2)]
            pub Endpoint: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UTCTime(pub $matter::tlv::Nullable<u64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Granularity(pub $matter::definitions::TimeSynchronization::types::GranularityEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TimeSource(pub $matter::definitions::TimeSynchronization::types::TimeSourceEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TrustedTimeSource(pub $matter::tlv::Nullable<$matter::definitions::TimeSynchronization::types::TrustedTimeSourceStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DefaultNTP(pub $matter::tlv::Nullable<$matter::tlv::MatterString>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TimeZone(pub $matter::tlv::MatterList<$matter::definitions::TimeSynchronization::types::TimeZoneStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DSTOffset(pub $matter::tlv::MatterList<$matter::definitions::TimeSynchronization::types::DSTOffsetStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LocalTime(pub $matter::tlv::Nullable<u64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TimeZoneDatabase(pub $matter::definitions::TimeSynchronization::types::TimeZoneDatabaseEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NTPServerAvailable(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TimeZoneListMaxSize(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xB, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DSTOffsetListMaxSize(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xC, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportsDNSResolve(pub bool);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetUTCTime {
            #[tagval(0)]
            pub UTCTime: u64,
            #[tagval(1)]
            pub Granularity: $matter::definitions::TimeSynchronization::types::GranularityEnum,
            #[tagval(2)]
            pub TimeSource: core::option::Option<$matter::definitions::TimeSynchronization::types::TimeSourceEnum>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetTrustedTimeSource {
            #[tagval(0)]
            pub TrustedTimeSource: $matter::tlv::Nullable<$matter::definitions::TimeSynchronization::types::FabricScopedTrustedTimeSourceStruct>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = SetTimeZoneResponse, response_id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetTimeZone {
            #[tagval(0)]
            pub TimeZone: $matter::tlv::MatterList<$matter::definitions::TimeSynchronization::types::TimeZoneStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetTimeZoneResponse {
            #[tagval(0)]
            pub DSTOffsetRequired: bool,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetDSTOffset {
            #[tagval(0)]
            pub DSTOffset: $matter::tlv::MatterList<$matter::definitions::TimeSynchronization::types::DSTOffsetStruct>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetDefaultNTP {
            #[tagval(0)]
            pub DefaultNTP: $matter::tlv::Nullable<$matter::tlv::MatterString>,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DSTTableEmpty {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DSTStatus {
            #[tagval(0)]
            pub DSTOffsetActive: bool,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TimeZoneStatus {
            #[tagval(0)]
            pub Offset: i32,
            #[tagval(1)]
            pub Name: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TimeFailure {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MissingTrustedTimeSource {
        }
    }
}
pub mod RVCRunMode {
    pub const ID: u32 = 0x0054;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ModeTag(pub u16);
        #[allow(non_upper_case_globals)]
        impl ModeTag {
            pub const Auto: Self = Self(0x0);
            pub const Quick: Self = Self(0x1);
            pub const Quiet: Self = Self(0x2);
            pub const LowNoise: Self = Self(0x3);
            pub const LowEnergy: Self = Self(0x4);
            pub const Vacation: Self = Self(0x5);
            pub const Min: Self = Self(0x6);
            pub const Max: Self = Self(0x7);
            pub const Night: Self = Self(0x8);
            pub const Day: Self = Self(0x9);
            pub const Idle: Self = Self(0x4000);
            pub const Cleaning: Self = Self(0x4001);
            pub const Mapping: Self = Self(0x4002);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusCodeEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl StatusCodeEnum {
            pub const Stuck: Self = Self(0x41);
            pub const DustBinMissing: Self = Self(0x42);
            pub const DustBinFull: Self = Self(0x43);
            pub const WaterTankEmpty: Self = Self(0x44);
            pub const WaterTankMissing: Self = Self(0x45);
            pub const WaterTankLidOpen: Self = Self(0x46);
            pub const MopCleaningPadMissing: Self = Self(0x47);
            pub const BatteryLow: Self = Self(0x48);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeOptionStruct {
            #[tagval(0)]
            pub Label: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Mode: u8,
            #[tagval(2)]
            pub ModeTags: $matter::tlv::MatterList<$matter::definitions::RVCRunMode::types::ModeTagStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeTagStruct {
            #[tagval(0)]
            pub MfgCode: core::option::Option<u16>,
            #[tagval(1)]
            pub Value: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedModes(pub $matter::tlv::MatterList<$matter::definitions::RVCRunMode::types::ModeOptionStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentMode(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartUpMode(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnMode(pub $matter::tlv::Nullable<u8>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = ChangeToModeResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToMode {
            #[tagval(0)]
            pub NewMode: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToModeResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub StatusText: $matter::tlv::MatterString,
        }
    }
    pub mod events {
    }
}
pub mod BooleanState {
    pub const ID: u32 = 0x0045;
    pub mod types {
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StateValue(pub bool);
    }
    pub mod commands {
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StateChange {
            #[tagval(0)]
            pub StateValue: bool,
        }
    }
}
pub mod CommodityPrice {
    pub const ID: u32 = 0x0095;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct CommodityPriceDetailBitmap(pub u16);
        #[allow(non_upper_case_globals)]
        impl CommodityPriceDetailBitmap {
            pub const Description: Self = Self(0x1);
            pub const Components: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CommodityPriceComponentStruct {
            #[tagval(0)]
            pub Price: i64,
            #[tagval(1)]
            pub Source: $matter::definitions::GlobalElements::types::TariffPriceTypeEnum,
            #[tagval(2)]
            pub Description: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(3)]
            pub TariffComponentID: core::option::Option<u32>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CommodityPriceStruct {
            #[tagval(0)]
            pub PeriodStart: u32,
            #[tagval(1)]
            pub PeriodEnd: $matter::tlv::Nullable<u32>,
            #[tagval(2)]
            pub Price: core::option::Option<i64>,
            #[tagval(3)]
            pub PriceLevel: core::option::Option<i16>,
            #[tagval(4)]
            pub Description: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(5)]
            pub Components: core::option::Option<$matter::tlv::MatterList<$matter::definitions::CommodityPrice::types::CommodityPriceComponentStruct>>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TariffUnit(pub $matter::definitions::GlobalElements::types::TariffUnitEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Currency(pub $matter::tlv::Nullable<$matter::definitions::GlobalElements::types::CurrencyStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentPrice(pub $matter::tlv::Nullable<$matter::definitions::CommodityPrice::types::CommodityPriceStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PriceForecast(pub $matter::tlv::MatterList<$matter::definitions::CommodityPrice::types::CommodityPriceStruct>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = GetDetailedPriceResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetDetailedPriceRequest {
            #[tagval(0)]
            pub Details: $matter::definitions::CommodityPrice::types::CommodityPriceDetailBitmap,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetDetailedPriceResponse {
            #[tagval(0)]
            pub CurrentPrice: $matter::tlv::Nullable<$matter::definitions::CommodityPrice::types::CommodityPriceStruct>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = GetDetailedForecastResponse, response_id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetDetailedForecastRequest {
            #[tagval(0)]
            pub Details: $matter::definitions::CommodityPrice::types::CommodityPriceDetailBitmap,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetDetailedForecastResponse {
            #[tagval(0)]
            pub PriceForecast: $matter::tlv::MatterList<$matter::definitions::CommodityPrice::types::CommodityPriceStruct>,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PriceChange {
            #[tagval(0)]
            pub CurrentPrice: $matter::tlv::Nullable<$matter::definitions::CommodityPrice::types::CommodityPriceStruct>,
        }
    }
}
pub mod ApplicationLauncher {
    pub const ID: u32 = 0x050C;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl StatusEnum {
            pub const Success: Self = Self(0x0);
            pub const AppNotAvailable: Self = Self(0x1);
            pub const SystemBusy: Self = Self(0x2);
            pub const PendingUserApproval: Self = Self(0x3);
            pub const Downloading: Self = Self(0x4);
            pub const Installing: Self = Self(0x5);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ApplicationEPStruct {
            #[tagval(0)]
            pub Application: $matter::definitions::ApplicationLauncher::types::ApplicationStruct,
            #[tagval(1)]
            pub Endpoint: core::option::Option<u16>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ApplicationStruct {
            #[tagval(0)]
            pub CatalogVendorID: u16,
            #[tagval(1)]
            pub ApplicationID: $matter::tlv::MatterString,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CatalogList(pub $matter::tlv::MatterList<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentApp(pub $matter::tlv::Nullable<$matter::definitions::ApplicationLauncher::types::ApplicationEPStruct>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = LauncherResponse, response_id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LaunchApp {
            #[tagval(0)]
            pub Application: core::option::Option<$matter::definitions::ApplicationLauncher::types::ApplicationStruct>,
            #[tagval(1)]
            pub Data: core::option::Option<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1, response = LauncherResponse, response_id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StopApp {
            #[tagval(0)]
            pub Application: core::option::Option<$matter::definitions::ApplicationLauncher::types::ApplicationStruct>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = LauncherResponse, response_id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HideApp {
            #[tagval(0)]
            pub Application: core::option::Option<$matter::definitions::ApplicationLauncher::types::ApplicationStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LauncherResponse {
            #[tagval(0)]
            pub Status: $matter::definitions::ApplicationLauncher::types::StatusEnum,
            #[tagval(1)]
            pub Data: core::option::Option<$matter::tlv::MatterBytes>,
        }
    }
    pub mod events {
    }
}
pub mod ThreadNetworkDiagnostics {
    pub const ID: u32 = 0x0035;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ConnectionStatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ConnectionStatusEnum {
            pub const Connected: Self = Self(0x0);
            pub const NotConnected: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct NetworkFaultEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl NetworkFaultEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const LinkDown: Self = Self(0x1);
            pub const HardwareFailure: Self = Self(0x2);
            pub const NetworkJammed: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct RoutingRoleEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl RoutingRoleEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const Unassigned: Self = Self(0x1);
            pub const SleepyEndDevice: Self = Self(0x2);
            pub const EndDevice: Self = Self(0x3);
            pub const REED: Self = Self(0x4);
            pub const Router: Self = Self(0x5);
            pub const Leader: Self = Self(0x6);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NeighborTableStruct {
            #[tagval(0)]
            pub ExtAddress: u64,
            #[tagval(1)]
            pub Age: u32,
            #[tagval(2)]
            pub Rloc16: u16,
            #[tagval(3)]
            pub LinkFrameCounter: u32,
            #[tagval(4)]
            pub MleFrameCounter: u32,
            #[tagval(5)]
            pub LQI: u8,
            #[tagval(6)]
            pub AverageRssi: $matter::tlv::Nullable<i8>,
            #[tagval(7)]
            pub LastRssi: $matter::tlv::Nullable<i8>,
            #[tagval(8)]
            pub FrameErrorRate: u8,
            #[tagval(9)]
            pub MessageErrorRate: u8,
            #[tagval(10)]
            pub RxOnWhenIdle: bool,
            #[tagval(11)]
            pub FullThreadDevice: bool,
            #[tagval(12)]
            pub FullNetworkData: bool,
            #[tagval(13)]
            pub IsChild: bool,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalDatasetComponents {
            #[tagval(0)]
            pub ActiveTimestampPresent: bool,
            #[tagval(1)]
            pub PendingTimestampPresent: bool,
            #[tagval(2)]
            pub MasterKeyPresent: bool,
            #[tagval(3)]
            pub NetworkNamePresent: bool,
            #[tagval(4)]
            pub ExtendedPanIdPresent: bool,
            #[tagval(5)]
            pub MeshLocalPrefixPresent: bool,
            #[tagval(6)]
            pub DelayPresent: bool,
            #[tagval(7)]
            pub PanIdPresent: bool,
            #[tagval(8)]
            pub ChannelPresent: bool,
            #[tagval(9)]
            pub PskcPresent: bool,
            #[tagval(10)]
            pub SecurityPolicyPresent: bool,
            #[tagval(11)]
            pub ChannelMaskPresent: bool,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RouteTableStruct {
            #[tagval(0)]
            pub ExtAddress: u64,
            #[tagval(1)]
            pub Rloc16: u16,
            #[tagval(2)]
            pub RouterId: u8,
            #[tagval(3)]
            pub NextHop: u8,
            #[tagval(4)]
            pub PathCost: u8,
            #[tagval(5)]
            pub LQIIn: u8,
            #[tagval(6)]
            pub LQIOut: u8,
            #[tagval(7)]
            pub Age: u8,
            #[tagval(8)]
            pub Allocated: bool,
            #[tagval(9)]
            pub LinkEstablished: bool,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SecurityPolicy {
            #[tagval(0)]
            pub RotationTime: u16,
            #[tagval(1)]
            pub Flags: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Channel(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RoutingRole(pub $matter::tlv::Nullable<$matter::definitions::ThreadNetworkDiagnostics::types::RoutingRoleEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NetworkName(pub $matter::tlv::Nullable<$matter::tlv::MatterString>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PanId(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ExtendedPanId(pub $matter::tlv::Nullable<u64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeshLocalPrefix(pub $matter::tlv::Nullable<$matter::tlv::MatterBytes>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OverrunCount(pub u64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NeighborTable(pub $matter::tlv::MatterList<$matter::definitions::ThreadNetworkDiagnostics::types::NeighborTableStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RouteTable(pub $matter::tlv::MatterList<$matter::definitions::ThreadNetworkDiagnostics::types::RouteTableStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PartitionId(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Weighting(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xB, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DataVersion(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xC, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StableDataVersion(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xD, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LeaderRouterId(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xE, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DetachedRoleCount(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xF, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChildRoleCount(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x10, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RouterRoleCount(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x11, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LeaderRoleCount(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x12, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AttachAttemptCount(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x13, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PartitionIdChangeCount(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x14, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BetterPartitionAttachAttemptCount(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x15, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ParentChangeCount(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x16, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TxTotalCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x17, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TxUnicastCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x18, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TxBroadcastCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x19, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TxAckRequestedCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1A, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TxAckedCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1B, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TxNoAckRequestedCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1C, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TxDataCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1D, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TxDataPollCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1E, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TxBeaconCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1F, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TxBeaconRequestCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x20, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TxOtherCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x21, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TxRetryCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x22, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TxDirectMaxRetryExpiryCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x23, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TxIndirectMaxRetryExpiryCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x24, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TxErrCcaCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x25, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TxErrAbortCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x26, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TxErrBusyChannelCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x27, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RxTotalCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x28, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RxUnicastCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x29, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RxBroadcastCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2A, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RxDataCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2B, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RxDataPollCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2C, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RxBeaconCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2D, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RxBeaconRequestCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2E, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RxOtherCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2F, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RxAddressFilteredCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x30, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RxDestAddrFilteredCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x31, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RxDuplicatedCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x32, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RxErrNoFrameCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x33, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RxErrUnknownNeighborCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x34, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RxErrInvalidSrcAddrCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x35, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RxErrSecCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x36, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RxErrFcsCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x37, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RxErrOtherCount(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x38, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveTimestamp(pub $matter::tlv::Nullable<u64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x39, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PendingTimestamp(pub $matter::tlv::Nullable<u64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3A, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Delay(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3B, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SecurityPolicy(pub $matter::tlv::Nullable<$matter::definitions::ThreadNetworkDiagnostics::types::SecurityPolicy>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3C, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChannelPage0Mask(pub $matter::tlv::Nullable<$matter::tlv::MatterBytes>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3D, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalDatasetComponents(pub $matter::tlv::Nullable<$matter::definitions::ThreadNetworkDiagnostics::types::OperationalDatasetComponents>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3E, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveNetworkFaultsList(pub $matter::tlv::MatterList<$matter::definitions::ThreadNetworkDiagnostics::types::NetworkFaultEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3F, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ExtAddress(pub $matter::tlv::Nullable<u64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x40, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Rloc16(pub $matter::tlv::Nullable<u16>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ResetCounts {
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ConnectionStatus {
            #[tagval(0)]
            pub ConnectionStatus: $matter::definitions::ThreadNetworkDiagnostics::types::ConnectionStatusEnum,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NetworkFaultChange {
            #[tagval(0)]
            pub Current: $matter::tlv::MatterList<$matter::definitions::ThreadNetworkDiagnostics::types::NetworkFaultEnum>,
            #[tagval(1)]
            pub Previous: $matter::tlv::MatterList<$matter::definitions::ThreadNetworkDiagnostics::types::NetworkFaultEnum>,
        }
    }
}
pub mod Actions {
    pub const ID: u32 = 0x0025;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ActionErrorEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ActionErrorEnum {
            pub const Unknown: Self = Self(0x0);
            pub const Interrupted: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ActionStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ActionStateEnum {
            pub const Inactive: Self = Self(0x0);
            pub const Active: Self = Self(0x1);
            pub const Paused: Self = Self(0x2);
            pub const Disabled: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ActionTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ActionTypeEnum {
            pub const Other: Self = Self(0x0);
            pub const Scene: Self = Self(0x1);
            pub const Sequence: Self = Self(0x2);
            pub const Automation: Self = Self(0x3);
            pub const Exception: Self = Self(0x4);
            pub const Notification: Self = Self(0x5);
            pub const Alarm: Self = Self(0x6);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct EndpointListTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl EndpointListTypeEnum {
            pub const Other: Self = Self(0x0);
            pub const Room: Self = Self(0x1);
            pub const Zone: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct CommandBits(pub u16);
        #[allow(non_upper_case_globals)]
        impl CommandBits {
            pub const InstantAction: Self = Self(0x1);
            pub const InstantActionWithTransition: Self = Self(0x2);
            pub const StartAction: Self = Self(0x4);
            pub const StartActionWithDuration: Self = Self(0x8);
            pub const StopAction: Self = Self(0x10);
            pub const PauseAction: Self = Self(0x20);
            pub const PauseActionWithDuration: Self = Self(0x40);
            pub const ResumeAction: Self = Self(0x80);
            pub const EnableAction: Self = Self(0x100);
            pub const EnableActionWithDuration: Self = Self(0x200);
            pub const DisableAction: Self = Self(0x400);
            pub const DisableActionWithDuration: Self = Self(0x800);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActionStruct {
            #[tagval(0)]
            pub ActionID: u16,
            #[tagval(1)]
            pub Name: $matter::tlv::MatterString,
            #[tagval(2)]
            pub Type: $matter::definitions::Actions::types::ActionTypeEnum,
            #[tagval(3)]
            pub EndpointListID: u16,
            #[tagval(4)]
            pub SupportedCommands: $matter::definitions::Actions::types::CommandBits,
            #[tagval(5)]
            pub State: $matter::definitions::Actions::types::ActionStateEnum,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EndpointListStruct {
            #[tagval(0)]
            pub EndpointListID: u16,
            #[tagval(1)]
            pub Name: $matter::tlv::MatterString,
            #[tagval(2)]
            pub Type: $matter::definitions::Actions::types::EndpointListTypeEnum,
            #[tagval(3)]
            pub Endpoints: $matter::tlv::MatterList<u16>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActionList(pub $matter::tlv::MatterList<$matter::definitions::Actions::types::ActionStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EndpointLists(pub $matter::tlv::MatterList<$matter::definitions::Actions::types::EndpointListStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetupURL(pub $matter::tlv::MatterString);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct InstantAction {
            #[tagval(0)]
            pub ActionID: u16,
            #[tagval(1)]
            pub InvokeID: core::option::Option<u32>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct InstantActionWithTransition {
            #[tagval(0)]
            pub ActionID: u16,
            #[tagval(1)]
            pub InvokeID: core::option::Option<u32>,
            #[tagval(2)]
            pub TransitionTime: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartAction {
            #[tagval(0)]
            pub ActionID: u16,
            #[tagval(1)]
            pub InvokeID: core::option::Option<u32>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartActionWithDuration {
            #[tagval(0)]
            pub ActionID: u16,
            #[tagval(1)]
            pub InvokeID: core::option::Option<u32>,
            #[tagval(2)]
            pub Duration: u32,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StopAction {
            #[tagval(0)]
            pub ActionID: u16,
            #[tagval(1)]
            pub InvokeID: core::option::Option<u32>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PauseAction {
            #[tagval(0)]
            pub ActionID: u16,
            #[tagval(1)]
            pub InvokeID: core::option::Option<u32>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PauseActionWithDuration {
            #[tagval(0)]
            pub ActionID: u16,
            #[tagval(1)]
            pub InvokeID: core::option::Option<u32>,
            #[tagval(2)]
            pub Duration: u32,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x7)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ResumeAction {
            #[tagval(0)]
            pub ActionID: u16,
            #[tagval(1)]
            pub InvokeID: core::option::Option<u32>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x8)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnableAction {
            #[tagval(0)]
            pub ActionID: u16,
            #[tagval(1)]
            pub InvokeID: core::option::Option<u32>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x9)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnableActionWithDuration {
            #[tagval(0)]
            pub ActionID: u16,
            #[tagval(1)]
            pub InvokeID: core::option::Option<u32>,
            #[tagval(2)]
            pub Duration: u32,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xA)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DisableAction {
            #[tagval(0)]
            pub ActionID: u16,
            #[tagval(1)]
            pub InvokeID: core::option::Option<u32>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xB)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DisableActionWithDuration {
            #[tagval(0)]
            pub ActionID: u16,
            #[tagval(1)]
            pub InvokeID: core::option::Option<u32>,
            #[tagval(2)]
            pub Duration: u32,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StateChanged {
            #[tagval(0)]
            pub ActionID: u16,
            #[tagval(1)]
            pub InvokeID: u32,
            #[tagval(2)]
            pub NewState: $matter::definitions::Actions::types::ActionStateEnum,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActionFailed {
            #[tagval(0)]
            pub ActionID: u16,
            #[tagval(1)]
            pub InvokeID: u32,
            #[tagval(2)]
            pub NewState: $matter::definitions::Actions::types::ActionStateEnum,
            #[tagval(3)]
            pub Error: $matter::definitions::Actions::types::ActionErrorEnum,
        }
    }
}
pub mod PM25ConcentrationMeasurement {
    pub const ID: u32 = 0x042A;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LevelValueEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl LevelValueEnum {
            pub const Unknown: Self = Self(0x0);
            pub const Low: Self = Self(0x1);
            pub const Medium: Self = Self(0x2);
            pub const High: Self = Self(0x3);
            pub const Critical: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementMediumEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementMediumEnum {
            pub const Air: Self = Self(0x0);
            pub const Water: Self = Self(0x1);
            pub const Soil: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementUnitEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementUnitEnum {
            pub const PPM: Self = Self(0x0);
            pub const PPB: Self = Self(0x1);
            pub const PPT: Self = Self(0x2);
            pub const MGM3: Self = Self(0x3);
            pub const UGM3: Self = Self(0x4);
            pub const NGM3: Self = Self(0x5);
            pub const PM3: Self = Self(0x6);
            pub const BQM3: Self = Self(0x7);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Uncertainty(pub f32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementUnit(pub $matter::definitions::PM25ConcentrationMeasurement::types::MeasurementUnitEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementMedium(pub $matter::definitions::PM25ConcentrationMeasurement::types::MeasurementMediumEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LevelValue(pub $matter::definitions::PM25ConcentrationMeasurement::types::LevelValueEnum);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod DiagnosticLogs {
    pub const ID: u32 = 0x0032;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct IntentEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl IntentEnum {
            pub const EndUserSupport: Self = Self(0x0);
            pub const NetworkDiag: Self = Self(0x1);
            pub const CrashLogs: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl StatusEnum {
            pub const Success: Self = Self(0x0);
            pub const Exhausted: Self = Self(0x1);
            pub const NoLogs: Self = Self(0x2);
            pub const Busy: Self = Self(0x3);
            pub const Denied: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct TransferProtocolEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl TransferProtocolEnum {
            pub const ResponsePayload: Self = Self(0x0);
            pub const BDX: Self = Self(0x1);
        }
    }
    pub mod attributes {
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = RetrieveLogsResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RetrieveLogsRequest {
            #[tagval(0)]
            pub Intent: $matter::definitions::DiagnosticLogs::types::IntentEnum,
            #[tagval(1)]
            pub RequestedProtocol: $matter::definitions::DiagnosticLogs::types::TransferProtocolEnum,
            #[tagval(2)]
            pub TransferFileDesignator: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RetrieveLogsResponse {
            #[tagval(0)]
            pub Status: $matter::definitions::DiagnosticLogs::types::StatusEnum,
            #[tagval(1)]
            pub LogContent: $matter::tlv::MatterBytes,
            #[tagval(2)]
            pub UTCTimeStamp: core::option::Option<u64>,
            #[tagval(3)]
            pub TimeSinceBoot: core::option::Option<u64>,
        }
    }
    pub mod events {
    }
}
pub mod GroupKeyManagement {
    pub const ID: u32 = 0x003F;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct GroupKeyMulticastPolicyEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl GroupKeyMulticastPolicyEnum {
            pub const PerGroupID: Self = Self(0x0);
            pub const AllNodes: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct GroupKeySecurityPolicyEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl GroupKeySecurityPolicyEnum {
            pub const TrustFirst: Self = Self(0x0);
            pub const CacheAndSync: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GroupInfoMapStruct {
            #[tagval(1)]
            pub GroupId: u16,
            #[tagval(2)]
            pub Endpoints: $matter::tlv::MatterList<u16>,
            #[tagval(3)]
            pub GroupName: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GroupKeyMapStruct {
            #[tagval(1)]
            pub GroupId: u16,
            #[tagval(2)]
            pub GroupKeySetID: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GroupKeySetStruct {
            #[tagval(0)]
            pub GroupKeySetID: u16,
            #[tagval(1)]
            pub GroupKeySecurityPolicy: $matter::definitions::GroupKeyManagement::types::GroupKeySecurityPolicyEnum,
            #[tagval(2)]
            pub EpochKey0: $matter::tlv::Nullable<$matter::tlv::MatterBytes>,
            #[tagval(3)]
            pub EpochStartTime0: $matter::tlv::Nullable<u64>,
            #[tagval(4)]
            pub EpochKey1: $matter::tlv::Nullable<$matter::tlv::MatterBytes>,
            #[tagval(5)]
            pub EpochStartTime1: $matter::tlv::Nullable<u64>,
            #[tagval(6)]
            pub EpochKey2: $matter::tlv::Nullable<$matter::tlv::MatterBytes>,
            #[tagval(7)]
            pub EpochStartTime2: $matter::tlv::Nullable<u64>,
            #[tagval(8)]
            pub GroupKeyMulticastPolicy: $matter::definitions::GroupKeyManagement::types::GroupKeyMulticastPolicyEnum,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GroupKeyMap(pub $matter::tlv::MatterList<$matter::definitions::GroupKeyManagement::types::GroupKeyMapStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GroupTable(pub $matter::tlv::MatterList<$matter::definitions::GroupKeyManagement::types::GroupInfoMapStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxGroupsPerFabric(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxGroupKeysPerFabric(pub u16);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct KeySetWrite {
            #[tagval(0)]
            pub GroupKeySet: $matter::definitions::GroupKeyManagement::types::GroupKeySetStruct,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1, response = KeySetReadResponse, response_id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct KeySetRead {
            #[tagval(0)]
            pub GroupKeySetID: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct KeySetReadResponse {
            #[tagval(0)]
            pub GroupKeySet: $matter::definitions::GroupKeyManagement::types::GroupKeySetStruct,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct KeySetRemove {
            #[tagval(0)]
            pub GroupKeySetID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4, response = KeySetReadAllIndicesResponse, response_id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct KeySetReadAllIndices {
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct KeySetReadAllIndicesResponse {
            #[tagval(0)]
            pub GroupKeySetIDs: $matter::tlv::MatterList<u16>,
        }
    }
    pub mod events {
    }
}
pub mod CarbonMonoxideConcentrationMeasurement {
    pub const ID: u32 = 0x040C;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LevelValueEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl LevelValueEnum {
            pub const Unknown: Self = Self(0x0);
            pub const Low: Self = Self(0x1);
            pub const Medium: Self = Self(0x2);
            pub const High: Self = Self(0x3);
            pub const Critical: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementMediumEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementMediumEnum {
            pub const Air: Self = Self(0x0);
            pub const Water: Self = Self(0x1);
            pub const Soil: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementUnitEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementUnitEnum {
            pub const PPM: Self = Self(0x0);
            pub const PPB: Self = Self(0x1);
            pub const PPT: Self = Self(0x2);
            pub const MGM3: Self = Self(0x3);
            pub const UGM3: Self = Self(0x4);
            pub const NGM3: Self = Self(0x5);
            pub const PM3: Self = Self(0x6);
            pub const BQM3: Self = Self(0x7);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Uncertainty(pub f32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementUnit(pub $matter::definitions::CarbonMonoxideConcentrationMeasurement::types::MeasurementUnitEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementMedium(pub $matter::definitions::CarbonMonoxideConcentrationMeasurement::types::MeasurementMediumEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LevelValue(pub $matter::definitions::CarbonMonoxideConcentrationMeasurement::types::LevelValueEnum);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod ApplicationBasic {
    pub const ID: u32 = 0x050D;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ApplicationStatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ApplicationStatusEnum {
            pub const Stopped: Self = Self(0x0);
            pub const ActiveVisibleFocus: Self = Self(0x1);
            pub const ActiveHidden: Self = Self(0x2);
            pub const ActiveVisibleNotFocus: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ApplicationStruct {
            #[tagval(0)]
            pub CatalogVendorID: u16,
            #[tagval(1)]
            pub ApplicationID: $matter::tlv::MatterString,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct VendorName(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct VendorID(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ApplicationName(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProductID(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Application(pub $matter::definitions::ApplicationBasic::types::ApplicationStruct);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Status(pub $matter::definitions::ApplicationBasic::types::ApplicationStatusEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ApplicationVersion(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AllowedVendorList(pub $matter::tlv::MatterList<u16>);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod LevelControl {
    pub const ID: u32 = 0x0008;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MoveModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MoveModeEnum {
            pub const Up: Self = Self(0x0);
            pub const Down: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StepModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl StepModeEnum {
            pub const Up: Self = Self(0x0);
            pub const Down: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OptionsBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl OptionsBitmap {
            pub const ExecuteIfOff: Self = Self(0x1);
            pub const CoupleColorTempToLevel: Self = Self(0x2);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentLevel(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemainingTime(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinLevel(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxLevel(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentFrequency(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinFrequency(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxFrequency(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xF, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Options(pub $matter::definitions::LevelControl::types::OptionsBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x10, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnOffTransitionTime(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x11, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnLevel(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x12, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnTransitionTime(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x13, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OffTransitionTime(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x14, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DefaultMoveRate(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4000, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartUpCurrentLevel(pub $matter::tlv::Nullable<u8>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MoveToLevel {
            #[tagval(0)]
            pub Level: u8,
            #[tagval(1)]
            pub TransitionTime: $matter::tlv::Nullable<u16>,
            #[tagval(2)]
            pub OptionsMask: $matter::definitions::LevelControl::types::OptionsBitmap,
            #[tagval(3)]
            pub OptionsOverride: $matter::definitions::LevelControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Move {
            #[tagval(0)]
            pub MoveMode: $matter::definitions::LevelControl::types::MoveModeEnum,
            #[tagval(1)]
            pub Rate: $matter::tlv::Nullable<u8>,
            #[tagval(2)]
            pub OptionsMask: $matter::definitions::LevelControl::types::OptionsBitmap,
            #[tagval(3)]
            pub OptionsOverride: $matter::definitions::LevelControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Step {
            #[tagval(0)]
            pub StepMode: $matter::definitions::LevelControl::types::StepModeEnum,
            #[tagval(1)]
            pub StepSize: u8,
            #[tagval(2)]
            pub TransitionTime: $matter::tlv::Nullable<u16>,
            #[tagval(3)]
            pub OptionsMask: $matter::definitions::LevelControl::types::OptionsBitmap,
            #[tagval(4)]
            pub OptionsOverride: $matter::definitions::LevelControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Stop {
            #[tagval(0)]
            pub OptionsMask: $matter::definitions::LevelControl::types::OptionsBitmap,
            #[tagval(1)]
            pub OptionsOverride: $matter::definitions::LevelControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MoveToLevelWithOnOff {
            #[tagval(0)]
            pub Level: u8,
            #[tagval(1)]
            pub TransitionTime: $matter::tlv::Nullable<u16>,
            #[tagval(2)]
            pub OptionsMask: $matter::definitions::LevelControl::types::OptionsBitmap,
            #[tagval(3)]
            pub OptionsOverride: $matter::definitions::LevelControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MoveWithOnOff {
            #[tagval(0)]
            pub MoveMode: $matter::definitions::LevelControl::types::MoveModeEnum,
            #[tagval(1)]
            pub Rate: $matter::tlv::Nullable<u8>,
            #[tagval(2)]
            pub OptionsMask: $matter::definitions::LevelControl::types::OptionsBitmap,
            #[tagval(3)]
            pub OptionsOverride: $matter::definitions::LevelControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StepWithOnOff {
            #[tagval(0)]
            pub StepMode: $matter::definitions::LevelControl::types::StepModeEnum,
            #[tagval(1)]
            pub StepSize: u8,
            #[tagval(2)]
            pub TransitionTime: $matter::tlv::Nullable<u16>,
            #[tagval(3)]
            pub OptionsMask: $matter::definitions::LevelControl::types::OptionsBitmap,
            #[tagval(4)]
            pub OptionsOverride: $matter::definitions::LevelControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x7)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StopWithOnOff {
            #[tagval(0)]
            pub OptionsMask: $matter::definitions::LevelControl::types::OptionsBitmap,
            #[tagval(1)]
            pub OptionsOverride: $matter::definitions::LevelControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x8)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MoveToClosestFrequency {
            #[tagval(0)]
            pub Frequency: u16,
        }
    }
    pub mod events {
    }
}
pub mod EnergyEVSE {
    pub const ID: u32 = 0x0099;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct EnergyTransferStoppedReasonEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl EnergyTransferStoppedReasonEnum {
            pub const EVStopped: Self = Self(0x0);
            pub const EVSEStopped: Self = Self(0x1);
            pub const Other: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct FaultStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl FaultStateEnum {
            pub const NoError: Self = Self(0x0);
            pub const MeterFailure: Self = Self(0x1);
            pub const OverVoltage: Self = Self(0x2);
            pub const UnderVoltage: Self = Self(0x3);
            pub const OverCurrent: Self = Self(0x4);
            pub const ContactWetFailure: Self = Self(0x5);
            pub const ContactDryFailure: Self = Self(0x6);
            pub const GroundFault: Self = Self(0x7);
            pub const PowerLoss: Self = Self(0x8);
            pub const PowerQuality: Self = Self(0x9);
            pub const PilotShortCircuit: Self = Self(0xA);
            pub const EmergencyStop: Self = Self(0xB);
            pub const EVDisconnected: Self = Self(0xC);
            pub const WrongPowerSupply: Self = Self(0xD);
            pub const LiveNeutralSwap: Self = Self(0xE);
            pub const OverTemperature: Self = Self(0xF);
            pub const Other: Self = Self(0xFF);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl StateEnum {
            pub const NotPluggedIn: Self = Self(0x0);
            pub const PluggedInNoDemand: Self = Self(0x1);
            pub const PluggedInDemand: Self = Self(0x2);
            pub const PluggedInCharging: Self = Self(0x3);
            pub const PluggedInDischarging: Self = Self(0x4);
            pub const SessionEnding: Self = Self(0x5);
            pub const Fault: Self = Self(0x6);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct SupplyStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl SupplyStateEnum {
            pub const Disabled: Self = Self(0x0);
            pub const ChargingEnabled: Self = Self(0x1);
            pub const DischargingEnabled: Self = Self(0x2);
            pub const DisabledError: Self = Self(0x3);
            pub const DisabledDiagnostics: Self = Self(0x4);
            pub const Enabled: Self = Self(0x5);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct TargetDayOfWeekBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl TargetDayOfWeekBitmap {
            pub const Sunday: Self = Self(0x1);
            pub const Monday: Self = Self(0x2);
            pub const Tuesday: Self = Self(0x4);
            pub const Wednesday: Self = Self(0x8);
            pub const Thursday: Self = Self(0x10);
            pub const Friday: Self = Self(0x20);
            pub const Saturday: Self = Self(0x40);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChargingTargetScheduleStruct {
            #[tagval(0)]
            pub DayOfWeekForSequence: $matter::definitions::EnergyEVSE::types::TargetDayOfWeekBitmap,
            #[tagval(1)]
            pub ChargingTargets: $matter::tlv::MatterList<$matter::definitions::EnergyEVSE::types::ChargingTargetStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChargingTargetStruct {
            #[tagval(0)]
            pub TargetTimeMinutesPastMidnight: u16,
            #[tagval(1)]
            pub TargetSoC: core::option::Option<u8>,
            #[tagval(2)]
            pub AddedEnergy: core::option::Option<i64>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct State(pub $matter::tlv::Nullable<$matter::definitions::EnergyEVSE::types::StateEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupplyState(pub $matter::definitions::EnergyEVSE::types::SupplyStateEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FaultState(pub $matter::definitions::EnergyEVSE::types::FaultStateEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChargingEnabledUntil(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DischargingEnabledUntil(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CircuitCapacity(pub i64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinimumChargeCurrent(pub i64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaximumChargeCurrent(pub i64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaximumDischargeCurrent(pub i64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UserMaximumChargeCurrent(pub i64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RandomizationDelayWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x23, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NextChargeStartTime(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x24, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NextChargeTargetTime(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x25, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NextChargeRequiredEnergy(pub $matter::tlv::Nullable<i64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x26, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NextChargeTargetSoC(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x27, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ApproximateEVEfficiency(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x30, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StateOfCharge(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x31, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatteryCapacity(pub $matter::tlv::Nullable<i64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x32, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct VehicleID(pub $matter::tlv::Nullable<$matter::tlv::MatterString>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x40, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SessionID(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x41, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SessionDuration(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x42, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SessionEnergyCharged(pub $matter::tlv::Nullable<i64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x43, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SessionEnergyDischarged(pub $matter::tlv::Nullable<i64>);
    }
    pub mod commands {
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetTargetsResponse {
            #[tagval(0)]
            pub ChargingTargetSchedules: $matter::tlv::MatterList<$matter::definitions::EnergyEVSE::types::ChargingTargetScheduleStruct>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Disable {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnableCharging {
            #[tagval(0)]
            pub ChargingEnabledUntil: $matter::tlv::Nullable<u32>,
            #[tagval(1)]
            pub MinimumChargeCurrent: i64,
            #[tagval(2)]
            pub MaximumChargeCurrent: i64,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnableDischarging {
            #[tagval(0)]
            pub DischargingEnabledUntil: $matter::tlv::Nullable<u32>,
            #[tagval(1)]
            pub MaximumDischargeCurrent: i64,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartDiagnostics {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetTargets {
            #[tagval(0)]
            pub ChargingTargetSchedules: $matter::tlv::MatterList<$matter::definitions::EnergyEVSE::types::ChargingTargetScheduleStruct>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6, response = GetTargetsResponse, response_id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetTargets {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x7)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ClearTargets {
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EVConnected {
            #[tagval(0)]
            pub SessionID: u32,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EVNotDetected {
            #[tagval(0)]
            pub SessionID: u32,
            #[tagval(1)]
            pub State: $matter::definitions::EnergyEVSE::types::StateEnum,
            #[tagval(2)]
            pub SessionDuration: u32,
            #[tagval(3)]
            pub SessionEnergyCharged: i64,
            #[tagval(4)]
            pub SessionEnergyDischarged: core::option::Option<i64>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnergyTransferStarted {
            #[tagval(0)]
            pub SessionID: u32,
            #[tagval(1)]
            pub State: $matter::definitions::EnergyEVSE::types::StateEnum,
            #[tagval(2)]
            pub MaximumCurrent: i64,
            #[tagval(3)]
            pub MaximumDischargeCurrent: core::option::Option<i64>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnergyTransferStopped {
            #[tagval(0)]
            pub SessionID: u32,
            #[tagval(1)]
            pub State: $matter::definitions::EnergyEVSE::types::StateEnum,
            #[tagval(2)]
            pub Reason: $matter::definitions::EnergyEVSE::types::EnergyTransferStoppedReasonEnum,
            #[tagval(4)]
            pub EnergyTransferred: i64,
            #[tagval(5)]
            pub EnergyDischarged: core::option::Option<i64>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Fault {
            #[tagval(0)]
            pub SessionID: $matter::tlv::Nullable<u32>,
            #[tagval(1)]
            pub State: $matter::definitions::EnergyEVSE::types::StateEnum,
            #[tagval(2)]
            pub FaultStatePreviousState: $matter::definitions::EnergyEVSE::types::FaultStateEnum,
            #[tagval(4)]
            pub FaultStateCurrentState: $matter::definitions::EnergyEVSE::types::FaultStateEnum,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RFID {
            #[tagval(0)]
            pub UID: $matter::tlv::MatterBytes,
        }
    }
}
pub mod ContentAppObserver {
    pub const ID: u32 = 0x0510;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl StatusEnum {
            pub const Success: Self = Self(0x0);
            pub const UnexpectedData: Self = Self(0x1);
        }
    }
    pub mod attributes {
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = ContentAppMessageResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ContentAppMessage {
            #[tagval(0)]
            pub Data: $matter::tlv::MatterString,
            #[tagval(1)]
            pub EncodingHint: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ContentAppMessageResponse {
            #[tagval(0)]
            pub Status: $matter::definitions::ContentAppObserver::types::StatusEnum,
            #[tagval(1)]
            pub Data: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub EncodingHint: core::option::Option<$matter::tlv::MatterString>,
        }
    }
    pub mod events {
    }
}
pub mod BridgedDeviceBasicInformation {
    pub const ID: u32 = 0x0039;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ColorEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ColorEnum {
            pub const Black: Self = Self(0x0);
            pub const Navy: Self = Self(0x1);
            pub const Green: Self = Self(0x2);
            pub const Teal: Self = Self(0x3);
            pub const Maroon: Self = Self(0x4);
            pub const Purple: Self = Self(0x5);
            pub const Olive: Self = Self(0x6);
            pub const Gray: Self = Self(0x7);
            pub const Blue: Self = Self(0x8);
            pub const Lime: Self = Self(0x9);
            pub const Aqua: Self = Self(0xA);
            pub const Red: Self = Self(0xB);
            pub const Fuchsia: Self = Self(0xC);
            pub const Yellow: Self = Self(0xD);
            pub const White: Self = Self(0xE);
            pub const Nickel: Self = Self(0xF);
            pub const Chrome: Self = Self(0x10);
            pub const Brass: Self = Self(0x11);
            pub const Copper: Self = Self(0x12);
            pub const Silver: Self = Self(0x13);
            pub const Gold: Self = Self(0x14);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ProductFinishEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ProductFinishEnum {
            pub const Other: Self = Self(0x0);
            pub const Matte: Self = Self(0x1);
            pub const Satin: Self = Self(0x2);
            pub const Polished: Self = Self(0x3);
            pub const Rugged: Self = Self(0x4);
            pub const Fabric: Self = Self(0x5);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CapabilityMinimaStruct {
            #[tagval(0)]
            pub CaseSessionsPerFabric: u16,
            #[tagval(1)]
            pub SubscriptionsPerFabric: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProductAppearanceStruct {
            #[tagval(0)]
            pub Finish: $matter::definitions::BridgedDeviceBasicInformation::types::ProductFinishEnum,
            #[tagval(1)]
            pub PrimaryColor: $matter::tlv::Nullable<$matter::definitions::BridgedDeviceBasicInformation::types::ColorEnum>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DataModelRevision(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct VendorName(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct VendorID(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProductName(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProductID(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NodeLabel(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Location(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HardwareVersion(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HardwareVersionString(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SoftwareVersion(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SoftwareVersionString(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xB, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ManufacturingDate(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xC, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PartNumber(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xD, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProductURL(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xE, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProductLabel(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xF, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SerialNumber(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x10, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LocalConfigDisabled(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x11, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Reachable(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x12, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UniqueID(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x13, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CapabilityMinima(pub $matter::definitions::BridgedDeviceBasicInformation::types::CapabilityMinimaStruct);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x14, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProductAppearance(pub $matter::definitions::BridgedDeviceBasicInformation::types::ProductAppearanceStruct);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x15, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SpecificationVersion(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x16, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxPathsPerInvoke(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x18, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ConfigurationVersion(pub u32);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x80)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct KeepActive {
            #[tagval(0)]
            pub StayActiveDuration: u32,
            #[tagval(1)]
            pub TimeoutMs: u32,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartUp {
            #[tagval(0)]
            pub SoftwareVersion: u32,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ShutDown {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Leave {
            #[tagval(0)]
            pub FabricIndex: core::option::Option<u8>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ReachableChanged {
            #[tagval(0)]
            pub ReachableNewValue: bool,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x80)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveChanged {
            #[tagval(0)]
            pub PromisedActiveDuration: u32,
        }
    }
}
pub mod SoftwareDiagnostics {
    pub const ID: u32 = 0x0034;
    pub mod types {
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ThreadMetricsStruct {
            #[tagval(0)]
            pub ID: u64,
            #[tagval(1)]
            pub Name: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub StackFreeCurrent: core::option::Option<u32>,
            #[tagval(3)]
            pub StackFreeMinimum: core::option::Option<u32>,
            #[tagval(4)]
            pub StackSize: core::option::Option<u32>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ThreadMetrics(pub $matter::tlv::MatterList<$matter::definitions::SoftwareDiagnostics::types::ThreadMetricsStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentHeapFree(pub u64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentHeapUsed(pub u64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentHeapHighWatermark(pub u64);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ResetWatermarks {
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SoftwareFault {
            #[tagval(0)]
            pub ID: u64,
            #[tagval(1)]
            pub Name: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub FaultRecording: core::option::Option<$matter::tlv::MatterBytes>,
        }
    }
}
pub mod PowerSourceConfiguration {
    pub const ID: u32 = 0x002E;
    pub mod types {
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Sources(pub $matter::tlv::MatterList<u16>);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod DishwasherMode {
    pub const ID: u32 = 0x0059;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ModeTag(pub u16);
        #[allow(non_upper_case_globals)]
        impl ModeTag {
            pub const Auto: Self = Self(0x0);
            pub const Quick: Self = Self(0x1);
            pub const Quiet: Self = Self(0x2);
            pub const LowNoise: Self = Self(0x3);
            pub const LowEnergy: Self = Self(0x4);
            pub const Vacation: Self = Self(0x5);
            pub const Min: Self = Self(0x6);
            pub const Max: Self = Self(0x7);
            pub const Night: Self = Self(0x8);
            pub const Day: Self = Self(0x9);
            pub const Normal: Self = Self(0x4000);
            pub const Heavy: Self = Self(0x4001);
            pub const Light: Self = Self(0x4002);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeOptionStruct {
            #[tagval(0)]
            pub Label: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Mode: u8,
            #[tagval(2)]
            pub ModeTags: $matter::tlv::MatterList<$matter::definitions::DishwasherMode::types::ModeTagStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeTagStruct {
            #[tagval(0)]
            pub MfgCode: core::option::Option<u16>,
            #[tagval(1)]
            pub Value: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedModes(pub $matter::tlv::MatterList<$matter::definitions::DishwasherMode::types::ModeOptionStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentMode(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartUpMode(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnMode(pub $matter::tlv::Nullable<u8>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = ChangeToModeResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToMode {
            #[tagval(0)]
            pub NewMode: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToModeResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub StatusText: $matter::tlv::MatterString,
        }
    }
    pub mod events {
    }
}
pub mod AdministratorCommissioning {
    pub const ID: u32 = 0x003C;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct CommissioningWindowStatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl CommissioningWindowStatusEnum {
            pub const WindowNotOpen: Self = Self(0x0);
            pub const EnhancedWindowOpen: Self = Self(0x1);
            pub const BasicWindowOpen: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusCodeEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl StatusCodeEnum {
            pub const Busy: Self = Self(0x2);
            pub const PAKEParameterError: Self = Self(0x3);
            pub const WindowNotOpen: Self = Self(0x4);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WindowStatus(pub $matter::definitions::AdministratorCommissioning::types::CommissioningWindowStatusEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AdminFabricIndex(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AdminVendorId(pub $matter::tlv::Nullable<u16>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OpenCommissioningWindow {
            #[tagval(0)]
            pub CommissioningTimeout: u16,
            #[tagval(1)]
            pub PAKEPasscodeVerifier: $matter::tlv::MatterBytes,
            #[tagval(2)]
            pub Discriminator: u16,
            #[tagval(3)]
            pub Iterations: u32,
            #[tagval(4)]
            pub Salt: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OpenBasicCommissioningWindow {
            #[tagval(0)]
            pub CommissioningTimeout: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RevokeCommissioning {
        }
    }
    pub mod events {
    }
}
pub mod ZoneManagement {
    pub const ID: u32 = 0x0550;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ZoneEventStoppedReasonEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ZoneEventStoppedReasonEnum {
            pub const ActionStopped: Self = Self(0x0);
            pub const Timeout: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ZoneEventTriggeredReasonEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ZoneEventTriggeredReasonEnum {
            pub const Motion: Self = Self(0x0);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ZoneSourceEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ZoneSourceEnum {
            pub const Mfg: Self = Self(0x0);
            pub const User: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ZoneTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ZoneTypeEnum {
            pub const TwoDCARTZone: Self = Self(0x0);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ZoneUseEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ZoneUseEnum {
            pub const Motion: Self = Self(0x0);
            pub const Privacy: Self = Self(0x1);
            pub const Focus: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TwoDCartesianVertexStruct {
            #[tagval(0)]
            pub X: u16,
            #[tagval(1)]
            pub Y: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TwoDCartesianZoneStruct {
            #[tagval(0)]
            pub Name: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Use: $matter::definitions::ZoneManagement::types::ZoneUseEnum,
            #[tagval(2)]
            pub Vertices: $matter::tlv::MatterList<$matter::definitions::ZoneManagement::types::TwoDCartesianVertexStruct>,
            #[tagval(3)]
            pub Color: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ZoneInformationStruct {
            #[tagval(0)]
            pub ZoneID: u16,
            #[tagval(1)]
            pub ZoneType: $matter::definitions::ZoneManagement::types::ZoneTypeEnum,
            #[tagval(2)]
            pub ZoneSource: $matter::definitions::ZoneManagement::types::ZoneSourceEnum,
            #[tagval(3)]
            pub TwoDCartesianZone: core::option::Option<$matter::definitions::ZoneManagement::types::TwoDCartesianZoneStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ZoneTriggerControlStruct {
            #[tagval(0)]
            pub ZoneID: u16,
            #[tagval(1)]
            pub InitialDuration: u32,
            #[tagval(2)]
            pub AugmentationDuration: u32,
            #[tagval(3)]
            pub MaxDuration: u32,
            #[tagval(4)]
            pub BlindDuration: u32,
            #[tagval(5)]
            pub Sensitivity: core::option::Option<u8>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxUserDefinedZones(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxZones(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Zones(pub $matter::tlv::MatterList<$matter::definitions::ZoneManagement::types::ZoneInformationStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Triggers(pub $matter::tlv::MatterList<$matter::definitions::ZoneManagement::types::ZoneTriggerControlStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SensitivityMax(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Sensitivity(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TwoDCartesianMax(pub $matter::definitions::ZoneManagement::types::TwoDCartesianVertexStruct);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = CreateTwoDCartesianZoneResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CreateTwoDCartesianZone {
            #[tagval(0)]
            pub Zone: $matter::definitions::ZoneManagement::types::TwoDCartesianZoneStruct,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CreateTwoDCartesianZoneResponse {
            #[tagval(0)]
            pub ZoneID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UpdateTwoDCartesianZone {
            #[tagval(0)]
            pub ZoneID: u16,
            #[tagval(1)]
            pub Zone: $matter::definitions::ZoneManagement::types::TwoDCartesianZoneStruct,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveZone {
            #[tagval(0)]
            pub ZoneID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CreateOrUpdateTrigger {
            #[tagval(0)]
            pub Trigger: $matter::definitions::ZoneManagement::types::ZoneTriggerControlStruct,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveTrigger {
            #[tagval(0)]
            pub ZoneID: u16,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ZoneTriggered {
            #[tagval(0)]
            pub Zone: u16,
            #[tagval(1)]
            pub Reason: $matter::definitions::ZoneManagement::types::ZoneEventTriggeredReasonEnum,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ZoneStopped {
            #[tagval(0)]
            pub Zone: u16,
            #[tagval(1)]
            pub Reason: $matter::definitions::ZoneManagement::types::ZoneEventStoppedReasonEnum,
        }
    }
}
pub mod JointFabricDatastore {
    pub const ID: u32 = 0x0752;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DatastoreAccessControlEntryAuthModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl DatastoreAccessControlEntryAuthModeEnum {
            pub const PASE: Self = Self(0x1);
            pub const CASE: Self = Self(0x2);
            pub const Group: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DatastoreAccessControlEntryPrivilegeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl DatastoreAccessControlEntryPrivilegeEnum {
            pub const View: Self = Self(0x1);
            pub const ProxyView: Self = Self(0x2);
            pub const Operate: Self = Self(0x3);
            pub const Manage: Self = Self(0x4);
            pub const Administer: Self = Self(0x5);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DatastoreGroupKeyMulticastPolicyEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl DatastoreGroupKeyMulticastPolicyEnum {
            pub const PerGroupID: Self = Self(0x0);
            pub const AllNodes: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DatastoreGroupKeySecurityPolicyEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl DatastoreGroupKeySecurityPolicyEnum {
            pub const TrustFirst: Self = Self(0x0);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DatastoreStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl DatastoreStateEnum {
            pub const Pending: Self = Self(0x0);
            pub const Committed: Self = Self(0x1);
            pub const DeletePending: Self = Self(0x2);
            pub const CommitFailed: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DatastoreACLEntryStruct {
            #[tagval(0)]
            pub NodeID: u64,
            #[tagval(1)]
            pub ListID: u16,
            #[tagval(2)]
            pub ACLEntry: $matter::definitions::JointFabricDatastore::types::DatastoreAccessControlEntryStruct,
            #[tagval(3)]
            pub StatusEntry: $matter::definitions::JointFabricDatastore::types::DatastoreStatusEntryStruct,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DatastoreAccessControlEntryStruct {
            #[tagval(1)]
            pub Privilege: $matter::definitions::JointFabricDatastore::types::DatastoreAccessControlEntryPrivilegeEnum,
            #[tagval(2)]
            pub AuthMode: $matter::definitions::JointFabricDatastore::types::DatastoreAccessControlEntryAuthModeEnum,
            #[tagval(3)]
            pub Subjects: $matter::tlv::Nullable<$matter::tlv::MatterList<u64>>,
            #[tagval(4)]
            pub Targets: $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::JointFabricDatastore::types::DatastoreAccessControlTargetStruct>>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DatastoreAccessControlTargetStruct {
            #[tagval(0)]
            pub Cluster: $matter::tlv::Nullable<u32>,
            #[tagval(1)]
            pub Endpoint: $matter::tlv::Nullable<u16>,
            #[tagval(2)]
            pub DeviceType: $matter::tlv::Nullable<u32>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DatastoreAdministratorInformationEntryStruct {
            #[tagval(1)]
            pub NodeID: u64,
            #[tagval(2)]
            pub FriendlyName: $matter::tlv::MatterString,
            #[tagval(3)]
            pub VendorID: u16,
            #[tagval(4)]
            pub ICAC: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DatastoreBindingTargetStruct {
            #[tagval(1)]
            pub Node: u64,
            #[tagval(2)]
            pub Group: core::option::Option<u16>,
            #[tagval(3)]
            pub Endpoint: core::option::Option<u16>,
            #[tagval(4)]
            pub Cluster: core::option::Option<u32>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DatastoreEndpointBindingEntryStruct {
            #[tagval(0)]
            pub NodeID: u64,
            #[tagval(1)]
            pub EndpointID: u16,
            #[tagval(2)]
            pub ListID: u16,
            #[tagval(3)]
            pub Binding: $matter::definitions::JointFabricDatastore::types::DatastoreBindingTargetStruct,
            #[tagval(4)]
            pub StatusEntry: $matter::definitions::JointFabricDatastore::types::DatastoreStatusEntryStruct,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DatastoreEndpointEntryStruct {
            #[tagval(0)]
            pub EndpointID: u16,
            #[tagval(1)]
            pub NodeID: u64,
            #[tagval(2)]
            pub FriendlyName: $matter::tlv::MatterString,
            #[tagval(3)]
            pub StatusEntry: $matter::definitions::JointFabricDatastore::types::DatastoreStatusEntryStruct,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DatastoreEndpointGroupIDEntryStruct {
            #[tagval(0)]
            pub NodeID: u64,
            #[tagval(1)]
            pub EndpointID: u16,
            #[tagval(2)]
            pub GroupID: u16,
            #[tagval(3)]
            pub StatusEntry: $matter::definitions::JointFabricDatastore::types::DatastoreStatusEntryStruct,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DatastoreGroupInformationEntryStruct {
            #[tagval(0)]
            pub GroupID: u64,
            #[tagval(1)]
            pub FriendlyName: $matter::tlv::MatterString,
            #[tagval(2)]
            pub GroupKeySetID: $matter::tlv::Nullable<u16>,
            #[tagval(3)]
            pub GroupCAT: $matter::tlv::Nullable<u16>,
            #[tagval(4)]
            pub GroupCATVersion: $matter::tlv::Nullable<u16>,
            #[tagval(5)]
            pub GroupPermission: $matter::definitions::JointFabricDatastore::types::DatastoreAccessControlEntryPrivilegeEnum,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DatastoreGroupKeySetStruct {
            #[tagval(0)]
            pub GroupKeySetID: u16,
            #[tagval(1)]
            pub GroupKeySecurityPolicy: $matter::definitions::JointFabricDatastore::types::DatastoreGroupKeySecurityPolicyEnum,
            #[tagval(2)]
            pub EpochKey0: $matter::tlv::Nullable<$matter::tlv::MatterBytes>,
            #[tagval(3)]
            pub EpochStartTime0: $matter::tlv::Nullable<u64>,
            #[tagval(4)]
            pub EpochKey1: $matter::tlv::Nullable<$matter::tlv::MatterBytes>,
            #[tagval(5)]
            pub EpochStartTime1: $matter::tlv::Nullable<u64>,
            #[tagval(6)]
            pub EpochKey2: $matter::tlv::Nullable<$matter::tlv::MatterBytes>,
            #[tagval(7)]
            pub EpochStartTime2: $matter::tlv::Nullable<u64>,
            #[tagval(8)]
            pub GroupKeyMulticastPolicy: $matter::definitions::JointFabricDatastore::types::DatastoreGroupKeyMulticastPolicyEnum,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DatastoreNodeInformationEntryStruct {
            #[tagval(1)]
            pub NodeID: u64,
            #[tagval(2)]
            pub FriendlyName: $matter::tlv::MatterString,
            #[tagval(3)]
            pub CommissioningStatusEntry: $matter::definitions::JointFabricDatastore::types::DatastoreStatusEntryStruct,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DatastoreNodeKeySetEntryStruct {
            #[tagval(0)]
            pub NodeID: u64,
            #[tagval(1)]
            pub GroupKeySetID: u16,
            #[tagval(2)]
            pub StatusEntry: $matter::definitions::JointFabricDatastore::types::DatastoreStatusEntryStruct,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DatastoreStatusEntryStruct {
            #[tagval(0)]
            pub State: $matter::definitions::JointFabricDatastore::types::DatastoreStateEnum,
            #[tagval(1)]
            pub UpdateTimestamp: u32,
            #[tagval(2)]
            pub FailureCode: u8,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AnchorRootCA(pub $matter::tlv::MatterBytes);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AnchorNodeID(pub u64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AnchorVendorID(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FriendlyName(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GroupKeySetList(pub $matter::tlv::MatterList<$matter::definitions::JointFabricDatastore::types::DatastoreGroupKeySetStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GroupList(pub $matter::tlv::MatterList<$matter::definitions::JointFabricDatastore::types::DatastoreGroupInformationEntryStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NodeList(pub $matter::tlv::MatterList<$matter::definitions::JointFabricDatastore::types::DatastoreNodeInformationEntryStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AdminList(pub $matter::tlv::MatterList<$matter::definitions::JointFabricDatastore::types::DatastoreAdministratorInformationEntryStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Status(pub $matter::definitions::JointFabricDatastore::types::DatastoreStatusEntryStruct);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EndpointGroupIDList(pub $matter::tlv::MatterList<$matter::definitions::JointFabricDatastore::types::DatastoreEndpointGroupIDEntryStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EndpointBindingList(pub $matter::tlv::MatterList<$matter::definitions::JointFabricDatastore::types::DatastoreEndpointBindingEntryStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xB, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NodeKeySetList(pub $matter::tlv::MatterList<$matter::definitions::JointFabricDatastore::types::DatastoreNodeKeySetEntryStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xC, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NodeACLList(pub $matter::tlv::MatterList<$matter::definitions::JointFabricDatastore::types::DatastoreACLEntryStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xD, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NodeEndpointList(pub $matter::tlv::MatterList<$matter::definitions::JointFabricDatastore::types::DatastoreEndpointEntryStruct>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddKeySet {
            #[tagval(0)]
            pub GroupKeySet: $matter::definitions::JointFabricDatastore::types::DatastoreGroupKeySetStruct,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UpdateKeySet {
            #[tagval(0)]
            pub GroupKeySet: $matter::definitions::JointFabricDatastore::types::DatastoreGroupKeySetStruct,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveKeySet {
            #[tagval(0)]
            pub GroupKeySetID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddGroup {
            #[tagval(0)]
            pub GroupID: u16,
            #[tagval(1)]
            pub FriendlyName: $matter::tlv::MatterString,
            #[tagval(2)]
            pub GroupKeySetID: $matter::tlv::Nullable<u16>,
            #[tagval(3)]
            pub GroupCAT: $matter::tlv::Nullable<u16>,
            #[tagval(4)]
            pub GroupCATVersion: $matter::tlv::Nullable<u16>,
            #[tagval(5)]
            pub GroupPermission: $matter::definitions::JointFabricDatastore::types::DatastoreAccessControlEntryPrivilegeEnum,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UpdateGroup {
            #[tagval(0)]
            pub GroupID: u16,
            #[tagval(1)]
            pub FriendlyName: $matter::tlv::Nullable<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub GroupKeySetID: $matter::tlv::Nullable<u16>,
            #[tagval(3)]
            pub GroupCAT: $matter::tlv::Nullable<u16>,
            #[tagval(4)]
            pub GroupCATVersion: $matter::tlv::Nullable<u16>,
            #[tagval(5)]
            pub GroupPermission: $matter::tlv::Nullable<$matter::definitions::JointFabricDatastore::types::DatastoreAccessControlEntryPrivilegeEnum>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveGroup {
            #[tagval(0)]
            pub GroupID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddAdmin {
            #[tagval(1)]
            pub NodeID: u64,
            #[tagval(2)]
            pub FriendlyName: $matter::tlv::MatterString,
            #[tagval(3)]
            pub VendorID: u16,
            #[tagval(4)]
            pub ICAC: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x7)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UpdateAdmin {
            #[tagval(0)]
            pub NodeID: $matter::tlv::Nullable<u64>,
            #[tagval(1)]
            pub FriendlyName: $matter::tlv::Nullable<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub ICAC: $matter::tlv::Nullable<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x8)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveAdmin {
            #[tagval(0)]
            pub NodeID: u64,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x9)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddPendingNode {
            #[tagval(0)]
            pub NodeID: u64,
            #[tagval(1)]
            pub FriendlyName: $matter::tlv::MatterString,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xA)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RefreshNode {
            #[tagval(0)]
            pub NodeID: u64,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xB)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UpdateNode {
            #[tagval(0)]
            pub NodeID: u64,
            #[tagval(1)]
            pub FriendlyName: $matter::tlv::MatterString,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xC)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveNode {
            #[tagval(0)]
            pub NodeID: u64,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xD)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UpdateEndpointForNode {
            #[tagval(0)]
            pub EndpointID: u16,
            #[tagval(1)]
            pub NodeID: u64,
            #[tagval(2)]
            pub FriendlyName: $matter::tlv::MatterString,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xE)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddGroupIDToEndpointForNode {
            #[tagval(0)]
            pub NodeID: u64,
            #[tagval(1)]
            pub EndpointID: u16,
            #[tagval(2)]
            pub GroupID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xF)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveGroupIDFromEndpointForNode {
            #[tagval(0)]
            pub NodeID: u64,
            #[tagval(1)]
            pub EndpointID: u16,
            #[tagval(2)]
            pub GroupID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x10)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddBindingToEndpointForNode {
            #[tagval(0)]
            pub NodeID: u64,
            #[tagval(1)]
            pub EndpointID: u16,
            #[tagval(2)]
            pub Binding: $matter::definitions::JointFabricDatastore::types::DatastoreBindingTargetStruct,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x11)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveBindingFromEndpointForNode {
            #[tagval(0)]
            pub ListID: u16,
            #[tagval(1)]
            pub EndpointID: u16,
            #[tagval(2)]
            pub NodeID: u64,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x12)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddACLToNode {
            #[tagval(0)]
            pub NodeID: u64,
            #[tagval(1)]
            pub ACLEntry: $matter::definitions::JointFabricDatastore::types::DatastoreAccessControlEntryStruct,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x13)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveACLFromNode {
            #[tagval(0)]
            pub ListID: u16,
            #[tagval(1)]
            pub NodeID: u64,
        }
    }
    pub mod events {
    }
}
pub mod OperationalState {
    pub const ID: u32 = 0x0060;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ErrorStateEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl ErrorStateEnum {
            pub const NoError: Self = Self(0x0);
            pub const UnableToStartOrResume: Self = Self(0x1);
            pub const UnableToCompleteOperation: Self = Self(0x2);
            pub const CommandInvalidInState: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OperationalStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl OperationalStateEnum {
            pub const Stopped: Self = Self(0x0);
            pub const Running: Self = Self(0x1);
            pub const Paused: Self = Self(0x2);
            pub const Error: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ErrorStateStruct {
            #[tagval(0)]
            pub ErrorStateID: $matter::definitions::OperationalState::types::ErrorStateEnum,
            #[tagval(1)]
            pub ErrorStateLabel: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub ErrorStateDetails: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalStateStruct {
            #[tagval(0)]
            pub OperationalStateID: $matter::definitions::OperationalState::types::OperationalStateEnum,
            #[tagval(1)]
            pub OperationalStateLabel: core::option::Option<$matter::tlv::MatterString>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PhaseList(pub $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::tlv::MatterString>>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentPhase(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CountdownTime(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalStateList(pub $matter::tlv::MatterList<$matter::definitions::OperationalState::types::OperationalStateStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalState(pub $matter::definitions::OperationalState::types::OperationalStateEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalError(pub $matter::definitions::OperationalState::types::ErrorStateStruct);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = OperationalCommandResponse, response_id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Pause {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1, response = OperationalCommandResponse, response_id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Stop {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = OperationalCommandResponse, response_id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Start {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3, response = OperationalCommandResponse, response_id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Resume {
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalCommandResponse {
            #[tagval(0)]
            pub CommandResponseState: $matter::definitions::OperationalState::types::ErrorStateStruct,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalError {
            #[tagval(0)]
            pub ErrorState: $matter::definitions::OperationalState::types::ErrorStateStruct,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationCompletion {
            #[tagval(0)]
            pub CompletionErrorCode: u8,
            #[tagval(1)]
            pub TotalOperationalTime: core::option::Option<$matter::tlv::Nullable<u32>>,
            #[tagval(2)]
            pub PausedTime: core::option::Option<$matter::tlv::Nullable<u32>>,
        }
    }
}
pub mod MicrowaveOvenMode {
    pub const ID: u32 = 0x005E;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ModeTag(pub u16);
        #[allow(non_upper_case_globals)]
        impl ModeTag {
            pub const Auto: Self = Self(0x0);
            pub const Quick: Self = Self(0x1);
            pub const Quiet: Self = Self(0x2);
            pub const LowNoise: Self = Self(0x3);
            pub const LowEnergy: Self = Self(0x4);
            pub const Vacation: Self = Self(0x5);
            pub const Min: Self = Self(0x6);
            pub const Max: Self = Self(0x7);
            pub const Night: Self = Self(0x8);
            pub const Day: Self = Self(0x9);
            pub const Normal: Self = Self(0x4000);
            pub const Defrost: Self = Self(0x4001);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeOptionStruct {
            #[tagval(0)]
            pub Label: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Mode: u8,
            #[tagval(2)]
            pub ModeTags: $matter::tlv::MatterList<$matter::definitions::MicrowaveOvenMode::types::ModeTagStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeTagStruct {
            #[tagval(0)]
            pub MfgCode: core::option::Option<u16>,
            #[tagval(1)]
            pub Value: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedModes(pub $matter::tlv::MatterList<$matter::definitions::MicrowaveOvenMode::types::ModeOptionStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentMode(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartUpMode(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnMode(pub $matter::tlv::Nullable<u8>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = ChangeToModeResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToMode {
            #[tagval(0)]
            pub NewMode: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToModeResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub StatusText: $matter::tlv::MatterString,
        }
    }
    pub mod events {
    }
}
pub mod LaundryDryerControls {
    pub const ID: u32 = 0x004A;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DrynessLevelEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl DrynessLevelEnum {
            pub const Low: Self = Self(0x0);
            pub const Normal: Self = Self(0x1);
            pub const Extra: Self = Self(0x2);
            pub const Max: Self = Self(0x3);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedDrynessLevels(pub $matter::tlv::MatterList<$matter::definitions::LaundryDryerControls::types::DrynessLevelEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SelectedDrynessLevel(pub $matter::tlv::Nullable<$matter::definitions::LaundryDryerControls::types::DrynessLevelEnum>);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod CommissionerControl {
    pub const ID: u32 = 0x0751;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct SupportedDeviceCategoryBitmap(pub u32);
        #[allow(non_upper_case_globals)]
        impl SupportedDeviceCategoryBitmap {
            pub const FabricSynchronization: Self = Self(0x1);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedDeviceCategories(pub $matter::definitions::CommissionerControl::types::SupportedDeviceCategoryBitmap);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RequestCommissioningApproval {
            #[tagval(0)]
            pub RequestID: u64,
            #[tagval(1)]
            pub VendorID: u16,
            #[tagval(2)]
            pub ProductID: u16,
            #[tagval(3)]
            pub Label: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1, response = ReverseOpenCommissioningWindow, response_id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CommissionNode {
            #[tagval(0)]
            pub RequestID: u64,
            #[tagval(1)]
            pub ResponseTimeoutSeconds: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ReverseOpenCommissioningWindow {
            #[tagval(0)]
            pub CommissioningTimeout: u16,
            #[tagval(1)]
            pub PAKEPasscodeVerifier: $matter::tlv::MatterBytes,
            #[tagval(2)]
            pub Discriminator: u16,
            #[tagval(3)]
            pub Iterations: u32,
            #[tagval(4)]
            pub Salt: $matter::tlv::MatterBytes,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CommissioningRequestResult {
            #[tagval(0)]
            pub RequestID: u64,
            #[tagval(1)]
            pub ClientNodeID: u64,
            #[tagval(2)]
            pub StatusCode: u8,
        }
    }
}
pub mod ModeSelect {
    pub const ID: u32 = 0x0050;
    pub mod types {
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeOptionStruct {
            #[tagval(0)]
            pub Label: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Mode: u8,
            #[tagval(2)]
            pub SemanticTags: $matter::tlv::MatterList<$matter::definitions::ModeSelect::types::SemanticTagStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SemanticTagStruct {
            #[tagval(0)]
            pub MfgCode: u16,
            #[tagval(1)]
            pub Value: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Description(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StandardNamespace(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedModes(pub $matter::tlv::MatterList<$matter::definitions::ModeSelect::types::ModeOptionStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentMode(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartUpMode(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnMode(pub $matter::tlv::Nullable<u8>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToMode {
            #[tagval(0)]
            pub NewMode: u8,
        }
    }
    pub mod events {
    }
}
pub mod PushAVStreamTransport {
    pub const ID: u32 = 0x0555;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct CMAFInterfaceEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl CMAFInterfaceEnum {
            pub const Interface1: Self = Self(0x0);
            pub const Interface2DASH: Self = Self(0x1);
            pub const Interface2HLS: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ContainerFormatEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ContainerFormatEnum {
            pub const CMAF: Self = Self(0x0);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct IngestMethodsEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl IngestMethodsEnum {
            pub const CMAFIngest: Self = Self(0x0);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusCodeEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl StatusCodeEnum {
            pub const InvalidTLSEndpoint: Self = Self(0x2);
            pub const InvalidStream: Self = Self(0x3);
            pub const InvalidURL: Self = Self(0x4);
            pub const InvalidZone: Self = Self(0x5);
            pub const InvalidCombination: Self = Self(0x6);
            pub const InvalidTriggerType: Self = Self(0x7);
            pub const InvalidTransportStatus: Self = Self(0x8);
            pub const InvalidOptions: Self = Self(0x9);
            pub const InvalidStreamUsage: Self = Self(0xA);
            pub const InvalidTime: Self = Self(0xB);
            pub const InvalidPreRollLength: Self = Self(0xC);
            pub const DuplicateStreamValues: Self = Self(0xD);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct TransportStatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl TransportStatusEnum {
            pub const Active: Self = Self(0x0);
            pub const Inactive: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct TransportTriggerTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl TransportTriggerTypeEnum {
            pub const Command: Self = Self(0x0);
            pub const Motion: Self = Self(0x1);
            pub const Continuous: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct TriggerActivationReasonEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl TriggerActivationReasonEnum {
            pub const UserInitiated: Self = Self(0x0);
            pub const Automation: Self = Self(0x1);
            pub const Emergency: Self = Self(0x2);
            pub const DoorbellPressed: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AudioStreamStruct {
            #[tagval(0)]
            pub AudioStreamName: $matter::tlv::MatterString,
            #[tagval(1)]
            pub AudioStreamID: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CMAFContainerOptionsStruct {
            #[tagval(0)]
            pub CMAFInterface: $matter::definitions::PushAVStreamTransport::types::CMAFInterfaceEnum,
            #[tagval(1)]
            pub SegmentDuration: u16,
            #[tagval(2)]
            pub ChunkDuration: u16,
            #[tagval(3)]
            pub SessionGroup: core::option::Option<u8>,
            #[tagval(4)]
            pub TrackName: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(5)]
            pub CENCKey: core::option::Option<$matter::tlv::MatterBytes>,
            #[tagval(6)]
            pub CENCKeyID: $matter::tlv::MatterBytes,
            #[tagval(7)]
            pub MetadataEnabled: core::option::Option<bool>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ContainerOptionsStruct {
            #[tagval(0)]
            pub ContainerType: $matter::definitions::PushAVStreamTransport::types::ContainerFormatEnum,
            #[tagval(1)]
            pub CMAFContainerOptions: $matter::definitions::PushAVStreamTransport::types::CMAFContainerOptionsStruct,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedFormatStruct {
            #[tagval(0)]
            pub ContainerFormat: $matter::definitions::PushAVStreamTransport::types::ContainerFormatEnum,
            #[tagval(1)]
            pub IngestMethod: $matter::definitions::PushAVStreamTransport::types::IngestMethodsEnum,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TransportConfigurationStruct {
            #[tagval(0)]
            pub ConnectionID: u16,
            #[tagval(1)]
            pub TransportStatus: $matter::definitions::PushAVStreamTransport::types::TransportStatusEnum,
            #[tagval(2)]
            pub TransportOptions: core::option::Option<$matter::definitions::PushAVStreamTransport::types::TransportOptionsStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TransportMotionTriggerTimeControlStruct {
            #[tagval(0)]
            pub InitialDuration: u16,
            #[tagval(1)]
            pub AugmentationDuration: u16,
            #[tagval(2)]
            pub MaxDuration: u32,
            #[tagval(3)]
            pub BlindDuration: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TransportOptionsStruct {
            #[tagval(0)]
            pub StreamUsage: $matter::definitions::GlobalElements::types::StreamUsageEnum,
            #[tagval(1)]
            pub VideoStreamID: core::option::Option<$matter::tlv::Nullable<u16>>,
            #[tagval(2)]
            pub AudioStreamID: core::option::Option<$matter::tlv::Nullable<u16>>,
            #[tagval(3)]
            pub TLSEndpointID: u16,
            #[tagval(4)]
            pub URL: $matter::tlv::MatterString,
            #[tagval(5)]
            pub TriggerOptions: $matter::definitions::PushAVStreamTransport::types::TransportTriggerOptionsStruct,
            #[tagval(6)]
            pub IngestMethod: $matter::definitions::PushAVStreamTransport::types::IngestMethodsEnum,
            #[tagval(7)]
            pub ContainerOptions: $matter::definitions::PushAVStreamTransport::types::ContainerOptionsStruct,
            #[tagval(8)]
            pub ExpiryTime: core::option::Option<u32>,
            #[tagval(9)]
            pub VideoStreams: core::option::Option<$matter::tlv::MatterList<$matter::definitions::PushAVStreamTransport::types::VideoStreamStruct>>,
            #[tagval(10)]
            pub AudioStreams: core::option::Option<$matter::tlv::MatterList<$matter::definitions::PushAVStreamTransport::types::AudioStreamStruct>>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TransportTriggerOptionsStruct {
            #[tagval(0)]
            pub TriggerType: $matter::definitions::PushAVStreamTransport::types::TransportTriggerTypeEnum,
            #[tagval(1)]
            pub MotionZones: $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::PushAVStreamTransport::types::TransportZoneOptionsStruct>>,
            #[tagval(2)]
            pub MotionSensitivity: core::option::Option<$matter::tlv::Nullable<u8>>,
            #[tagval(3)]
            pub MotionTimeControl: $matter::definitions::PushAVStreamTransport::types::TransportMotionTriggerTimeControlStruct,
            #[tagval(4)]
            pub MaxPreRollLen: core::option::Option<u16>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TransportZoneOptionsStruct {
            #[tagval(0)]
            pub Zone: $matter::tlv::Nullable<u16>,
            #[tagval(1)]
            pub Sensitivity: core::option::Option<u8>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct VideoStreamStruct {
            #[tagval(0)]
            pub VideoStreamName: $matter::tlv::MatterString,
            #[tagval(1)]
            pub VideoStreamID: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedFormats(pub $matter::tlv::MatterList<$matter::definitions::PushAVStreamTransport::types::SupportedFormatStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentConnections(pub $matter::tlv::MatterList<$matter::definitions::PushAVStreamTransport::types::TransportConfigurationStruct>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = AllocatePushTransportResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AllocatePushTransport {
            #[tagval(0)]
            pub TransportOptions: $matter::definitions::PushAVStreamTransport::types::TransportOptionsStruct,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AllocatePushTransportResponse {
            #[tagval(0)]
            pub TransportConfiguration: $matter::definitions::PushAVStreamTransport::types::TransportConfigurationStruct,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DeallocatePushTransport {
            #[tagval(0)]
            pub ConnectionID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModifyPushTransport {
            #[tagval(0)]
            pub ConnectionID: u16,
            #[tagval(1)]
            pub TransportOptions: $matter::definitions::PushAVStreamTransport::types::TransportOptionsStruct,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetTransportStatus {
            #[tagval(0)]
            pub ConnectionID: $matter::tlv::Nullable<u16>,
            #[tagval(1)]
            pub TransportStatus: $matter::definitions::PushAVStreamTransport::types::TransportStatusEnum,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ManuallyTriggerTransport {
            #[tagval(0)]
            pub ConnectionID: u16,
            #[tagval(1)]
            pub ActivationReason: $matter::definitions::PushAVStreamTransport::types::TriggerActivationReasonEnum,
            #[tagval(2)]
            pub TimeControl: core::option::Option<$matter::definitions::PushAVStreamTransport::types::TransportMotionTriggerTimeControlStruct>,
            #[tagval(3)]
            pub UserDefined: core::option::Option<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6, response = FindTransportResponse, response_id = 0x7)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FindTransport {
            #[tagval(0)]
            pub ConnectionID: $matter::tlv::Nullable<u16>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FindTransportResponse {
            #[tagval(0)]
            pub TransportConfigurations: $matter::tlv::MatterList<$matter::definitions::PushAVStreamTransport::types::TransportConfigurationStruct>,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PushTransportBegin {
            #[tagval(0)]
            pub ConnectionID: u16,
            #[tagval(1)]
            pub TriggerType: $matter::definitions::PushAVStreamTransport::types::TransportTriggerTypeEnum,
            #[tagval(2)]
            pub ActivationReason: $matter::definitions::PushAVStreamTransport::types::TriggerActivationReasonEnum,
            #[tagval(3)]
            pub ContainerType: $matter::definitions::PushAVStreamTransport::types::ContainerFormatEnum,
            #[tagval(4)]
            pub CMAFSessionNumber: u64,
            #[tagval(5)]
            pub VendorSpecificContext: core::option::Option<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PushTransportEnd {
            #[tagval(0)]
            pub ConnectionID: u16,
            #[tagval(1)]
            pub ContainerType: $matter::definitions::PushAVStreamTransport::types::ContainerFormatEnum,
            #[tagval(2)]
            pub CMAFSessionNumber: u64,
        }
    }
}
pub mod SoilMeasurement {
    pub const ID: u32 = 0x0430;
    pub mod types {
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SoilMoistureMeasurementLimits(pub $matter::definitions::GlobalElements::types::MeasurementAccuracyStruct);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SoilMoistureMeasuredValue(pub $matter::tlv::Nullable<u8>);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod TimeFormatLocalization {
    pub const ID: u32 = 0x002C;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct CalendarTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl CalendarTypeEnum {
            pub const Buddhist: Self = Self(0x0);
            pub const Chinese: Self = Self(0x1);
            pub const Coptic: Self = Self(0x2);
            pub const Ethiopian: Self = Self(0x3);
            pub const Gregorian: Self = Self(0x4);
            pub const Hebrew: Self = Self(0x5);
            pub const Indian: Self = Self(0x6);
            pub const Islamic: Self = Self(0x7);
            pub const Japanese: Self = Self(0x8);
            pub const Korean: Self = Self(0x9);
            pub const Persian: Self = Self(0xA);
            pub const Taiwanese: Self = Self(0xB);
            pub const UseActiveLocale: Self = Self(0xFF);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct HourFormatEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl HourFormatEnum {
            pub const _12hr: Self = Self(0x0);
            pub const _24hr: Self = Self(0x1);
            pub const UseActiveLocale: Self = Self(0xFF);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HourFormat(pub $matter::definitions::TimeFormatLocalization::types::HourFormatEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveCalendarType(pub $matter::definitions::TimeFormatLocalization::types::CalendarTypeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedCalendarTypes(pub $matter::tlv::MatterList<$matter::definitions::TimeFormatLocalization::types::CalendarTypeEnum>);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod AudioOutput {
    pub const ID: u32 = 0x050B;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OutputTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl OutputTypeEnum {
            pub const HDMI: Self = Self(0x0);
            pub const BT: Self = Self(0x1);
            pub const Optical: Self = Self(0x2);
            pub const Headphone: Self = Self(0x3);
            pub const Internal: Self = Self(0x4);
            pub const Other: Self = Self(0x5);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OutputInfoStruct {
            #[tagval(0)]
            pub Index: u8,
            #[tagval(1)]
            pub OutputType: $matter::definitions::AudioOutput::types::OutputTypeEnum,
            #[tagval(2)]
            pub Name: $matter::tlv::MatterString,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OutputList(pub $matter::tlv::MatterList<$matter::definitions::AudioOutput::types::OutputInfoStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentOutput(pub u8);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SelectOutput {
            #[tagval(0)]
            pub Index: u8,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RenameOutput {
            #[tagval(0)]
            pub Index: u8,
            #[tagval(1)]
            pub Name: $matter::tlv::MatterString,
        }
    }
    pub mod events {
    }
}
pub mod OnOff {
    pub const ID: u32 = 0x0006;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DelayedAllOffEffectVariantEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl DelayedAllOffEffectVariantEnum {
            pub const DelayedOffFastFade: Self = Self(0x0);
            pub const NoFade: Self = Self(0x1);
            pub const DelayedOffSlowFade: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DyingLightEffectVariantEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl DyingLightEffectVariantEnum {
            pub const DyingLightFadeOff: Self = Self(0x0);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct EffectIdentifierEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl EffectIdentifierEnum {
            pub const DelayedAllOff: Self = Self(0x0);
            pub const DyingLight: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StartUpOnOffEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl StartUpOnOffEnum {
            pub const Off: Self = Self(0x0);
            pub const On: Self = Self(0x1);
            pub const Toggle: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OnOffControlBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl OnOffControlBitmap {
            pub const AcceptOnlyWhenOn: Self = Self(0x1);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnOff(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4000, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GlobalSceneControl(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4001, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnTime(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4002, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OffWaitTime(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4003, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartUpOnOff(pub $matter::tlv::Nullable<$matter::definitions::OnOff::types::StartUpOnOffEnum>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Off {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct On {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Toggle {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x40)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OffWithEffect {
            #[tagval(0)]
            pub EffectIdentifier: $matter::definitions::OnOff::types::EffectIdentifierEnum,
            #[tagval(1)]
            pub EffectVariant: u8,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x41)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnWithRecallGlobalScene {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x42)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnWithTimedOff {
            #[tagval(0)]
            pub OnOffControl: $matter::definitions::OnOff::types::OnOffControlBitmap,
            #[tagval(1)]
            pub OnTime: u16,
            #[tagval(2)]
            pub OffWaitTime: u16,
        }
    }
    pub mod events {
    }
}
pub mod ColorControl {
    pub const ID: u32 = 0x0300;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ColorLoopActionEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ColorLoopActionEnum {
            pub const Deactivate: Self = Self(0x0);
            pub const ActivateFromColorLoopStartEnhancedHue: Self = Self(0x1);
            pub const ActivateFromEnhancedCurrentHue: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ColorLoopDirectionEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ColorLoopDirectionEnum {
            pub const Decrement: Self = Self(0x0);
            pub const Increment: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ColorModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ColorModeEnum {
            pub const CurrentHueAndCurrentSaturation: Self = Self(0x0);
            pub const CurrentXAndCurrentY: Self = Self(0x1);
            pub const ColorTemperatureMireds: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DirectionEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl DirectionEnum {
            pub const Shortest: Self = Self(0x0);
            pub const Longest: Self = Self(0x1);
            pub const Up: Self = Self(0x2);
            pub const Down: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DriftCompensationEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl DriftCompensationEnum {
            pub const None: Self = Self(0x0);
            pub const OtherOrUnknown: Self = Self(0x1);
            pub const TemperatureMonitoring: Self = Self(0x2);
            pub const OpticalLuminanceMonitoringAndFeedback: Self = Self(0x3);
            pub const OpticalColorMonitoringAndFeedback: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct EnhancedColorModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl EnhancedColorModeEnum {
            pub const CurrentHueAndCurrentSaturation: Self = Self(0x0);
            pub const CurrentXAndCurrentY: Self = Self(0x1);
            pub const ColorTemperatureMireds: Self = Self(0x2);
            pub const EnhancedCurrentHueAndCurrentSaturation: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MoveModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MoveModeEnum {
            pub const Stop: Self = Self(0x0);
            pub const Up: Self = Self(0x1);
            pub const Down: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StepModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl StepModeEnum {
            pub const Up: Self = Self(0x1);
            pub const Down: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ColorCapabilitiesBitmap(pub u16);
        #[allow(non_upper_case_globals)]
        impl ColorCapabilitiesBitmap {
            pub const HueSaturation: Self = Self(0x1);
            pub const EnhancedHue: Self = Self(0x2);
            pub const ColorLoop: Self = Self(0x4);
            pub const XY: Self = Self(0x8);
            pub const ColorTemperature: Self = Self(0x10);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OptionsBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl OptionsBitmap {
            pub const ExecuteIfOff: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct UpdateFlagsBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl UpdateFlagsBitmap {
            pub const UpdateAction: Self = Self(0x1);
            pub const UpdateDirection: Self = Self(0x2);
            pub const UpdateTime: Self = Self(0x4);
            pub const UpdateStartHue: Self = Self(0x8);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentHue(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentSaturation(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemainingTime(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentX(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentY(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DriftCompensation(pub $matter::definitions::ColorControl::types::DriftCompensationEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CompensationText(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorTemperatureMireds(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorMode(pub $matter::definitions::ColorControl::types::ColorModeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xF, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Options(pub $matter::definitions::ColorControl::types::OptionsBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x10, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfPrimaries(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x11, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Primary1X(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x12, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Primary1Y(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x13, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Primary1Intensity(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x15, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Primary2X(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x16, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Primary2Y(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x17, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Primary2Intensity(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x19, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Primary3X(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1A, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Primary3Y(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1B, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Primary3Intensity(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x20, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Primary4X(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x21, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Primary4Y(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x22, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Primary4Intensity(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x24, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Primary5X(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x25, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Primary5Y(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x26, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Primary5Intensity(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x28, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Primary6X(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x29, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Primary6Y(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2A, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Primary6Intensity(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x30, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WhitePointX(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x31, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WhitePointY(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x32, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorPointRX(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x33, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorPointRY(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x34, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorPointRIntensity(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x36, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorPointGX(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x37, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorPointGY(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x38, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorPointGIntensity(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3A, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorPointBX(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3B, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorPointBY(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3C, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorPointBIntensity(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4000, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnhancedCurrentHue(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4001, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnhancedColorMode(pub $matter::definitions::ColorControl::types::EnhancedColorModeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4002, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorLoopActive(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4003, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorLoopDirection(pub $matter::definitions::ColorControl::types::ColorLoopDirectionEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4004, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorLoopTime(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4005, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorLoopStartEnhancedHue(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4006, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorLoopStoredEnhancedHue(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x400A, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorCapabilities(pub $matter::definitions::ColorControl::types::ColorCapabilitiesBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x400B, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorTempPhysicalMinMireds(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x400C, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorTempPhysicalMaxMireds(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x400D, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CoupleColorTempToLevelMinMireds(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4010, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartUpColorTemperatureMireds(pub $matter::tlv::Nullable<u16>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MoveToHue {
            #[tagval(0)]
            pub Hue: u8,
            #[tagval(1)]
            pub Direction: $matter::definitions::ColorControl::types::DirectionEnum,
            #[tagval(2)]
            pub TransitionTime: u16,
            #[tagval(3)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(4)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MoveHue {
            #[tagval(0)]
            pub MoveMode: $matter::definitions::ColorControl::types::MoveModeEnum,
            #[tagval(1)]
            pub Rate: u8,
            #[tagval(2)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(3)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StepHue {
            #[tagval(0)]
            pub StepMode: $matter::definitions::ColorControl::types::StepModeEnum,
            #[tagval(1)]
            pub StepSize: u8,
            #[tagval(2)]
            pub TransitionTime: u8,
            #[tagval(3)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(4)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MoveToSaturation {
            #[tagval(0)]
            pub Saturation: u8,
            #[tagval(1)]
            pub TransitionTime: u16,
            #[tagval(2)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(3)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MoveSaturation {
            #[tagval(0)]
            pub MoveMode: $matter::definitions::ColorControl::types::MoveModeEnum,
            #[tagval(1)]
            pub Rate: u8,
            #[tagval(2)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(3)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StepSaturation {
            #[tagval(0)]
            pub StepMode: $matter::definitions::ColorControl::types::StepModeEnum,
            #[tagval(1)]
            pub StepSize: u8,
            #[tagval(2)]
            pub TransitionTime: u8,
            #[tagval(3)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(4)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MoveToHueAndSaturation {
            #[tagval(0)]
            pub Hue: u8,
            #[tagval(1)]
            pub Saturation: u8,
            #[tagval(2)]
            pub TransitionTime: u16,
            #[tagval(3)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(4)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x7)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MoveToColor {
            #[tagval(0)]
            pub ColorX: u16,
            #[tagval(1)]
            pub ColorY: u16,
            #[tagval(2)]
            pub TransitionTime: u16,
            #[tagval(3)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(4)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x8)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MoveColor {
            #[tagval(0)]
            pub RateX: i16,
            #[tagval(1)]
            pub RateY: i16,
            #[tagval(2)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(3)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x9)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StepColor {
            #[tagval(0)]
            pub StepX: i16,
            #[tagval(1)]
            pub StepY: i16,
            #[tagval(2)]
            pub TransitionTime: u16,
            #[tagval(3)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(4)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xA)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MoveToColorTemperature {
            #[tagval(0)]
            pub ColorTemperatureMireds: u16,
            #[tagval(1)]
            pub TransitionTime: u16,
            #[tagval(2)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(3)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x40)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnhancedMoveToHue {
            #[tagval(0)]
            pub EnhancedHue: u16,
            #[tagval(1)]
            pub Direction: $matter::definitions::ColorControl::types::DirectionEnum,
            #[tagval(2)]
            pub TransitionTime: u16,
            #[tagval(3)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(4)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x41)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnhancedMoveHue {
            #[tagval(0)]
            pub MoveMode: $matter::definitions::ColorControl::types::MoveModeEnum,
            #[tagval(1)]
            pub Rate: u16,
            #[tagval(2)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(3)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x42)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnhancedStepHue {
            #[tagval(0)]
            pub StepMode: $matter::definitions::ColorControl::types::StepModeEnum,
            #[tagval(1)]
            pub StepSize: u16,
            #[tagval(2)]
            pub TransitionTime: u16,
            #[tagval(3)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(4)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x43)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnhancedMoveToHueAndSaturation {
            #[tagval(0)]
            pub EnhancedHue: u16,
            #[tagval(1)]
            pub Saturation: u8,
            #[tagval(2)]
            pub TransitionTime: u16,
            #[tagval(3)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(4)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x44)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ColorLoopSet {
            #[tagval(0)]
            pub UpdateFlags: $matter::definitions::ColorControl::types::UpdateFlagsBitmap,
            #[tagval(1)]
            pub Action: $matter::definitions::ColorControl::types::ColorLoopActionEnum,
            #[tagval(2)]
            pub Direction: $matter::definitions::ColorControl::types::ColorLoopDirectionEnum,
            #[tagval(3)]
            pub Time: u16,
            #[tagval(4)]
            pub StartHue: u16,
            #[tagval(5)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(6)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x47)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StopMoveStep {
            #[tagval(0)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(1)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4B)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MoveColorTemperature {
            #[tagval(0)]
            pub MoveMode: $matter::definitions::ColorControl::types::MoveModeEnum,
            #[tagval(1)]
            pub Rate: u16,
            #[tagval(2)]
            pub ColorTemperatureMinimumMireds: u16,
            #[tagval(3)]
            pub ColorTemperatureMaximumMireds: u16,
            #[tagval(4)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(5)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4C)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StepColorTemperature {
            #[tagval(0)]
            pub StepMode: $matter::definitions::ColorControl::types::StepModeEnum,
            #[tagval(1)]
            pub StepSize: u16,
            #[tagval(2)]
            pub TransitionTime: u16,
            #[tagval(3)]
            pub ColorTemperatureMinimumMireds: u16,
            #[tagval(4)]
            pub ColorTemperatureMaximumMireds: u16,
            #[tagval(5)]
            pub OptionsMask: $matter::definitions::ColorControl::types::OptionsBitmap,
            #[tagval(6)]
            pub OptionsOverride: $matter::definitions::ColorControl::types::OptionsBitmap,
        }
    }
    pub mod events {
    }
}
pub mod PM10ConcentrationMeasurement {
    pub const ID: u32 = 0x042D;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LevelValueEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl LevelValueEnum {
            pub const Unknown: Self = Self(0x0);
            pub const Low: Self = Self(0x1);
            pub const Medium: Self = Self(0x2);
            pub const High: Self = Self(0x3);
            pub const Critical: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementMediumEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementMediumEnum {
            pub const Air: Self = Self(0x0);
            pub const Water: Self = Self(0x1);
            pub const Soil: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementUnitEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementUnitEnum {
            pub const PPM: Self = Self(0x0);
            pub const PPB: Self = Self(0x1);
            pub const PPT: Self = Self(0x2);
            pub const MGM3: Self = Self(0x3);
            pub const UGM3: Self = Self(0x4);
            pub const NGM3: Self = Self(0x5);
            pub const PM3: Self = Self(0x6);
            pub const BQM3: Self = Self(0x7);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Uncertainty(pub f32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementUnit(pub $matter::definitions::PM10ConcentrationMeasurement::types::MeasurementUnitEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementMedium(pub $matter::definitions::PM10ConcentrationMeasurement::types::MeasurementMediumEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LevelValue(pub $matter::definitions::PM10ConcentrationMeasurement::types::LevelValueEnum);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod OTASoftwareUpdateProvider {
    pub const ID: u32 = 0x0029;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ApplyUpdateActionEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ApplyUpdateActionEnum {
            pub const Proceed: Self = Self(0x0);
            pub const AwaitNextAction: Self = Self(0x1);
            pub const Discontinue: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DownloadProtocolEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl DownloadProtocolEnum {
            pub const BDXSynchronous: Self = Self(0x0);
            pub const BDXAsynchronous: Self = Self(0x1);
            pub const HTTPS: Self = Self(0x2);
            pub const VendorSpecific: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl StatusEnum {
            pub const UpdateAvailable: Self = Self(0x0);
            pub const Busy: Self = Self(0x1);
            pub const NotAvailable: Self = Self(0x2);
            pub const DownloadProtocolNotSupported: Self = Self(0x3);
        }
    }
    pub mod attributes {
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = QueryImageResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct QueryImage {
            #[tagval(0)]
            pub VendorID: u16,
            #[tagval(1)]
            pub ProductID: u16,
            #[tagval(2)]
            pub SoftwareVersion: u32,
            #[tagval(3)]
            pub ProtocolsSupported: $matter::tlv::MatterList<$matter::definitions::OTASoftwareUpdateProvider::types::DownloadProtocolEnum>,
            #[tagval(4)]
            pub HardwareVersion: core::option::Option<u16>,
            #[tagval(5)]
            pub Location: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(6)]
            pub RequestorCanConsent: core::option::Option<bool>,
            #[tagval(7)]
            pub MetadataForProvider: core::option::Option<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct QueryImageResponse {
            #[tagval(0)]
            pub Status: $matter::definitions::OTASoftwareUpdateProvider::types::StatusEnum,
            #[tagval(1)]
            pub DelayedActionTime: u32,
            #[tagval(2)]
            pub ImageURI: $matter::tlv::MatterString,
            #[tagval(3)]
            pub SoftwareVersion: u32,
            #[tagval(4)]
            pub SoftwareVersionString: $matter::tlv::MatterString,
            #[tagval(5)]
            pub UpdateToken: $matter::tlv::MatterBytes,
            #[tagval(6)]
            pub UserConsentNeeded: core::option::Option<bool>,
            #[tagval(7)]
            pub MetadataForRequestor: core::option::Option<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = ApplyUpdateResponse, response_id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ApplyUpdateRequest {
            #[tagval(0)]
            pub UpdateToken: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub NewVersion: u32,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ApplyUpdateResponse {
            #[tagval(0)]
            pub Action: $matter::definitions::OTASoftwareUpdateProvider::types::ApplyUpdateActionEnum,
            #[tagval(1)]
            pub DelayedActionTime: u32,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NotifyUpdateApplied {
            #[tagval(0)]
            pub UpdateToken: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub SoftwareVersion: u32,
        }
    }
    pub mod events {
    }
}
pub mod DishwasherAlarm {
    pub const ID: u32 = 0x005D;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct AlarmBitmap(pub u32);
        #[allow(non_upper_case_globals)]
        impl AlarmBitmap {
            pub const InflowError: Self = Self(0x1);
            pub const DrainError: Self = Self(0x2);
            pub const DoorError: Self = Self(0x4);
            pub const TempTooLow: Self = Self(0x8);
            pub const TempTooHigh: Self = Self(0x10);
            pub const WaterLevelError: Self = Self(0x20);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Mask(pub $matter::definitions::DishwasherAlarm::types::AlarmBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Latch(pub $matter::definitions::DishwasherAlarm::types::AlarmBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct State(pub $matter::definitions::DishwasherAlarm::types::AlarmBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Supported(pub $matter::definitions::DishwasherAlarm::types::AlarmBitmap);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Reset {
            #[tagval(0)]
            pub Alarms: $matter::definitions::DishwasherAlarm::types::AlarmBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModifyEnabledAlarms {
            #[tagval(0)]
            pub Mask: $matter::definitions::DishwasherAlarm::types::AlarmBitmap,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Notify {
            #[tagval(0)]
            pub Active: $matter::definitions::DishwasherAlarm::types::AlarmBitmap,
            #[tagval(1)]
            pub Inactive: $matter::definitions::DishwasherAlarm::types::AlarmBitmap,
            #[tagval(2)]
            pub State: $matter::definitions::DishwasherAlarm::types::AlarmBitmap,
            #[tagval(3)]
            pub Mask: $matter::definitions::DishwasherAlarm::types::AlarmBitmap,
        }
    }
}
pub mod SmokeCOAlarm {
    pub const ID: u32 = 0x005C;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct AlarmStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl AlarmStateEnum {
            pub const Normal: Self = Self(0x0);
            pub const Warning: Self = Self(0x1);
            pub const Critical: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ContaminationStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ContaminationStateEnum {
            pub const Normal: Self = Self(0x0);
            pub const Low: Self = Self(0x1);
            pub const Warning: Self = Self(0x2);
            pub const Critical: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct EndOfServiceEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl EndOfServiceEnum {
            pub const Normal: Self = Self(0x0);
            pub const Expired: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ExpressedStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ExpressedStateEnum {
            pub const Normal: Self = Self(0x0);
            pub const SmokeAlarm: Self = Self(0x1);
            pub const COAlarm: Self = Self(0x2);
            pub const BatteryAlert: Self = Self(0x3);
            pub const Testing: Self = Self(0x4);
            pub const HardwareFault: Self = Self(0x5);
            pub const EndOfService: Self = Self(0x6);
            pub const InterconnectSmoke: Self = Self(0x7);
            pub const InterconnectCO: Self = Self(0x8);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MuteStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MuteStateEnum {
            pub const NotMuted: Self = Self(0x0);
            pub const Muted: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct SensitivityEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl SensitivityEnum {
            pub const High: Self = Self(0x0);
            pub const Standard: Self = Self(0x1);
            pub const Low: Self = Self(0x2);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ExpressedState(pub $matter::definitions::SmokeCOAlarm::types::ExpressedStateEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SmokeState(pub $matter::definitions::SmokeCOAlarm::types::AlarmStateEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct COState(pub $matter::definitions::SmokeCOAlarm::types::AlarmStateEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatteryAlert(pub $matter::definitions::SmokeCOAlarm::types::AlarmStateEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DeviceMuted(pub $matter::definitions::SmokeCOAlarm::types::MuteStateEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TestInProgress(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HardwareFaultAlert(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EndOfServiceAlert(pub $matter::definitions::SmokeCOAlarm::types::EndOfServiceEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct InterconnectSmokeAlarm(pub $matter::definitions::SmokeCOAlarm::types::AlarmStateEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct InterconnectCOAlarm(pub $matter::definitions::SmokeCOAlarm::types::AlarmStateEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ContaminationState(pub $matter::definitions::SmokeCOAlarm::types::ContaminationStateEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xB, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SmokeSensitivityLevel(pub $matter::definitions::SmokeCOAlarm::types::SensitivityEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xC, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ExpiryDate(pub u32);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SelfTestRequest {
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SmokeAlarm {
            #[tagval(0)]
            pub AlarmSeverityLevel: $matter::definitions::SmokeCOAlarm::types::AlarmStateEnum,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct COAlarm {
            #[tagval(0)]
            pub AlarmSeverityLevel: $matter::definitions::SmokeCOAlarm::types::AlarmStateEnum,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LowBattery {
            #[tagval(0)]
            pub AlarmSeverityLevel: $matter::definitions::SmokeCOAlarm::types::AlarmStateEnum,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HardwareFault {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EndOfService {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SelfTestComplete {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x6)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AlarmMuted {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x7)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MuteEnded {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x8)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct InterconnectSmokeAlarm {
            #[tagval(0)]
            pub AlarmSeverityLevel: $matter::definitions::SmokeCOAlarm::types::AlarmStateEnum,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x9)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct InterconnectCOAlarm {
            #[tagval(0)]
            pub AlarmSeverityLevel: $matter::definitions::SmokeCOAlarm::types::AlarmStateEnum,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0xA)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AllClear {
        }
    }
}
pub mod WiFiNetworkManagement {
    pub const ID: u32 = 0x0451;
    pub mod types {
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SSID(pub $matter::tlv::Nullable<$matter::tlv::MatterBytes>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PassphraseSurrogate(pub $matter::tlv::Nullable<u64>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = NetworkPassphraseResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NetworkPassphraseRequest {
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NetworkPassphraseResponse {
            #[tagval(0)]
            pub Passphrase: $matter::tlv::MatterBytes,
        }
    }
    pub mod events {
    }
}
pub mod CameraAVSettingsUserLevelManagement {
    pub const ID: u32 = 0x0552;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct PhysicalMovementEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl PhysicalMovementEnum {
            pub const Idle: Self = Self(0x0);
            pub const Moving: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DPTZStruct {
            #[tagval(0)]
            pub VideoStreamID: u16,
            #[tagval(1)]
            pub Viewport: $matter::definitions::GlobalElements::types::ViewportStruct,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MPTZPresetStruct {
            #[tagval(0)]
            pub PresetID: u8,
            #[tagval(1)]
            pub Name: $matter::tlv::MatterString,
            #[tagval(2)]
            pub Settings: $matter::definitions::CameraAVSettingsUserLevelManagement::types::MPTZStruct,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MPTZStruct {
            #[tagval(0)]
            pub Pan: core::option::Option<i16>,
            #[tagval(1)]
            pub Tilt: core::option::Option<i16>,
            #[tagval(2)]
            pub Zoom: core::option::Option<u8>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MPTZPosition(pub $matter::definitions::CameraAVSettingsUserLevelManagement::types::MPTZStruct);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxPresets(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MPTZPresets(pub $matter::tlv::MatterList<$matter::definitions::CameraAVSettingsUserLevelManagement::types::MPTZPresetStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DPTZStreams(pub $matter::tlv::MatterList<$matter::definitions::CameraAVSettingsUserLevelManagement::types::DPTZStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ZoomMax(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TiltMin(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TiltMax(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PanMin(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PanMax(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MovementState(pub $matter::definitions::CameraAVSettingsUserLevelManagement::types::PhysicalMovementEnum);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MPTZSetPosition {
            #[tagval(0)]
            pub Pan: core::option::Option<i16>,
            #[tagval(1)]
            pub Tilt: core::option::Option<i16>,
            #[tagval(2)]
            pub Zoom: core::option::Option<u8>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MPTZRelativeMove {
            #[tagval(0)]
            pub PanDelta: core::option::Option<i16>,
            #[tagval(1)]
            pub TiltDelta: core::option::Option<i16>,
            #[tagval(2)]
            pub ZoomDelta: core::option::Option<i8>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MPTZMoveToPreset {
            #[tagval(0)]
            pub PresetID: u8,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MPTZSavePreset {
            #[tagval(0)]
            pub PresetID: core::option::Option<u8>,
            #[tagval(1)]
            pub Name: $matter::tlv::MatterString,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MPTZRemovePreset {
            #[tagval(0)]
            pub PresetID: u8,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DPTZSetViewport {
            #[tagval(0)]
            pub VideoStreamID: u16,
            #[tagval(1)]
            pub Viewport: $matter::definitions::GlobalElements::types::ViewportStruct,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DPTZRelativeMove {
            #[tagval(0)]
            pub VideoStreamID: u16,
            #[tagval(1)]
            pub DeltaX: core::option::Option<i16>,
            #[tagval(2)]
            pub DeltaY: core::option::Option<i16>,
            #[tagval(3)]
            pub ZoomDelta: core::option::Option<i8>,
        }
    }
    pub mod events {
    }
}
pub mod Messages {
    pub const ID: u32 = 0x0097;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct FutureMessagePreferenceEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl FutureMessagePreferenceEnum {
            pub const Allowed: Self = Self(0x0);
            pub const Increased: Self = Self(0x1);
            pub const Reduced: Self = Self(0x2);
            pub const Disallowed: Self = Self(0x3);
            pub const Banned: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MessagePriorityEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MessagePriorityEnum {
            pub const Low: Self = Self(0x0);
            pub const Medium: Self = Self(0x1);
            pub const High: Self = Self(0x2);
            pub const Critical: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MessageControlBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl MessageControlBitmap {
            pub const ConfirmationRequired: Self = Self(0x1);
            pub const ResponseRequired: Self = Self(0x2);
            pub const ReplyMessage: Self = Self(0x4);
            pub const MessageConfirmed: Self = Self(0x8);
            pub const MessageProtected: Self = Self(0x10);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MessageResponseOptionStruct {
            #[tagval(0)]
            pub MessageResponseID: u32,
            #[tagval(1)]
            pub Label: $matter::tlv::MatterString,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MessageStruct {
            #[tagval(0)]
            pub MessageID: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub Priority: $matter::definitions::Messages::types::MessagePriorityEnum,
            #[tagval(2)]
            pub MessageControl: $matter::definitions::Messages::types::MessageControlBitmap,
            #[tagval(3)]
            pub StartTime: $matter::tlv::Nullable<u32>,
            #[tagval(4)]
            pub Duration: $matter::tlv::Nullable<u64>,
            #[tagval(5)]
            pub MessageText: $matter::tlv::MatterString,
            #[tagval(6)]
            pub Responses: core::option::Option<$matter::tlv::MatterList<$matter::definitions::Messages::types::MessageResponseOptionStruct>>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Messages(pub $matter::tlv::MatterList<$matter::definitions::Messages::types::MessageStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveMessageIDs(pub $matter::tlv::MatterList<$matter::tlv::MatterBytes>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PresentMessagesRequest {
            #[tagval(0)]
            pub MessageID: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub Priority: $matter::definitions::Messages::types::MessagePriorityEnum,
            #[tagval(2)]
            pub MessageControl: $matter::definitions::Messages::types::MessageControlBitmap,
            #[tagval(3)]
            pub StartTime: $matter::tlv::Nullable<u32>,
            #[tagval(4)]
            pub Duration: $matter::tlv::Nullable<u64>,
            #[tagval(5)]
            pub MessageText: $matter::tlv::MatterString,
            #[tagval(6)]
            pub Responses: core::option::Option<$matter::tlv::MatterList<$matter::definitions::Messages::types::MessageResponseOptionStruct>>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CancelMessagesRequest {
            #[tagval(0)]
            pub MessageIDs: $matter::tlv::MatterList<$matter::tlv::MatterBytes>,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MessageQueued {
            #[tagval(0)]
            pub MessageID: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MessagePresented {
            #[tagval(0)]
            pub MessageID: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MessageComplete {
            #[tagval(0)]
            pub MessageID: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub ResponseID: core::option::Option<$matter::tlv::Nullable<u32>>,
            #[tagval(2)]
            pub Reply: core::option::Option<$matter::tlv::Nullable<$matter::tlv::MatterString>>,
            #[tagval(3)]
            pub FutureMessagesPreference: $matter::tlv::Nullable<$matter::definitions::Messages::types::FutureMessagePreferenceEnum>,
        }
    }
}
pub mod CarbonDioxideConcentrationMeasurement {
    pub const ID: u32 = 0x040D;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LevelValueEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl LevelValueEnum {
            pub const Unknown: Self = Self(0x0);
            pub const Low: Self = Self(0x1);
            pub const Medium: Self = Self(0x2);
            pub const High: Self = Self(0x3);
            pub const Critical: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementMediumEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementMediumEnum {
            pub const Air: Self = Self(0x0);
            pub const Water: Self = Self(0x1);
            pub const Soil: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementUnitEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementUnitEnum {
            pub const PPM: Self = Self(0x0);
            pub const PPB: Self = Self(0x1);
            pub const PPT: Self = Self(0x2);
            pub const MGM3: Self = Self(0x3);
            pub const UGM3: Self = Self(0x4);
            pub const NGM3: Self = Self(0x5);
            pub const PM3: Self = Self(0x6);
            pub const BQM3: Self = Self(0x7);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Uncertainty(pub f32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementUnit(pub $matter::definitions::CarbonDioxideConcentrationMeasurement::types::MeasurementUnitEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementMedium(pub $matter::definitions::CarbonDioxideConcentrationMeasurement::types::MeasurementMediumEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LevelValue(pub $matter::definitions::CarbonDioxideConcentrationMeasurement::types::LevelValueEnum);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod AccountLogin {
    pub const ID: u32 = 0x050E;
    pub mod types {
    }
    pub mod attributes {
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = GetSetupPINResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetSetupPIN {
            #[tagval(0)]
            pub TempAccountIdentifier: $matter::tlv::MatterString,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetSetupPINResponse {
            #[tagval(0)]
            pub SetupPIN: $matter::tlv::MatterString,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Login {
            #[tagval(0)]
            pub TempAccountIdentifier: $matter::tlv::MatterString,
            #[tagval(1)]
            pub SetupPIN: $matter::tlv::MatterString,
            #[tagval(2)]
            pub Node: core::option::Option<u64>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Logout {
            #[tagval(0)]
            pub Node: core::option::Option<u64>,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LoggedOut {
            #[tagval(0)]
            pub Node: core::option::Option<u64>,
        }
    }
}
pub mod RVCCleanMode {
    pub const ID: u32 = 0x0055;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ModeTag(pub u16);
        #[allow(non_upper_case_globals)]
        impl ModeTag {
            pub const Auto: Self = Self(0x0);
            pub const Quick: Self = Self(0x1);
            pub const Quiet: Self = Self(0x2);
            pub const LowNoise: Self = Self(0x3);
            pub const LowEnergy: Self = Self(0x4);
            pub const Vacation: Self = Self(0x5);
            pub const Min: Self = Self(0x6);
            pub const Max: Self = Self(0x7);
            pub const Night: Self = Self(0x8);
            pub const Day: Self = Self(0x9);
            pub const DeepClean: Self = Self(0x4000);
            pub const Vacuum: Self = Self(0x4001);
            pub const Mop: Self = Self(0x4002);
            pub const VacuumthenMop: Self = Self(0x4003);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusCodeEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl StatusCodeEnum {
            pub const CleaningInProgress: Self = Self(0x40);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeOptionStruct {
            #[tagval(0)]
            pub Label: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Mode: u8,
            #[tagval(2)]
            pub ModeTags: $matter::tlv::MatterList<$matter::definitions::RVCCleanMode::types::ModeTagStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeTagStruct {
            #[tagval(0)]
            pub MfgCode: core::option::Option<u16>,
            #[tagval(1)]
            pub Value: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedModes(pub $matter::tlv::MatterList<$matter::definitions::RVCCleanMode::types::ModeOptionStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentMode(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartUpMode(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnMode(pub $matter::tlv::Nullable<u8>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = ChangeToModeResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToMode {
            #[tagval(0)]
            pub NewMode: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToModeResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub StatusText: $matter::tlv::MatterString,
        }
    }
    pub mod events {
    }
}
pub mod ElectricalPowerMeasurement {
    pub const ID: u32 = 0x0090;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementTypeEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl MeasurementTypeEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const Voltage: Self = Self(0x1);
            pub const ActiveCurrent: Self = Self(0x2);
            pub const ReactiveCurrent: Self = Self(0x3);
            pub const ApparentCurrent: Self = Self(0x4);
            pub const ActivePower: Self = Self(0x5);
            pub const ReactivePower: Self = Self(0x6);
            pub const ApparentPower: Self = Self(0x7);
            pub const RMSVoltage: Self = Self(0x8);
            pub const RMSCurrent: Self = Self(0x9);
            pub const RMSPower: Self = Self(0xA);
            pub const Frequency: Self = Self(0xB);
            pub const PowerFactor: Self = Self(0xC);
            pub const NeutralCurrent: Self = Self(0xD);
            pub const ElectricalEnergy: Self = Self(0xE);
            pub const ReactiveEnergy: Self = Self(0xF);
            pub const ApparentEnergy: Self = Self(0x10);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct PowerModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl PowerModeEnum {
            pub const Unknown: Self = Self(0x0);
            pub const DC: Self = Self(0x1);
            pub const AC: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HarmonicMeasurementStruct {
            #[tagval(0)]
            pub Order: u8,
            #[tagval(1)]
            pub Measurement: $matter::tlv::Nullable<i64>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementAccuracyRangeStruct {
            #[tagval(0)]
            pub RangeMin: i64,
            #[tagval(1)]
            pub RangeMax: i64,
            #[tagval(2)]
            pub PercentMax: core::option::Option<u16>,
            #[tagval(3)]
            pub PercentMin: core::option::Option<u16>,
            #[tagval(4)]
            pub PercentTypical: core::option::Option<u16>,
            #[tagval(5)]
            pub FixedMax: core::option::Option<u64>,
            #[tagval(6)]
            pub FixedMin: core::option::Option<u64>,
            #[tagval(7)]
            pub FixedTypical: core::option::Option<u64>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementAccuracyStruct {
            #[tagval(0)]
            pub MeasurementType: $matter::definitions::ElectricalPowerMeasurement::types::MeasurementTypeEnum,
            #[tagval(1)]
            pub Measured: bool,
            #[tagval(2)]
            pub MinMeasuredValue: i64,
            #[tagval(3)]
            pub MaxMeasuredValue: i64,
            #[tagval(4)]
            pub AccuracyRanges: $matter::tlv::MatterList<$matter::definitions::ElectricalPowerMeasurement::types::MeasurementAccuracyRangeStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementRangeStruct {
            #[tagval(0)]
            pub MeasurementType: $matter::definitions::ElectricalPowerMeasurement::types::MeasurementTypeEnum,
            #[tagval(1)]
            pub Min: i64,
            #[tagval(2)]
            pub Max: i64,
            #[tagval(3)]
            pub StartTimestamp: u32,
            #[tagval(4)]
            pub EndTimestamp: u32,
            #[tagval(5)]
            pub MinTimestamp: u32,
            #[tagval(6)]
            pub MaxTimestamp: u32,
            #[tagval(7)]
            pub StartSystime: u64,
            #[tagval(8)]
            pub EndSystime: u64,
            #[tagval(9)]
            pub MinSystime: u64,
            #[tagval(10)]
            pub MaxSystime: u64,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PowerMode(pub $matter::definitions::ElectricalPowerMeasurement::types::PowerModeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfMeasurementTypes(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Accuracy(pub $matter::tlv::MatterList<$matter::definitions::ElectricalPowerMeasurement::types::MeasurementAccuracyStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Ranges(pub $matter::tlv::MatterList<$matter::definitions::ElectricalPowerMeasurement::types::MeasurementRangeStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Voltage(pub $matter::tlv::Nullable<i64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveCurrent(pub $matter::tlv::Nullable<i64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ReactiveCurrent(pub $matter::tlv::Nullable<i64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ApparentCurrent(pub $matter::tlv::Nullable<i64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActivePower(pub $matter::tlv::Nullable<i64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ReactivePower(pub $matter::tlv::Nullable<i64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ApparentPower(pub $matter::tlv::Nullable<i64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xB, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RMSVoltage(pub $matter::tlv::Nullable<i64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xC, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RMSCurrent(pub $matter::tlv::Nullable<i64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xD, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RMSPower(pub $matter::tlv::Nullable<i64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xE, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Frequency(pub $matter::tlv::Nullable<i64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xF, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HarmonicCurrents(pub $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::ElectricalPowerMeasurement::types::HarmonicMeasurementStruct>>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x10, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HarmonicPhases(pub $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::ElectricalPowerMeasurement::types::HarmonicMeasurementStruct>>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x11, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PowerFactor(pub $matter::tlv::Nullable<i64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x12, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NeutralCurrent(pub $matter::tlv::Nullable<i64>);
    }
    pub mod commands {
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementPeriodRanges {
            #[tagval(0)]
            pub Ranges: $matter::tlv::MatterList<$matter::definitions::ElectricalPowerMeasurement::types::MeasurementRangeStruct>,
        }
    }
}
pub mod FixedLabel {
    pub const ID: u32 = 0x0040;
    pub mod types {
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LabelStruct {
            #[tagval(0)]
            pub Label: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Value: $matter::tlv::MatterString,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LabelList(pub $matter::tlv::MatterList<$matter::definitions::FixedLabel::types::LabelStruct>);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod UnitLocalization {
    pub const ID: u32 = 0x002D;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct TempUnitEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl TempUnitEnum {
            pub const Fahrenheit: Self = Self(0x0);
            pub const Celsius: Self = Self(0x1);
            pub const Kelvin: Self = Self(0x2);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TemperatureUnit(pub $matter::definitions::UnitLocalization::types::TempUnitEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedTemperatureUnits(pub $matter::tlv::MatterList<$matter::definitions::UnitLocalization::types::TempUnitEnum>);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod PowerSource {
    pub const ID: u32 = 0x002F;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct BatApprovedChemistryEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl BatApprovedChemistryEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const Alkaline: Self = Self(0x1);
            pub const LithiumCarbonFluoride: Self = Self(0x2);
            pub const LithiumChromiumOxide: Self = Self(0x3);
            pub const LithiumCopperOxide: Self = Self(0x4);
            pub const LithiumIronDisulfide: Self = Self(0x5);
            pub const LithiumManganeseDioxide: Self = Self(0x6);
            pub const LithiumThionylChloride: Self = Self(0x7);
            pub const Magnesium: Self = Self(0x8);
            pub const MercuryOxide: Self = Self(0x9);
            pub const NickelOxyhydride: Self = Self(0xA);
            pub const SilverOxide: Self = Self(0xB);
            pub const ZincAir: Self = Self(0xC);
            pub const ZincCarbon: Self = Self(0xD);
            pub const ZincChloride: Self = Self(0xE);
            pub const ZincManganeseDioxide: Self = Self(0xF);
            pub const LeadAcid: Self = Self(0x10);
            pub const LithiumCobaltOxide: Self = Self(0x11);
            pub const LithiumIon: Self = Self(0x12);
            pub const LithiumIonPolymer: Self = Self(0x13);
            pub const LithiumIronPhosphate: Self = Self(0x14);
            pub const LithiumSulfur: Self = Self(0x15);
            pub const LithiumTitanate: Self = Self(0x16);
            pub const NickelCadmium: Self = Self(0x17);
            pub const NickelHydrogen: Self = Self(0x18);
            pub const NickelIron: Self = Self(0x19);
            pub const NickelMetalHydride: Self = Self(0x1A);
            pub const NickelZinc: Self = Self(0x1B);
            pub const SilverZinc: Self = Self(0x1C);
            pub const SodiumIon: Self = Self(0x1D);
            pub const SodiumSulfur: Self = Self(0x1E);
            pub const ZincBromide: Self = Self(0x1F);
            pub const ZincCerium: Self = Self(0x20);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct BatChargeFaultEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl BatChargeFaultEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const AmbientTooHot: Self = Self(0x1);
            pub const AmbientTooCold: Self = Self(0x2);
            pub const BatteryTooHot: Self = Self(0x3);
            pub const BatteryTooCold: Self = Self(0x4);
            pub const BatteryAbsent: Self = Self(0x5);
            pub const BatteryOverVoltage: Self = Self(0x6);
            pub const BatteryUnderVoltage: Self = Self(0x7);
            pub const ChargerOverVoltage: Self = Self(0x8);
            pub const ChargerUnderVoltage: Self = Self(0x9);
            pub const SafetyTimeout: Self = Self(0xA);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct BatChargeLevelEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl BatChargeLevelEnum {
            pub const OK: Self = Self(0x0);
            pub const Warning: Self = Self(0x1);
            pub const Critical: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct BatChargeStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl BatChargeStateEnum {
            pub const Unknown: Self = Self(0x0);
            pub const IsCharging: Self = Self(0x1);
            pub const IsAtFullCharge: Self = Self(0x2);
            pub const IsNotCharging: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct BatCommonDesignationEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl BatCommonDesignationEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const AAA: Self = Self(0x1);
            pub const AA: Self = Self(0x2);
            pub const C: Self = Self(0x3);
            pub const D: Self = Self(0x4);
            pub const _4v5: Self = Self(0x5);
            pub const _6v0: Self = Self(0x6);
            pub const _9v0: Self = Self(0x7);
            pub const _1_2AA: Self = Self(0x8);
            pub const AAAA: Self = Self(0x9);
            pub const A: Self = Self(0xA);
            pub const B: Self = Self(0xB);
            pub const F: Self = Self(0xC);
            pub const N: Self = Self(0xD);
            pub const No6: Self = Self(0xE);
            pub const SubC: Self = Self(0xF);
            pub const A23: Self = Self(0x10);
            pub const A27: Self = Self(0x11);
            pub const BA5800: Self = Self(0x12);
            pub const Duplex: Self = Self(0x13);
            pub const _4SR44: Self = Self(0x14);
            pub const _523: Self = Self(0x15);
            pub const _531: Self = Self(0x16);
            pub const _15v0: Self = Self(0x17);
            pub const _22v5: Self = Self(0x18);
            pub const _30v0: Self = Self(0x19);
            pub const _45v0: Self = Self(0x1A);
            pub const _67v5: Self = Self(0x1B);
            pub const J: Self = Self(0x1C);
            pub const CR123A: Self = Self(0x1D);
            pub const CR2: Self = Self(0x1E);
            pub const _2CR5: Self = Self(0x1F);
            pub const CR_P2: Self = Self(0x20);
            pub const CR_V3: Self = Self(0x21);
            pub const SR41: Self = Self(0x22);
            pub const SR43: Self = Self(0x23);
            pub const SR44: Self = Self(0x24);
            pub const SR45: Self = Self(0x25);
            pub const SR48: Self = Self(0x26);
            pub const SR54: Self = Self(0x27);
            pub const SR55: Self = Self(0x28);
            pub const SR57: Self = Self(0x29);
            pub const SR58: Self = Self(0x2A);
            pub const SR59: Self = Self(0x2B);
            pub const SR60: Self = Self(0x2C);
            pub const SR63: Self = Self(0x2D);
            pub const SR64: Self = Self(0x2E);
            pub const SR65: Self = Self(0x2F);
            pub const SR66: Self = Self(0x30);
            pub const SR67: Self = Self(0x31);
            pub const SR68: Self = Self(0x32);
            pub const SR69: Self = Self(0x33);
            pub const SR516: Self = Self(0x34);
            pub const SR731: Self = Self(0x35);
            pub const SR712: Self = Self(0x36);
            pub const LR932: Self = Self(0x37);
            pub const A5: Self = Self(0x38);
            pub const A10: Self = Self(0x39);
            pub const A13: Self = Self(0x3A);
            pub const A312: Self = Self(0x3B);
            pub const A675: Self = Self(0x3C);
            pub const AC41E: Self = Self(0x3D);
            pub const _10180: Self = Self(0x3E);
            pub const _10280: Self = Self(0x3F);
            pub const _10440: Self = Self(0x40);
            pub const _14250: Self = Self(0x41);
            pub const _14430: Self = Self(0x42);
            pub const _14500: Self = Self(0x43);
            pub const _14650: Self = Self(0x44);
            pub const _15270: Self = Self(0x45);
            pub const _16340: Self = Self(0x46);
            pub const RCR123A: Self = Self(0x47);
            pub const _17500: Self = Self(0x48);
            pub const _17670: Self = Self(0x49);
            pub const _18350: Self = Self(0x4A);
            pub const _18500: Self = Self(0x4B);
            pub const _18650: Self = Self(0x4C);
            pub const _19670: Self = Self(0x4D);
            pub const _25500: Self = Self(0x4E);
            pub const _26650: Self = Self(0x4F);
            pub const _32600: Self = Self(0x50);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct BatFaultEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl BatFaultEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const OverTemp: Self = Self(0x1);
            pub const UnderTemp: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct BatReplaceabilityEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl BatReplaceabilityEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const NotReplaceable: Self = Self(0x1);
            pub const UserReplaceable: Self = Self(0x2);
            pub const FactoryReplaceable: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct PowerSourceStatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl PowerSourceStatusEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const Active: Self = Self(0x1);
            pub const Standby: Self = Self(0x2);
            pub const Unavailable: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct WiredCurrentTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl WiredCurrentTypeEnum {
            pub const AC: Self = Self(0x0);
            pub const DC: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct WiredFaultEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl WiredFaultEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const OverVoltage: Self = Self(0x1);
            pub const UnderVoltage: Self = Self(0x2);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Status(pub $matter::definitions::PowerSource::types::PowerSourceStatusEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Order(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Description(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WiredAssessedInputVoltage(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WiredAssessedInputFrequency(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WiredCurrentType(pub $matter::definitions::PowerSource::types::WiredCurrentTypeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WiredAssessedCurrent(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WiredNominalVoltage(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WiredMaximumCurrent(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WiredPresent(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveWiredFaults(pub $matter::tlv::MatterList<$matter::definitions::PowerSource::types::WiredFaultEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xB, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatVoltage(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xC, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatPercentRemaining(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xD, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatTimeRemaining(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xE, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatChargeLevel(pub $matter::definitions::PowerSource::types::BatChargeLevelEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xF, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatReplacementNeeded(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x10, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatReplaceability(pub $matter::definitions::PowerSource::types::BatReplaceabilityEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x11, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatPresent(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x12, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveBatFaults(pub $matter::tlv::MatterList<$matter::definitions::PowerSource::types::BatFaultEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x13, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatReplacementDescription(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x14, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatCommonDesignation(pub $matter::definitions::PowerSource::types::BatCommonDesignationEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x15, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatANSIDesignation(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x16, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatIECDesignation(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x17, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatApprovedChemistry(pub $matter::definitions::PowerSource::types::BatApprovedChemistryEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x18, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatCapacity(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x19, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatQuantity(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1A, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatChargeState(pub $matter::definitions::PowerSource::types::BatChargeStateEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1B, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatTimeToFullCharge(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1C, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatFunctionalWhileCharging(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1D, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatChargingCurrent(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1E, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveBatChargeFaults(pub $matter::tlv::MatterList<$matter::definitions::PowerSource::types::BatChargeFaultEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1F, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EndpointList(pub $matter::tlv::MatterList<u16>);
    }
    pub mod commands {
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WiredFaultChange {
            #[tagval(0)]
            pub Current: $matter::tlv::MatterList<$matter::definitions::PowerSource::types::WiredFaultEnum>,
            #[tagval(1)]
            pub Previous: $matter::tlv::MatterList<$matter::definitions::PowerSource::types::WiredFaultEnum>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatFaultChange {
            #[tagval(0)]
            pub Current: $matter::tlv::MatterList<$matter::definitions::PowerSource::types::BatFaultEnum>,
            #[tagval(1)]
            pub Previous: $matter::tlv::MatterList<$matter::definitions::PowerSource::types::BatFaultEnum>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BatChargeFaultChange {
            #[tagval(0)]
            pub Current: $matter::tlv::MatterList<$matter::definitions::PowerSource::types::BatChargeFaultEnum>,
            #[tagval(1)]
            pub Previous: $matter::tlv::MatterList<$matter::definitions::PowerSource::types::BatChargeFaultEnum>,
        }
    }
}
pub mod OzoneConcentrationMeasurement {
    pub const ID: u32 = 0x0415;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LevelValueEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl LevelValueEnum {
            pub const Unknown: Self = Self(0x0);
            pub const Low: Self = Self(0x1);
            pub const Medium: Self = Self(0x2);
            pub const High: Self = Self(0x3);
            pub const Critical: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementMediumEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementMediumEnum {
            pub const Air: Self = Self(0x0);
            pub const Water: Self = Self(0x1);
            pub const Soil: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementUnitEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementUnitEnum {
            pub const PPM: Self = Self(0x0);
            pub const PPB: Self = Self(0x1);
            pub const PPT: Self = Self(0x2);
            pub const MGM3: Self = Self(0x3);
            pub const UGM3: Self = Self(0x4);
            pub const NGM3: Self = Self(0x5);
            pub const PM3: Self = Self(0x6);
            pub const BQM3: Self = Self(0x7);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Uncertainty(pub f32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementUnit(pub $matter::definitions::OzoneConcentrationMeasurement::types::MeasurementUnitEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementMedium(pub $matter::definitions::OzoneConcentrationMeasurement::types::MeasurementMediumEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LevelValue(pub $matter::definitions::OzoneConcentrationMeasurement::types::LevelValueEnum);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod PowerTopology {
    pub const ID: u32 = 0x009C;
    pub mod types {
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CircuitNodeStruct {
            #[tagval(1)]
            pub Node: u64,
            #[tagval(2)]
            pub Endpoint: core::option::Option<u16>,
            #[tagval(3)]
            pub Label: core::option::Option<$matter::tlv::MatterString>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AvailableEndpoints(pub $matter::tlv::MatterList<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveEndpoints(pub $matter::tlv::MatterList<u16>);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod IlluminanceMeasurement {
    pub const ID: u32 = 0x0400;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LightSensorTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl LightSensorTypeEnum {
            pub const Photodiode: Self = Self(0x0);
            pub const CMOS: Self = Self(0x1);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasuredValue(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinMeasuredValue(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxMeasuredValue(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Tolerance(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LightSensorType(pub $matter::tlv::Nullable<$matter::definitions::IlluminanceMeasurement::types::LightSensorTypeEnum>);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod CommodityMetering {
    pub const ID: u32 = 0x0B07;
    pub mod types {
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeteredQuantityStruct {
            #[tagval(0)]
            pub TariffComponentIDs: $matter::tlv::MatterList<u32>,
            #[tagval(1)]
            pub Quantity: i64,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeteredQuantity(pub $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::CommodityMetering::types::MeteredQuantityStruct>>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeteredQuantityTimestamp(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TariffUnit(pub $matter::tlv::Nullable<$matter::definitions::GlobalElements::types::TariffUnitEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaximumMeteredQuantities(pub $matter::tlv::Nullable<u16>);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod Descriptor {
    pub const ID: u32 = 0x001D;
    pub mod types {
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DeviceTypeStruct {
            #[tagval(0)]
            pub DeviceType: u32,
            #[tagval(1)]
            pub Revision: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DeviceTypeList(pub $matter::tlv::MatterList<$matter::definitions::Descriptor::types::DeviceTypeStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ServerList(pub $matter::tlv::MatterList<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ClientList(pub $matter::tlv::MatterList<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PartsList(pub $matter::tlv::MatterList<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TagList(pub $matter::tlv::MatterList<$matter::definitions::GlobalElements::types::SemanticTagStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EndpointUniqueID(pub $matter::tlv::MatterString);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod ElectricalGridConditions {
    pub const ID: u32 = 0x00A0;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ThreeLevelEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ThreeLevelEnum {
            pub const Low: Self = Self(0x0);
            pub const Medium: Self = Self(0x1);
            pub const High: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ElectricalGridConditionsStruct {
            #[tagval(0)]
            pub PeriodStart: u32,
            #[tagval(1)]
            pub PeriodEnd: $matter::tlv::Nullable<u32>,
            #[tagval(2)]
            pub GridCarbonIntensity: i16,
            #[tagval(3)]
            pub GridCarbonLevel: $matter::definitions::ElectricalGridConditions::types::ThreeLevelEnum,
            #[tagval(4)]
            pub LocalCarbonIntensity: i16,
            #[tagval(5)]
            pub LocalCarbonLevel: $matter::definitions::ElectricalGridConditions::types::ThreeLevelEnum,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LocalGenerationAvailable(pub $matter::tlv::Nullable<bool>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentConditions(pub $matter::tlv::Nullable<$matter::definitions::ElectricalGridConditions::types::ElectricalGridConditionsStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ForecastConditions(pub $matter::tlv::MatterList<$matter::definitions::ElectricalGridConditions::types::ElectricalGridConditionsStruct>);
    }
    pub mod commands {
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentConditionsChanged {
            #[tagval(0)]
            pub CurrentConditions: $matter::tlv::Nullable<$matter::definitions::ElectricalGridConditions::types::ElectricalGridConditionsStruct>,
        }
    }
}
pub mod NitrogenDioxideConcentrationMeasurement {
    pub const ID: u32 = 0x0413;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LevelValueEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl LevelValueEnum {
            pub const Unknown: Self = Self(0x0);
            pub const Low: Self = Self(0x1);
            pub const Medium: Self = Self(0x2);
            pub const High: Self = Self(0x3);
            pub const Critical: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementMediumEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementMediumEnum {
            pub const Air: Self = Self(0x0);
            pub const Water: Self = Self(0x1);
            pub const Soil: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementUnitEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementUnitEnum {
            pub const PPM: Self = Self(0x0);
            pub const PPB: Self = Self(0x1);
            pub const PPT: Self = Self(0x2);
            pub const MGM3: Self = Self(0x3);
            pub const UGM3: Self = Self(0x4);
            pub const NGM3: Self = Self(0x5);
            pub const PM3: Self = Self(0x6);
            pub const BQM3: Self = Self(0x7);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Uncertainty(pub f32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementUnit(pub $matter::definitions::NitrogenDioxideConcentrationMeasurement::types::MeasurementUnitEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementMedium(pub $matter::definitions::NitrogenDioxideConcentrationMeasurement::types::MeasurementMediumEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LevelValue(pub $matter::definitions::NitrogenDioxideConcentrationMeasurement::types::LevelValueEnum);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod PM1ConcentrationMeasurement {
    pub const ID: u32 = 0x042C;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LevelValueEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl LevelValueEnum {
            pub const Unknown: Self = Self(0x0);
            pub const Low: Self = Self(0x1);
            pub const Medium: Self = Self(0x2);
            pub const High: Self = Self(0x3);
            pub const Critical: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementMediumEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementMediumEnum {
            pub const Air: Self = Self(0x0);
            pub const Water: Self = Self(0x1);
            pub const Soil: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementUnitEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementUnitEnum {
            pub const PPM: Self = Self(0x0);
            pub const PPB: Self = Self(0x1);
            pub const PPT: Self = Self(0x2);
            pub const MGM3: Self = Self(0x3);
            pub const UGM3: Self = Self(0x4);
            pub const NGM3: Self = Self(0x5);
            pub const PM3: Self = Self(0x6);
            pub const BQM3: Self = Self(0x7);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Uncertainty(pub f32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementUnit(pub $matter::definitions::PM1ConcentrationMeasurement::types::MeasurementUnitEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementMedium(pub $matter::definitions::PM1ConcentrationMeasurement::types::MeasurementMediumEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LevelValue(pub $matter::definitions::PM1ConcentrationMeasurement::types::LevelValueEnum);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod BasicInformation {
    pub const ID: u32 = 0x0028;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ColorEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ColorEnum {
            pub const Black: Self = Self(0x0);
            pub const Navy: Self = Self(0x1);
            pub const Green: Self = Self(0x2);
            pub const Teal: Self = Self(0x3);
            pub const Maroon: Self = Self(0x4);
            pub const Purple: Self = Self(0x5);
            pub const Olive: Self = Self(0x6);
            pub const Gray: Self = Self(0x7);
            pub const Blue: Self = Self(0x8);
            pub const Lime: Self = Self(0x9);
            pub const Aqua: Self = Self(0xA);
            pub const Red: Self = Self(0xB);
            pub const Fuchsia: Self = Self(0xC);
            pub const Yellow: Self = Self(0xD);
            pub const White: Self = Self(0xE);
            pub const Nickel: Self = Self(0xF);
            pub const Chrome: Self = Self(0x10);
            pub const Brass: Self = Self(0x11);
            pub const Copper: Self = Self(0x12);
            pub const Silver: Self = Self(0x13);
            pub const Gold: Self = Self(0x14);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ProductFinishEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ProductFinishEnum {
            pub const Other: Self = Self(0x0);
            pub const Matte: Self = Self(0x1);
            pub const Satin: Self = Self(0x2);
            pub const Polished: Self = Self(0x3);
            pub const Rugged: Self = Self(0x4);
            pub const Fabric: Self = Self(0x5);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CapabilityMinimaStruct {
            #[tagval(0)]
            pub CaseSessionsPerFabric: u16,
            #[tagval(1)]
            pub SubscriptionsPerFabric: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProductAppearanceStruct {
            #[tagval(0)]
            pub Finish: $matter::definitions::BasicInformation::types::ProductFinishEnum,
            #[tagval(1)]
            pub PrimaryColor: $matter::tlv::Nullable<$matter::definitions::BasicInformation::types::ColorEnum>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DataModelRevision(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct VendorName(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct VendorID(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProductName(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProductID(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NodeLabel(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Location(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HardwareVersion(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HardwareVersionString(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SoftwareVersion(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SoftwareVersionString(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xB, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ManufacturingDate(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xC, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PartNumber(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xD, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProductURL(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xE, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProductLabel(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xF, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SerialNumber(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x10, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LocalConfigDisabled(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x11, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Reachable(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x12, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UniqueID(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x13, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CapabilityMinima(pub $matter::definitions::BasicInformation::types::CapabilityMinimaStruct);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x14, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProductAppearance(pub $matter::definitions::BasicInformation::types::ProductAppearanceStruct);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x15, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SpecificationVersion(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x16, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxPathsPerInvoke(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x18, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ConfigurationVersion(pub u32);
    }
    pub mod commands {
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartUp {
            #[tagval(0)]
            pub SoftwareVersion: u32,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ShutDown {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Leave {
            #[tagval(0)]
            pub FabricIndex: u8,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ReachableChanged {
            #[tagval(0)]
            pub ReachableNewValue: bool,
        }
    }
}
pub mod RelativeHumidityMeasurement {
    pub const ID: u32 = 0x0405;
    pub mod types {
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasuredValue(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinMeasuredValue(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxMeasuredValue(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Tolerance(pub u16);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod MediaPlayback {
    pub const ID: u32 = 0x0506;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct CharacteristicEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl CharacteristicEnum {
            pub const ForcedSubtitles: Self = Self(0x0);
            pub const DescribesVideo: Self = Self(0x1);
            pub const EasyToRead: Self = Self(0x2);
            pub const FrameBased: Self = Self(0x3);
            pub const MainProgram: Self = Self(0x4);
            pub const OriginalContent: Self = Self(0x5);
            pub const VoiceOverTranslation: Self = Self(0x6);
            pub const Caption: Self = Self(0x7);
            pub const Subtitle: Self = Self(0x8);
            pub const Alternate: Self = Self(0x9);
            pub const Supplementary: Self = Self(0xA);
            pub const Commentary: Self = Self(0xB);
            pub const DubbedTranslation: Self = Self(0xC);
            pub const Description: Self = Self(0xD);
            pub const Metadata: Self = Self(0xE);
            pub const EnhancedAudioIntelligibility: Self = Self(0xF);
            pub const Emergency: Self = Self(0x10);
            pub const Karaoke: Self = Self(0x11);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct PlaybackStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl PlaybackStateEnum {
            pub const Playing: Self = Self(0x0);
            pub const Paused: Self = Self(0x1);
            pub const NotPlaying: Self = Self(0x2);
            pub const Buffering: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl StatusEnum {
            pub const Success: Self = Self(0x0);
            pub const InvalidStateForCommand: Self = Self(0x1);
            pub const NotAllowed: Self = Self(0x2);
            pub const NotActive: Self = Self(0x3);
            pub const SpeedOutOfRange: Self = Self(0x4);
            pub const SeekOutOfRange: Self = Self(0x5);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PlaybackPositionStruct {
            #[tagval(0)]
            pub UpdatedAt: u64,
            #[tagval(1)]
            pub Position: $matter::tlv::Nullable<u64>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TrackAttributesStruct {
            #[tagval(0)]
            pub LanguageCode: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Characteristics: core::option::Option<$matter::tlv::Nullable<$matter::tlv::MatterString>>,
            #[tagval(2)]
            pub DisplayName: core::option::Option<$matter::tlv::Nullable<$matter::tlv::MatterString>>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TrackStruct {
            #[tagval(0)]
            pub ID: $matter::tlv::MatterString,
            #[tagval(1)]
            pub TrackAttributes: $matter::definitions::MediaPlayback::types::TrackAttributesStruct,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentState(pub $matter::definitions::MediaPlayback::types::PlaybackStateEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartTime(pub $matter::tlv::Nullable<u64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Duration(pub $matter::tlv::Nullable<u64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SampledPosition(pub $matter::tlv::Nullable<$matter::definitions::MediaPlayback::types::PlaybackPositionStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PlaybackSpeed(pub f32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SeekRangeEnd(pub $matter::tlv::Nullable<u64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SeekRangeStart(pub $matter::tlv::Nullable<u64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveAudioTrack(pub $matter::tlv::Nullable<$matter::definitions::MediaPlayback::types::TrackStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AvailableAudioTracks(pub $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::MediaPlayback::types::TrackStruct>>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveTextTrack(pub $matter::tlv::Nullable<$matter::definitions::MediaPlayback::types::TrackStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AvailableTextTracks(pub $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::MediaPlayback::types::TrackStruct>>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = PlaybackResponse, response_id = 0xA)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Play {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1, response = PlaybackResponse, response_id = 0xA)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Pause {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = PlaybackResponse, response_id = 0xA)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Stop {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3, response = PlaybackResponse, response_id = 0xA)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartOver {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4, response = PlaybackResponse, response_id = 0xA)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Previous {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5, response = PlaybackResponse, response_id = 0xA)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Next {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6, response = PlaybackResponse, response_id = 0xA)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Rewind {
            #[tagval(0)]
            pub AudioAdvanceUnmuted: core::option::Option<bool>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x7, response = PlaybackResponse, response_id = 0xA)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FastForward {
            #[tagval(0)]
            pub AudioAdvanceUnmuted: core::option::Option<bool>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x8, response = PlaybackResponse, response_id = 0xA)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SkipForward {
            #[tagval(0)]
            pub DeltaPositionMilliseconds: u64,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x9, response = PlaybackResponse, response_id = 0xA)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SkipBackward {
            #[tagval(0)]
            pub DeltaPositionMilliseconds: u64,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PlaybackResponse {
            #[tagval(0)]
            pub Status: $matter::definitions::MediaPlayback::types::StatusEnum,
            #[tagval(1)]
            pub Data: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xB, response = PlaybackResponse, response_id = 0xA)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Seek {
            #[tagval(0)]
            pub Position: u64,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xC)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActivateAudioTrack {
            #[tagval(0)]
            pub TrackID: $matter::tlv::MatterString,
            #[tagval(1)]
            pub AudioOutputIndex: core::option::Option<$matter::tlv::Nullable<u8>>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xD)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActivateTextTrack {
            #[tagval(0)]
            pub TrackID: $matter::tlv::MatterString,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xE)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DeactivateTextTrack {
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StateChanged {
            #[tagval(0)]
            pub CurrentState: $matter::definitions::MediaPlayback::types::PlaybackStateEnum,
            #[tagval(1)]
            pub StartTime: core::option::Option<u64>,
            #[tagval(2)]
            pub Duration: core::option::Option<u64>,
            #[tagval(3)]
            pub SampledPosition: core::option::Option<$matter::definitions::MediaPlayback::types::PlaybackPositionStruct>,
            #[tagval(4)]
            pub PlaybackSpeed: core::option::Option<f32>,
            #[tagval(5)]
            pub SeekRangeEnd: core::option::Option<u64>,
            #[tagval(6)]
            pub SeekRangeStart: core::option::Option<u64>,
            #[tagval(7)]
            pub Data: core::option::Option<$matter::tlv::MatterBytes>,
            #[tagval(8)]
            pub AudioAdvanceUnmuted: core::option::Option<bool>,
        }
    }
}
pub mod WindowCovering {
    pub const ID: u32 = 0x0102;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct EndProductTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl EndProductTypeEnum {
            pub const RollerShade: Self = Self(0x0);
            pub const RomanShade: Self = Self(0x1);
            pub const BalloonShade: Self = Self(0x2);
            pub const WovenWood: Self = Self(0x3);
            pub const PleatedShade: Self = Self(0x4);
            pub const CellularShade: Self = Self(0x5);
            pub const LayeredShade: Self = Self(0x6);
            pub const LayeredShade2D: Self = Self(0x7);
            pub const SheerShade: Self = Self(0x8);
            pub const TiltOnlyInteriorBlind: Self = Self(0x9);
            pub const InteriorBlind: Self = Self(0xA);
            pub const VerticalBlindStripCurtain: Self = Self(0xB);
            pub const InteriorVenetianBlind: Self = Self(0xC);
            pub const ExteriorVenetianBlind: Self = Self(0xD);
            pub const LateralLeftCurtain: Self = Self(0xE);
            pub const LateralRightCurtain: Self = Self(0xF);
            pub const CentralCurtain: Self = Self(0x10);
            pub const RollerShutter: Self = Self(0x11);
            pub const ExteriorVerticalScreen: Self = Self(0x12);
            pub const AwningTerracePatio: Self = Self(0x13);
            pub const AwningVerticalScreen: Self = Self(0x14);
            pub const TiltOnlyPergola: Self = Self(0x15);
            pub const SwingingShutter: Self = Self(0x16);
            pub const SlidingShutter: Self = Self(0x17);
            pub const Unknown: Self = Self(0xFF);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct TypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl TypeEnum {
            pub const RollerShade: Self = Self(0x0);
            pub const RollerShade2Motor: Self = Self(0x1);
            pub const RollerShadeExterior: Self = Self(0x2);
            pub const RollerShadeExterior2Motor: Self = Self(0x3);
            pub const Drapery: Self = Self(0x4);
            pub const Awning: Self = Self(0x5);
            pub const Shutter: Self = Self(0x6);
            pub const TiltBlindTiltOnly: Self = Self(0x7);
            pub const TiltBlindLiftAndTilt: Self = Self(0x8);
            pub const ProjectorScreen: Self = Self(0x9);
            pub const Unknown: Self = Self(0xFF);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ConfigStatusBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl ConfigStatusBitmap {
            pub const Operational: Self = Self(0x1);
            pub const OnlineReserved: Self = Self(0x2);
            pub const LiftMovementReversed: Self = Self(0x4);
            pub const LiftPositionAware: Self = Self(0x8);
            pub const TiltPositionAware: Self = Self(0x10);
            pub const LiftEncoderControlled: Self = Self(0x20);
            pub const TiltEncoderControlled: Self = Self(0x40);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ModeBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl ModeBitmap {
            pub const MotorDirectionReversed: Self = Self(0x1);
            pub const CalibrationMode: Self = Self(0x2);
            pub const MaintenanceMode: Self = Self(0x4);
            pub const LedFeedback: Self = Self(0x8);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OperationalStatusBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl OperationalStatusBitmap {
            pub const Global: Self = Self(0x1);
            pub const Lift: Self = Self(0x1);
            pub const Tilt: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct SafetyStatusBitmap(pub u16);
        #[allow(non_upper_case_globals)]
        impl SafetyStatusBitmap {
            pub const RemoteLockout: Self = Self(0x1);
            pub const TamperDetection: Self = Self(0x2);
            pub const FailedCommunication: Self = Self(0x4);
            pub const PositionFailure: Self = Self(0x8);
            pub const ThermalProtection: Self = Self(0x10);
            pub const ObstacleDetected: Self = Self(0x20);
            pub const Power: Self = Self(0x40);
            pub const StopInput: Self = Self(0x80);
            pub const MotorJammed: Self = Self(0x100);
            pub const HardwareFailure: Self = Self(0x200);
            pub const ManualOperation: Self = Self(0x400);
            pub const Protection: Self = Self(0x800);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Type(pub $matter::definitions::WindowCovering::types::TypeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfActuationsLift(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfActuationsTilt(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ConfigStatus(pub $matter::definitions::WindowCovering::types::ConfigStatusBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentPositionLiftPercentage(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentPositionTiltPercentage(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalStatus(pub $matter::definitions::WindowCovering::types::OperationalStatusBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xB, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TargetPositionLiftPercent100ths(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xC, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TargetPositionTiltPercent100ths(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xD, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EndProductType(pub $matter::definitions::WindowCovering::types::EndProductTypeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xE, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentPositionLiftPercent100ths(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xF, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentPositionTiltPercent100ths(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x17, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Mode(pub $matter::definitions::WindowCovering::types::ModeBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1A, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SafetyStatus(pub $matter::definitions::WindowCovering::types::SafetyStatusBitmap);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UpOrOpen {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DownOrClose {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StopMotion {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GoToLiftPercentage {
            #[tagval(0)]
            pub LiftPercent100thsValue: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x8)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GoToTiltPercentage {
            #[tagval(0)]
            pub TiltPercent100thsValue: u16,
        }
    }
    pub mod events {
    }
}
pub mod WiFiNetworkDiagnostics {
    pub const ID: u32 = 0x0036;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct AssociationFailureCauseEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl AssociationFailureCauseEnum {
            pub const Unknown: Self = Self(0x0);
            pub const AssociationFailed: Self = Self(0x1);
            pub const AuthenticationFailed: Self = Self(0x2);
            pub const SsidNotFound: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ConnectionStatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ConnectionStatusEnum {
            pub const Connected: Self = Self(0x0);
            pub const NotConnected: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct SecurityTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl SecurityTypeEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const None: Self = Self(0x1);
            pub const WEP: Self = Self(0x2);
            pub const WPA: Self = Self(0x3);
            pub const WPA2: Self = Self(0x4);
            pub const WPA3: Self = Self(0x5);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct WiFiVersionEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl WiFiVersionEnum {
            pub const a: Self = Self(0x0);
            pub const b: Self = Self(0x1);
            pub const g: Self = Self(0x2);
            pub const n: Self = Self(0x3);
            pub const ac: Self = Self(0x4);
            pub const ax: Self = Self(0x5);
            pub const ah: Self = Self(0x6);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BSSID(pub $matter::tlv::Nullable<$matter::tlv::MatterBytes>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SecurityType(pub $matter::tlv::Nullable<$matter::definitions::WiFiNetworkDiagnostics::types::SecurityTypeEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WiFiVersion(pub $matter::tlv::Nullable<$matter::definitions::WiFiNetworkDiagnostics::types::WiFiVersionEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChannelNumber(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RSSI(pub $matter::tlv::Nullable<i8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BeaconLostCount(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BeaconRxCount(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PacketMulticastRxCount(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PacketMulticastTxCount(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PacketUnicastRxCount(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PacketUnicastTxCount(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xB, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentMaxRate(pub $matter::tlv::Nullable<u64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xC, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OverrunCount(pub $matter::tlv::Nullable<u64>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ResetCounts {
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Disconnection {
            #[tagval(0)]
            pub ReasonCode: u16,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AssociationFailure {
            #[tagval(0)]
            pub AssociationFailureCause: $matter::definitions::WiFiNetworkDiagnostics::types::AssociationFailureCauseEnum,
            #[tagval(1)]
            pub Status: u16,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ConnectionStatus {
            #[tagval(0)]
            pub ConnectionStatus: $matter::definitions::WiFiNetworkDiagnostics::types::ConnectionStatusEnum,
        }
    }
}
pub mod AirQuality {
    pub const ID: u32 = 0x005B;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct AirQualityEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl AirQualityEnum {
            pub const Unknown: Self = Self(0x0);
            pub const Good: Self = Self(0x1);
            pub const Fair: Self = Self(0x2);
            pub const Moderate: Self = Self(0x3);
            pub const Poor: Self = Self(0x4);
            pub const VeryPoor: Self = Self(0x5);
            pub const ExtremelyPoor: Self = Self(0x6);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AirQuality(pub $matter::definitions::AirQuality::types::AirQualityEnum);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod TotalVolatileOrganicCompoundsConcentrationMeasurement {
    pub const ID: u32 = 0x042E;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LevelValueEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl LevelValueEnum {
            pub const Unknown: Self = Self(0x0);
            pub const Low: Self = Self(0x1);
            pub const Medium: Self = Self(0x2);
            pub const High: Self = Self(0x3);
            pub const Critical: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementMediumEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementMediumEnum {
            pub const Air: Self = Self(0x0);
            pub const Water: Self = Self(0x1);
            pub const Soil: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementUnitEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementUnitEnum {
            pub const PPM: Self = Self(0x0);
            pub const PPB: Self = Self(0x1);
            pub const PPT: Self = Self(0x2);
            pub const MGM3: Self = Self(0x3);
            pub const UGM3: Self = Self(0x4);
            pub const NGM3: Self = Self(0x5);
            pub const PM3: Self = Self(0x6);
            pub const BQM3: Self = Self(0x7);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Uncertainty(pub f32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementUnit(pub $matter::definitions::TotalVolatileOrganicCompoundsConcentrationMeasurement::types::MeasurementUnitEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementMedium(pub $matter::definitions::TotalVolatileOrganicCompoundsConcentrationMeasurement::types::MeasurementMediumEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LevelValue(pub $matter::definitions::TotalVolatileOrganicCompoundsConcentrationMeasurement::types::LevelValueEnum);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod OTASoftwareUpdateRequestor {
    pub const ID: u32 = 0x002A;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct AnnouncementReasonEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl AnnouncementReasonEnum {
            pub const SimpleAnnouncement: Self = Self(0x0);
            pub const UpdateAvailable: Self = Self(0x1);
            pub const UrgentUpdateAvailable: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ChangeReasonEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ChangeReasonEnum {
            pub const Unknown: Self = Self(0x0);
            pub const Success: Self = Self(0x1);
            pub const Failure: Self = Self(0x2);
            pub const TimeOut: Self = Self(0x3);
            pub const DelayByProvider: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct UpdateStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl UpdateStateEnum {
            pub const Unknown: Self = Self(0x0);
            pub const Idle: Self = Self(0x1);
            pub const Querying: Self = Self(0x2);
            pub const DelayedOnQuery: Self = Self(0x3);
            pub const Downloading: Self = Self(0x4);
            pub const Applying: Self = Self(0x5);
            pub const DelayedOnApply: Self = Self(0x6);
            pub const RollingBack: Self = Self(0x7);
            pub const DelayedOnUserConsent: Self = Self(0x8);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProviderLocation {
            #[tagval(1)]
            pub ProviderNodeID: u64,
            #[tagval(2)]
            pub Endpoint: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DefaultOTAProviders(pub $matter::tlv::MatterList<$matter::definitions::OTASoftwareUpdateRequestor::types::ProviderLocation>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UpdatePossible(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UpdateState(pub $matter::definitions::OTASoftwareUpdateRequestor::types::UpdateStateEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UpdateStateProgress(pub $matter::tlv::Nullable<u8>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AnnounceOTAProvider {
            #[tagval(0)]
            pub ProviderNodeID: u64,
            #[tagval(1)]
            pub VendorID: u16,
            #[tagval(2)]
            pub AnnouncementReason: $matter::definitions::OTASoftwareUpdateRequestor::types::AnnouncementReasonEnum,
            #[tagval(3)]
            pub MetadataForNode: core::option::Option<$matter::tlv::MatterBytes>,
            #[tagval(4)]
            pub Endpoint: u16,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StateTransition {
            #[tagval(0)]
            pub PreviousState: $matter::definitions::OTASoftwareUpdateRequestor::types::UpdateStateEnum,
            #[tagval(1)]
            pub NewState: $matter::definitions::OTASoftwareUpdateRequestor::types::UpdateStateEnum,
            #[tagval(2)]
            pub Reason: $matter::definitions::OTASoftwareUpdateRequestor::types::ChangeReasonEnum,
            #[tagval(3)]
            pub TargetSoftwareVersion: $matter::tlv::Nullable<u32>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct VersionApplied {
            #[tagval(0)]
            pub SoftwareVersion: u32,
            #[tagval(1)]
            pub ProductID: u16,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DownloadError {
            #[tagval(0)]
            pub SoftwareVersion: u32,
            #[tagval(1)]
            pub BytesDownloaded: u64,
            #[tagval(2)]
            pub ProgressPercent: $matter::tlv::Nullable<u8>,
            #[tagval(3)]
            pub PlatformCode: $matter::tlv::Nullable<i64>,
        }
    }
}
pub mod WebRTCTransportRequestor {
    pub const ID: u32 = 0x0554;
    pub mod types {
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentSessions(pub $matter::tlv::MatterList<$matter::definitions::GlobalElements::types::WebRTCSessionStruct>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Offer {
            #[tagval(0)]
            pub WebRTCSessionID: u16,
            #[tagval(1)]
            pub SDP: $matter::tlv::MatterString,
            #[tagval(2)]
            pub ICEServers: core::option::Option<$matter::tlv::MatterList<$matter::definitions::GlobalElements::types::ICEServerStruct>>,
            #[tagval(3)]
            pub ICETransportPolicy: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Answer {
            #[tagval(0)]
            pub WebRTCSessionID: u16,
            #[tagval(1)]
            pub SDP: $matter::tlv::MatterString,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ICECandidates {
            #[tagval(0)]
            pub WebRTCSessionID: u16,
            #[tagval(1)]
            pub ICECandidates: $matter::tlv::MatterList<$matter::definitions::GlobalElements::types::ICECandidateStruct>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct End {
            #[tagval(0)]
            pub WebRTCSessionID: u16,
            #[tagval(1)]
            pub Reason: $matter::definitions::GlobalElements::types::WebRTCEndReasonEnum,
        }
    }
    pub mod events {
    }
}
pub mod ThreadNetworkDirectory {
    pub const ID: u32 = 0x0453;
    pub mod types {
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ThreadNetworkStruct {
            #[tagval(0)]
            pub ExtendedPanID: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub NetworkName: $matter::tlv::MatterString,
            #[tagval(2)]
            pub Channel: u16,
            #[tagval(3)]
            pub ActiveTimestamp: u64,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PreferredExtendedPanID(pub $matter::tlv::Nullable<$matter::tlv::MatterBytes>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ThreadNetworks(pub $matter::tlv::MatterList<$matter::definitions::ThreadNetworkDirectory::types::ThreadNetworkStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ThreadNetworkTableSize(pub u8);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddNetwork {
            #[tagval(0)]
            pub OperationalDataset: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveNetwork {
            #[tagval(0)]
            pub ExtendedPanID: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = OperationalDatasetResponse, response_id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetOperationalDataset {
            #[tagval(0)]
            pub ExtendedPanID: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalDatasetResponse {
            #[tagval(0)]
            pub OperationalDataset: $matter::tlv::MatterBytes,
        }
    }
    pub mod events {
    }
}
pub mod ServiceArea {
    pub const ID: u32 = 0x0150;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OperationalStatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl OperationalStatusEnum {
            pub const Pending: Self = Self(0x0);
            pub const Operating: Self = Self(0x1);
            pub const Skipped: Self = Self(0x2);
            pub const Completed: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct SelectAreasStatus(pub u8);
        #[allow(non_upper_case_globals)]
        impl SelectAreasStatus {
            pub const Success: Self = Self(0x0);
            pub const UnsupportedArea: Self = Self(0x1);
            pub const InvalidInMode: Self = Self(0x2);
            pub const InvalidSet: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct SkipAreaStatus(pub u8);
        #[allow(non_upper_case_globals)]
        impl SkipAreaStatus {
            pub const Success: Self = Self(0x0);
            pub const InvalidAreaList: Self = Self(0x1);
            pub const InvalidInMode: Self = Self(0x2);
            pub const InvalidSkippedArea: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AreaInfoStruct {
            #[tagval(0)]
            pub LocationInfo: $matter::tlv::Nullable<$matter::definitions::GlobalElements::types::LocationDescriptorStruct>,
            #[tagval(1)]
            pub LandmarkInfo: $matter::tlv::Nullable<$matter::definitions::ServiceArea::types::LandmarkInfoStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AreaStruct {
            #[tagval(0)]
            pub AreaID: u32,
            #[tagval(1)]
            pub MapID: $matter::tlv::Nullable<u32>,
            #[tagval(2)]
            pub AreaInfo: $matter::definitions::ServiceArea::types::AreaInfoStruct,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LandmarkInfoStruct {
            #[tagval(0)]
            pub LandmarkTag: u8,
            #[tagval(1)]
            pub RelativePositionTag: $matter::tlv::Nullable<u8>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MapStruct {
            #[tagval(0)]
            pub MapID: u32,
            #[tagval(1)]
            pub Name: $matter::tlv::MatterString,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProgressStruct {
            #[tagval(0)]
            pub AreaID: u32,
            #[tagval(1)]
            pub Status: $matter::definitions::ServiceArea::types::OperationalStatusEnum,
            #[tagval(2)]
            pub TotalOperationalTime: core::option::Option<$matter::tlv::Nullable<u32>>,
            #[tagval(3)]
            pub EstimatedTime: core::option::Option<$matter::tlv::Nullable<u32>>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedAreas(pub $matter::tlv::MatterList<$matter::definitions::ServiceArea::types::AreaStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedMaps(pub $matter::tlv::MatterList<$matter::definitions::ServiceArea::types::MapStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SelectedAreas(pub $matter::tlv::MatterList<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentArea(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EstimatedEndTime(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Progress(pub $matter::tlv::MatterList<$matter::definitions::ServiceArea::types::ProgressStruct>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = SelectAreasResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SelectAreas {
            #[tagval(0)]
            pub NewAreas: $matter::tlv::MatterList<u32>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SelectAreasResponse {
            #[tagval(0)]
            pub Status: $matter::definitions::ServiceArea::types::SelectAreasStatus,
            #[tagval(1)]
            pub StatusText: $matter::tlv::MatterString,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = SkipAreaResponse, response_id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SkipArea {
            #[tagval(0)]
            pub SkippedArea: u32,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SkipAreaResponse {
            #[tagval(0)]
            pub Status: $matter::definitions::ServiceArea::types::SkipAreaStatus,
            #[tagval(1)]
            pub StatusText: $matter::tlv::MatterString,
        }
    }
    pub mod events {
    }
}
pub mod RefrigeratorAndTemperatureControlledCabinetMode {
    pub const ID: u32 = 0x0052;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ModeTag(pub u16);
        #[allow(non_upper_case_globals)]
        impl ModeTag {
            pub const Auto: Self = Self(0x0);
            pub const Quick: Self = Self(0x1);
            pub const Quiet: Self = Self(0x2);
            pub const LowNoise: Self = Self(0x3);
            pub const LowEnergy: Self = Self(0x4);
            pub const Vacation: Self = Self(0x5);
            pub const Min: Self = Self(0x6);
            pub const Max: Self = Self(0x7);
            pub const Night: Self = Self(0x8);
            pub const Day: Self = Self(0x9);
            pub const RapidCool: Self = Self(0x4000);
            pub const RapidFreeze: Self = Self(0x4001);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeOptionStruct {
            #[tagval(0)]
            pub Label: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Mode: u8,
            #[tagval(2)]
            pub ModeTags: $matter::tlv::MatterList<$matter::definitions::RefrigeratorAndTemperatureControlledCabinetMode::types::ModeTagStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeTagStruct {
            #[tagval(0)]
            pub MfgCode: core::option::Option<u16>,
            #[tagval(1)]
            pub Value: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedModes(pub $matter::tlv::MatterList<$matter::definitions::RefrigeratorAndTemperatureControlledCabinetMode::types::ModeOptionStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentMode(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartUpMode(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnMode(pub $matter::tlv::Nullable<u8>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = ChangeToModeResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToMode {
            #[tagval(0)]
            pub NewMode: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToModeResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub StatusText: $matter::tlv::MatterString,
        }
    }
    pub mod events {
    }
}
pub mod AccessControl {
    pub const ID: u32 = 0x001F;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct AccessControlEntryAuthModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl AccessControlEntryAuthModeEnum {
            pub const PASE: Self = Self(0x1);
            pub const CASE: Self = Self(0x2);
            pub const Group: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct AccessControlEntryPrivilegeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl AccessControlEntryPrivilegeEnum {
            pub const View: Self = Self(0x1);
            pub const ProxyView: Self = Self(0x2);
            pub const Operate: Self = Self(0x3);
            pub const Manage: Self = Self(0x4);
            pub const Administer: Self = Self(0x5);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct AccessRestrictionTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl AccessRestrictionTypeEnum {
            pub const AttributeAccessForbidden: Self = Self(0x0);
            pub const AttributeWriteForbidden: Self = Self(0x1);
            pub const CommandForbidden: Self = Self(0x2);
            pub const EventForbidden: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ChangeTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ChangeTypeEnum {
            pub const Changed: Self = Self(0x0);
            pub const Added: Self = Self(0x1);
            pub const Removed: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AccessControlEntryStruct {
            #[tagval(1)]
            pub Privilege: $matter::definitions::AccessControl::types::AccessControlEntryPrivilegeEnum,
            #[tagval(2)]
            pub AuthMode: $matter::definitions::AccessControl::types::AccessControlEntryAuthModeEnum,
            #[tagval(3)]
            pub Subjects: $matter::tlv::Nullable<$matter::tlv::MatterList<u64>>,
            #[tagval(4)]
            pub Targets: $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::AccessControl::types::AccessControlTargetStruct>>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AccessControlExtensionStruct {
            #[tagval(1)]
            pub Data: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AccessControlTargetStruct {
            #[tagval(0)]
            pub Cluster: $matter::tlv::Nullable<u32>,
            #[tagval(1)]
            pub Endpoint: $matter::tlv::Nullable<u16>,
            #[tagval(2)]
            pub DeviceType: $matter::tlv::Nullable<u32>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AccessRestrictionEntryStruct {
            #[tagval(0)]
            pub Endpoint: u16,
            #[tagval(1)]
            pub Cluster: u32,
            #[tagval(2)]
            pub Restrictions: $matter::tlv::MatterList<$matter::definitions::AccessControl::types::AccessRestrictionStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AccessRestrictionStruct {
            #[tagval(0)]
            pub Type: $matter::definitions::AccessControl::types::AccessRestrictionTypeEnum,
            #[tagval(1)]
            pub ID: $matter::tlv::Nullable<u32>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CommissioningAccessRestrictionEntryStruct {
            #[tagval(0)]
            pub Endpoint: u16,
            #[tagval(1)]
            pub Cluster: u32,
            #[tagval(2)]
            pub Restrictions: $matter::tlv::MatterList<$matter::definitions::AccessControl::types::AccessRestrictionStruct>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ACL(pub $matter::tlv::MatterList<$matter::definitions::AccessControl::types::AccessControlEntryStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Extension(pub $matter::tlv::MatterList<$matter::definitions::AccessControl::types::AccessControlExtensionStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SubjectsPerAccessControlEntry(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TargetsPerAccessControlEntry(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AccessControlEntriesPerFabric(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CommissioningARL(pub $matter::tlv::MatterList<$matter::definitions::AccessControl::types::CommissioningAccessRestrictionEntryStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ARL(pub $matter::tlv::MatterList<$matter::definitions::AccessControl::types::AccessRestrictionEntryStruct>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = ReviewFabricRestrictionsResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ReviewFabricRestrictions {
            #[tagval(0)]
            pub ARL: $matter::tlv::MatterList<$matter::definitions::AccessControl::types::CommissioningAccessRestrictionEntryStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ReviewFabricRestrictionsResponse {
            #[tagval(0)]
            pub Token: u64,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AccessControlEntryChanged {
            #[tagval(1)]
            pub AdminNodeID: $matter::tlv::Nullable<u64>,
            #[tagval(2)]
            pub AdminPasscodeID: $matter::tlv::Nullable<u16>,
            #[tagval(3)]
            pub ChangeType: $matter::definitions::AccessControl::types::ChangeTypeEnum,
            #[tagval(4)]
            pub LatestValue: $matter::tlv::Nullable<$matter::definitions::AccessControl::types::AccessControlEntryStruct>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AccessControlExtensionChanged {
            #[tagval(1)]
            pub AdminNodeID: $matter::tlv::Nullable<u64>,
            #[tagval(2)]
            pub AdminPasscodeID: $matter::tlv::Nullable<u16>,
            #[tagval(3)]
            pub ChangeType: $matter::definitions::AccessControl::types::ChangeTypeEnum,
            #[tagval(4)]
            pub LatestValue: $matter::tlv::Nullable<$matter::definitions::AccessControl::types::AccessControlExtensionStruct>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FabricRestrictionReviewUpdate {
            #[tagval(0)]
            pub Token: u64,
            #[tagval(1)]
            pub Instruction: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub ARLRequestFlowUrl: core::option::Option<$matter::tlv::MatterString>,
        }
    }
}
pub mod WaterHeaterMode {
    pub const ID: u32 = 0x009E;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ModeTag(pub u16);
        #[allow(non_upper_case_globals)]
        impl ModeTag {
            pub const Auto: Self = Self(0x0);
            pub const Quick: Self = Self(0x1);
            pub const Quiet: Self = Self(0x2);
            pub const LowNoise: Self = Self(0x3);
            pub const LowEnergy: Self = Self(0x4);
            pub const Vacation: Self = Self(0x5);
            pub const Min: Self = Self(0x6);
            pub const Max: Self = Self(0x7);
            pub const Night: Self = Self(0x8);
            pub const Day: Self = Self(0x9);
            pub const Off: Self = Self(0x4000);
            pub const Manual: Self = Self(0x4001);
            pub const Timed: Self = Self(0x4002);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeOptionStruct {
            #[tagval(0)]
            pub Label: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Mode: u8,
            #[tagval(2)]
            pub ModeTags: $matter::tlv::MatterList<$matter::definitions::WaterHeaterMode::types::ModeTagStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeTagStruct {
            #[tagval(0)]
            pub MfgCode: core::option::Option<u16>,
            #[tagval(1)]
            pub Value: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedModes(pub $matter::tlv::MatterList<$matter::definitions::WaterHeaterMode::types::ModeOptionStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentMode(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartUpMode(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnMode(pub $matter::tlv::Nullable<u8>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = ChangeToModeResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToMode {
            #[tagval(0)]
            pub NewMode: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToModeResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub StatusText: $matter::tlv::MatterString,
        }
    }
    pub mod events {
    }
}
pub mod TLSClientManagement {
    pub const ID: u32 = 0x0802;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusCodeEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl StatusCodeEnum {
            pub const EndpointAlreadyInstalled: Self = Self(0x2);
            pub const RootCertificateNotFound: Self = Self(0x3);
            pub const ClientCertificateNotFound: Self = Self(0x4);
            pub const EndpointInUse: Self = Self(0x5);
            pub const InvalidTime: Self = Self(0x6);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TLSEndpointStruct {
            #[tagval(0)]
            pub EndpointID: u16,
            #[tagval(1)]
            pub Hostname: $matter::tlv::MatterBytes,
            #[tagval(2)]
            pub Port: u16,
            #[tagval(3)]
            pub CAID: u16,
            #[tagval(4)]
            pub CCDID: $matter::tlv::Nullable<u16>,
            #[tagval(5)]
            pub ReferenceCount: u8,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxProvisioned(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProvisionedEndpoints(pub $matter::tlv::MatterList<$matter::definitions::TLSClientManagement::types::TLSEndpointStruct>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = ProvisionEndpointResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProvisionEndpoint {
            #[tagval(0)]
            pub Hostname: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub Port: u16,
            #[tagval(2)]
            pub CAID: u16,
            #[tagval(3)]
            pub CCDID: $matter::tlv::Nullable<u16>,
            #[tagval(4)]
            pub EndpointID: $matter::tlv::Nullable<u16>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProvisionEndpointResponse {
            #[tagval(0)]
            pub EndpointID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = FindEndpointResponse, response_id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FindEndpoint {
            #[tagval(0)]
            pub EndpointID: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FindEndpointResponse {
            #[tagval(0)]
            pub Endpoint: $matter::definitions::TLSClientManagement::types::TLSEndpointStruct,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveEndpoint {
            #[tagval(0)]
            pub EndpointID: u16,
        }
    }
    pub mod events {
    }
}
pub mod ElectricalEnergyMeasurement {
    pub const ID: u32 = 0x0091;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementTypeEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl MeasurementTypeEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const Voltage: Self = Self(0x1);
            pub const ActiveCurrent: Self = Self(0x2);
            pub const ReactiveCurrent: Self = Self(0x3);
            pub const ApparentCurrent: Self = Self(0x4);
            pub const ActivePower: Self = Self(0x5);
            pub const ReactivePower: Self = Self(0x6);
            pub const ApparentPower: Self = Self(0x7);
            pub const RMSVoltage: Self = Self(0x8);
            pub const RMSCurrent: Self = Self(0x9);
            pub const RMSPower: Self = Self(0xA);
            pub const Frequency: Self = Self(0xB);
            pub const PowerFactor: Self = Self(0xC);
            pub const NeutralCurrent: Self = Self(0xD);
            pub const ElectricalEnergy: Self = Self(0xE);
            pub const ReactiveEnergy: Self = Self(0xF);
            pub const ApparentEnergy: Self = Self(0x10);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CumulativeEnergyResetStruct {
            #[tagval(0)]
            pub ImportedResetTimestamp: core::option::Option<$matter::tlv::Nullable<u32>>,
            #[tagval(1)]
            pub ExportedResetTimestamp: core::option::Option<$matter::tlv::Nullable<u32>>,
            #[tagval(2)]
            pub ImportedResetSystime: core::option::Option<$matter::tlv::Nullable<u64>>,
            #[tagval(3)]
            pub ExportedResetSystime: core::option::Option<$matter::tlv::Nullable<u64>>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnergyMeasurementStruct {
            #[tagval(0)]
            pub Energy: i64,
            #[tagval(1)]
            pub StartTimestamp: u32,
            #[tagval(2)]
            pub EndTimestamp: u32,
            #[tagval(3)]
            pub StartSystime: u64,
            #[tagval(4)]
            pub EndSystime: u64,
            #[tagval(5)]
            pub ApparentEnergy: core::option::Option<i64>,
            #[tagval(6)]
            pub ReactiveEnergy: core::option::Option<i64>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementAccuracyRangeStruct {
            #[tagval(0)]
            pub RangeMin: i64,
            #[tagval(1)]
            pub RangeMax: i64,
            #[tagval(2)]
            pub PercentMax: core::option::Option<u16>,
            #[tagval(3)]
            pub PercentMin: core::option::Option<u16>,
            #[tagval(4)]
            pub PercentTypical: core::option::Option<u16>,
            #[tagval(5)]
            pub FixedMax: core::option::Option<u64>,
            #[tagval(6)]
            pub FixedMin: core::option::Option<u64>,
            #[tagval(7)]
            pub FixedTypical: core::option::Option<u64>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementAccuracyStruct {
            #[tagval(0)]
            pub MeasurementType: $matter::definitions::ElectricalEnergyMeasurement::types::MeasurementTypeEnum,
            #[tagval(1)]
            pub Measured: bool,
            #[tagval(2)]
            pub MinMeasuredValue: i64,
            #[tagval(3)]
            pub MaxMeasuredValue: i64,
            #[tagval(4)]
            pub AccuracyRanges: $matter::tlv::MatterList<$matter::definitions::ElectricalEnergyMeasurement::types::MeasurementAccuracyRangeStruct>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Accuracy(pub $matter::definitions::ElectricalEnergyMeasurement::types::MeasurementAccuracyStruct);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CumulativeEnergyImported(pub $matter::tlv::Nullable<$matter::definitions::ElectricalEnergyMeasurement::types::EnergyMeasurementStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CumulativeEnergyExported(pub $matter::tlv::Nullable<$matter::definitions::ElectricalEnergyMeasurement::types::EnergyMeasurementStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeriodicEnergyImported(pub $matter::tlv::Nullable<$matter::definitions::ElectricalEnergyMeasurement::types::EnergyMeasurementStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeriodicEnergyExported(pub $matter::tlv::Nullable<$matter::definitions::ElectricalEnergyMeasurement::types::EnergyMeasurementStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CumulativeEnergyReset(pub $matter::tlv::Nullable<$matter::definitions::ElectricalEnergyMeasurement::types::CumulativeEnergyResetStruct>);
    }
    pub mod commands {
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CumulativeEnergyMeasured {
            #[tagval(0)]
            pub EnergyImported: core::option::Option<$matter::definitions::ElectricalEnergyMeasurement::types::EnergyMeasurementStruct>,
            #[tagval(1)]
            pub EnergyExported: core::option::Option<$matter::definitions::ElectricalEnergyMeasurement::types::EnergyMeasurementStruct>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeriodicEnergyMeasured {
            #[tagval(0)]
            pub EnergyImported: core::option::Option<$matter::definitions::ElectricalEnergyMeasurement::types::EnergyMeasurementStruct>,
            #[tagval(1)]
            pub EnergyExported: core::option::Option<$matter::definitions::ElectricalEnergyMeasurement::types::EnergyMeasurementStruct>,
        }
    }
}
pub mod ClosureControl {
    pub const ID: u32 = 0x0104;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ClosureErrorEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ClosureErrorEnum {
            pub const PhysicallyBlocked: Self = Self(0x0);
            pub const BlockedBySensor: Self = Self(0x1);
            pub const TemperatureLimited: Self = Self(0x2);
            pub const MaintenanceRequired: Self = Self(0x3);
            pub const InternalInterference: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct CurrentPositionEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl CurrentPositionEnum {
            pub const FullyClosed: Self = Self(0x0);
            pub const FullyOpened: Self = Self(0x1);
            pub const PartiallyOpened: Self = Self(0x2);
            pub const OpenedForPedestrian: Self = Self(0x3);
            pub const OpenedForVentilation: Self = Self(0x4);
            pub const OpenedAtSignature: Self = Self(0x5);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MainStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MainStateEnum {
            pub const Stopped: Self = Self(0x0);
            pub const Moving: Self = Self(0x1);
            pub const WaitingForMotion: Self = Self(0x2);
            pub const Error: Self = Self(0x3);
            pub const Calibrating: Self = Self(0x4);
            pub const Protected: Self = Self(0x5);
            pub const Disengaged: Self = Self(0x6);
            pub const SetupRequired: Self = Self(0x7);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct TargetPositionEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl TargetPositionEnum {
            pub const MoveToFullyClosed: Self = Self(0x0);
            pub const MoveToFullyOpen: Self = Self(0x1);
            pub const MoveToPedestrianPosition: Self = Self(0x2);
            pub const MoveToVentilationPosition: Self = Self(0x3);
            pub const MoveToSignaturePosition: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LatchControlModesBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl LatchControlModesBitmap {
            pub const RemoteLatching: Self = Self(0x1);
            pub const RemoteUnlatching: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OverallCurrentStateStruct {
            #[tagval(0)]
            pub Position: core::option::Option<$matter::tlv::Nullable<$matter::definitions::ClosureControl::types::CurrentPositionEnum>>,
            #[tagval(1)]
            pub Latch: core::option::Option<$matter::tlv::Nullable<bool>>,
            #[tagval(2)]
            pub Speed: core::option::Option<$matter::definitions::GlobalElements::types::ThreeLevelAutoEnum>,
            #[tagval(3)]
            pub SecureState: $matter::tlv::Nullable<bool>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OverallTargetStateStruct {
            #[tagval(0)]
            pub Position: core::option::Option<$matter::tlv::Nullable<$matter::definitions::ClosureControl::types::TargetPositionEnum>>,
            #[tagval(1)]
            pub Latch: core::option::Option<$matter::tlv::Nullable<bool>>,
            #[tagval(2)]
            pub Speed: core::option::Option<$matter::definitions::GlobalElements::types::ThreeLevelAutoEnum>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CountdownTime(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MainState(pub $matter::definitions::ClosureControl::types::MainStateEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentErrorList(pub $matter::tlv::MatterList<$matter::definitions::ClosureControl::types::ClosureErrorEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OverallCurrentState(pub $matter::tlv::Nullable<$matter::definitions::ClosureControl::types::OverallCurrentStateStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OverallTargetState(pub $matter::tlv::Nullable<$matter::definitions::ClosureControl::types::OverallTargetStateStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LatchControlModes(pub $matter::definitions::ClosureControl::types::LatchControlModesBitmap);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Stop {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MoveTo {
            #[tagval(0)]
            pub Position: core::option::Option<$matter::definitions::ClosureControl::types::TargetPositionEnum>,
            #[tagval(1)]
            pub Latch: core::option::Option<bool>,
            #[tagval(2)]
            pub Speed: core::option::Option<$matter::definitions::GlobalElements::types::ThreeLevelAutoEnum>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Calibrate {
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalError {
            #[tagval(0)]
            pub ErrorState: $matter::tlv::MatterList<$matter::definitions::ClosureControl::types::ClosureErrorEnum>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MovementCompleted {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EngageStateChanged {
            #[tagval(0)]
            pub EngageValue: bool,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SecureStateChanged {
            #[tagval(0)]
            pub SecureValue: bool,
        }
    }
}
pub mod Identify {
    pub const ID: u32 = 0x0003;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct EffectIdentifierEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl EffectIdentifierEnum {
            pub const Blink: Self = Self(0x0);
            pub const Breathe: Self = Self(0x1);
            pub const Okay: Self = Self(0x2);
            pub const ChannelChange: Self = Self(0xB);
            pub const FinishEffect: Self = Self(0xFE);
            pub const StopEffect: Self = Self(0xFF);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct EffectVariantEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl EffectVariantEnum {
            pub const Default: Self = Self(0x0);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct IdentifyTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl IdentifyTypeEnum {
            pub const None: Self = Self(0x0);
            pub const LightOutput: Self = Self(0x1);
            pub const VisibleIndicator: Self = Self(0x2);
            pub const AudibleBeep: Self = Self(0x3);
            pub const Display: Self = Self(0x4);
            pub const Actuator: Self = Self(0x5);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct IdentifyTime(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct IdentifyType(pub $matter::definitions::Identify::types::IdentifyTypeEnum);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Identify {
            #[tagval(0)]
            pub IdentifyTime: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x40)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TriggerEffect {
            #[tagval(0)]
            pub EffectIdentifier: $matter::definitions::Identify::types::EffectIdentifierEnum,
            #[tagval(1)]
            pub EffectVariant: $matter::definitions::Identify::types::EffectVariantEnum,
        }
    }
    pub mod events {
    }
}
pub mod LowPower {
    pub const ID: u32 = 0x0508;
    pub mod types {
    }
    pub mod attributes {
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Sleep {
        }
    }
    pub mod events {
    }
}
pub mod Binding {
    pub const ID: u32 = 0x001E;
    pub mod types {
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TargetStruct {
            #[tagval(1)]
            pub Node: u64,
            #[tagval(2)]
            pub Group: core::option::Option<u16>,
            #[tagval(3)]
            pub Endpoint: core::option::Option<u16>,
            #[tagval(4)]
            pub Cluster: core::option::Option<u32>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Binding(pub $matter::tlv::MatterList<$matter::definitions::Binding::types::TargetStruct>);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod EnergyEVSEMode {
    pub const ID: u32 = 0x009D;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ModeTag(pub u16);
        #[allow(non_upper_case_globals)]
        impl ModeTag {
            pub const Auto: Self = Self(0x0);
            pub const Quick: Self = Self(0x1);
            pub const Quiet: Self = Self(0x2);
            pub const LowNoise: Self = Self(0x3);
            pub const LowEnergy: Self = Self(0x4);
            pub const Vacation: Self = Self(0x5);
            pub const Min: Self = Self(0x6);
            pub const Max: Self = Self(0x7);
            pub const Night: Self = Self(0x8);
            pub const Day: Self = Self(0x9);
            pub const Manual: Self = Self(0x4000);
            pub const TimeOfUse: Self = Self(0x4001);
            pub const SolarCharging: Self = Self(0x4002);
            pub const V2X: Self = Self(0x4003);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeOptionStruct {
            #[tagval(0)]
            pub Label: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Mode: u8,
            #[tagval(2)]
            pub ModeTags: $matter::tlv::MatterList<$matter::definitions::EnergyEVSEMode::types::ModeTagStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeTagStruct {
            #[tagval(0)]
            pub MfgCode: core::option::Option<u16>,
            #[tagval(1)]
            pub Value: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedModes(pub $matter::tlv::MatterList<$matter::definitions::EnergyEVSEMode::types::ModeOptionStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentMode(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartUpMode(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnMode(pub $matter::tlv::Nullable<u8>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = ChangeToModeResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToMode {
            #[tagval(0)]
            pub NewMode: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToModeResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub StatusText: $matter::tlv::MatterString,
        }
    }
    pub mod events {
    }
}
pub mod BooleanStateConfiguration {
    pub const ID: u32 = 0x0080;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct AlarmModeBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl AlarmModeBitmap {
            pub const Visual: Self = Self(0x1);
            pub const Audible: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct SensorFaultBitmap(pub u16);
        #[allow(non_upper_case_globals)]
        impl SensorFaultBitmap {
            pub const GeneralFault: Self = Self(0x1);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentSensitivityLevel(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedSensitivityLevels(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DefaultSensitivityLevel(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AlarmsActive(pub $matter::definitions::BooleanStateConfiguration::types::AlarmModeBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AlarmsSuppressed(pub $matter::definitions::BooleanStateConfiguration::types::AlarmModeBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AlarmsEnabled(pub $matter::definitions::BooleanStateConfiguration::types::AlarmModeBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AlarmsSupported(pub $matter::definitions::BooleanStateConfiguration::types::AlarmModeBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SensorFault(pub $matter::definitions::BooleanStateConfiguration::types::SensorFaultBitmap);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SuppressAlarm {
            #[tagval(0)]
            pub AlarmsToSuppress: $matter::definitions::BooleanStateConfiguration::types::AlarmModeBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnableDisableAlarm {
            #[tagval(0)]
            pub AlarmsToEnableDisable: $matter::definitions::BooleanStateConfiguration::types::AlarmModeBitmap,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AlarmsStateChanged {
            #[tagval(0)]
            pub AlarmsActive: $matter::definitions::BooleanStateConfiguration::types::AlarmModeBitmap,
            #[tagval(1)]
            pub AlarmsSuppressed: core::option::Option<$matter::definitions::BooleanStateConfiguration::types::AlarmModeBitmap>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SensorFault {
            #[tagval(0)]
            pub SensorFault: $matter::definitions::BooleanStateConfiguration::types::SensorFaultBitmap,
        }
    }
}
pub mod RadonConcentrationMeasurement {
    pub const ID: u32 = 0x042F;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LevelValueEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl LevelValueEnum {
            pub const Unknown: Self = Self(0x0);
            pub const Low: Self = Self(0x1);
            pub const Medium: Self = Self(0x2);
            pub const High: Self = Self(0x3);
            pub const Critical: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementMediumEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementMediumEnum {
            pub const Air: Self = Self(0x0);
            pub const Water: Self = Self(0x1);
            pub const Soil: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementUnitEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeasurementUnitEnum {
            pub const PPM: Self = Self(0x0);
            pub const PPB: Self = Self(0x1);
            pub const PPT: Self = Self(0x2);
            pub const MGM3: Self = Self(0x3);
            pub const UGM3: Self = Self(0x4);
            pub const NGM3: Self = Self(0x5);
            pub const PM3: Self = Self(0x6);
            pub const BQM3: Self = Self(0x7);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValue(pub $matter::tlv::Nullable<f32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AverageMeasuredValueWindow(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Uncertainty(pub f32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementUnit(pub $matter::definitions::RadonConcentrationMeasurement::types::MeasurementUnitEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementMedium(pub $matter::definitions::RadonConcentrationMeasurement::types::MeasurementMediumEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LevelValue(pub $matter::definitions::RadonConcentrationMeasurement::types::LevelValueEnum);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod LocalizationConfiguration {
    pub const ID: u32 = 0x002B;
    pub mod types {
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveLocale(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedLocales(pub $matter::tlv::MatterList<$matter::tlv::MatterString>);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod MeterIdentification {
    pub const ID: u32 = 0x0B06;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeterTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl MeterTypeEnum {
            pub const Utility: Self = Self(0x0);
            pub const Private: Self = Self(0x1);
            pub const Generic: Self = Self(0x2);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeterType(pub $matter::tlv::Nullable<$matter::definitions::MeterIdentification::types::MeterTypeEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PointOfDelivery(pub $matter::tlv::Nullable<$matter::tlv::MatterString>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeterSerialNumber(pub $matter::tlv::Nullable<$matter::tlv::MatterString>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProtocolVersion(pub $matter::tlv::Nullable<$matter::tlv::MatterString>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PowerThreshold(pub $matter::tlv::Nullable<$matter::definitions::GlobalElements::types::PowerThresholdStruct>);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod EnergyPreference {
    pub const ID: u32 = 0x009B;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct EnergyPriorityEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl EnergyPriorityEnum {
            pub const Comfort: Self = Self(0x0);
            pub const Speed: Self = Self(0x1);
            pub const Efficiency: Self = Self(0x2);
            pub const WaterConsumption: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BalanceStruct {
            #[tagval(0)]
            pub Step: u8,
            #[tagval(1)]
            pub Label: core::option::Option<$matter::tlv::MatterString>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnergyBalances(pub $matter::tlv::MatterList<$matter::definitions::EnergyPreference::types::BalanceStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentEnergyBalance(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnergyPriorities(pub $matter::tlv::MatterList<$matter::definitions::EnergyPreference::types::EnergyPriorityEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LowPowerModeSensitivities(pub $matter::tlv::MatterList<$matter::definitions::EnergyPreference::types::BalanceStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentLowPowerModeSensitivity(pub u8);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod ScenesManagement {
    pub const ID: u32 = 0x0062;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct CopyModeBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl CopyModeBitmap {
            pub const CopyAllScenes: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AttributeValuePairStruct {
            #[tagval(0)]
            pub AttributeID: u32,
            #[tagval(1)]
            pub ValueUnsigned8: core::option::Option<u8>,
            #[tagval(2)]
            pub ValueSigned8: core::option::Option<i8>,
            #[tagval(3)]
            pub ValueUnsigned16: core::option::Option<u16>,
            #[tagval(4)]
            pub ValueSigned16: core::option::Option<i16>,
            #[tagval(5)]
            pub ValueUnsigned32: core::option::Option<u32>,
            #[tagval(6)]
            pub ValueSigned32: core::option::Option<i32>,
            #[tagval(7)]
            pub ValueUnsigned64: core::option::Option<u64>,
            #[tagval(8)]
            pub ValueSigned64: core::option::Option<i64>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ExtensionFieldSetStruct {
            #[tagval(0)]
            pub ClusterID: u32,
            #[tagval(1)]
            pub AttributeValueList: $matter::tlv::MatterList<$matter::definitions::ScenesManagement::types::AttributeValuePairStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SceneInfoStruct {
            #[tagval(0)]
            pub SceneCount: u8,
            #[tagval(1)]
            pub CurrentScene: u8,
            #[tagval(2)]
            pub CurrentGroup: u16,
            #[tagval(3)]
            pub SceneValid: bool,
            #[tagval(4)]
            pub RemainingCapacity: u8,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SceneTableSize(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FabricSceneInfo(pub $matter::tlv::MatterList<$matter::definitions::ScenesManagement::types::SceneInfoStruct>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = AddSceneResponse, response_id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddScene {
            #[tagval(0)]
            pub GroupID: u16,
            #[tagval(1)]
            pub SceneID: u8,
            #[tagval(2)]
            pub TransitionTime: u32,
            #[tagval(3)]
            pub SceneName: $matter::tlv::MatterString,
            #[tagval(4)]
            pub ExtensionFieldSetStructs: $matter::tlv::MatterList<$matter::definitions::ScenesManagement::types::ExtensionFieldSetStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddSceneResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub GroupID: u16,
            #[tagval(2)]
            pub SceneID: u8,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1, response = ViewSceneResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ViewScene {
            #[tagval(0)]
            pub GroupID: u16,
            #[tagval(1)]
            pub SceneID: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ViewSceneResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub GroupID: u16,
            #[tagval(2)]
            pub SceneID: u8,
            #[tagval(3)]
            pub TransitionTime: u32,
            #[tagval(4)]
            pub SceneName: $matter::tlv::MatterString,
            #[tagval(5)]
            pub ExtensionFieldSetStructs: $matter::tlv::MatterList<$matter::definitions::ScenesManagement::types::ExtensionFieldSetStruct>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = RemoveSceneResponse, response_id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveScene {
            #[tagval(0)]
            pub GroupID: u16,
            #[tagval(1)]
            pub SceneID: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveSceneResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub GroupID: u16,
            #[tagval(2)]
            pub SceneID: u8,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3, response = RemoveAllScenesResponse, response_id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveAllScenes {
            #[tagval(0)]
            pub GroupID: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveAllScenesResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub GroupID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4, response = StoreSceneResponse, response_id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StoreScene {
            #[tagval(0)]
            pub GroupID: u16,
            #[tagval(1)]
            pub SceneID: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StoreSceneResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub GroupID: u16,
            #[tagval(2)]
            pub SceneID: u8,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RecallScene {
            #[tagval(0)]
            pub GroupID: u16,
            #[tagval(1)]
            pub SceneID: u8,
            #[tagval(2)]
            pub TransitionTime: core::option::Option<$matter::tlv::Nullable<u32>>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6, response = GetSceneMembershipResponse, response_id = 0x6)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetSceneMembership {
            #[tagval(0)]
            pub GroupID: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetSceneMembershipResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub Capacity: $matter::tlv::Nullable<u8>,
            #[tagval(2)]
            pub GroupID: u16,
            #[tagval(3)]
            pub SceneList: $matter::tlv::MatterList<u8>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x40, response = CopySceneResponse, response_id = 0x40)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CopyScene {
            #[tagval(0)]
            pub Mode: $matter::definitions::ScenesManagement::types::CopyModeBitmap,
            #[tagval(1)]
            pub GroupIdentifierFrom: u16,
            #[tagval(2)]
            pub SceneIdentifierFrom: u8,
            #[tagval(3)]
            pub GroupIdentifierTo: u16,
            #[tagval(4)]
            pub SceneIdentifierTo: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CopySceneResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub GroupIdentifierFrom: u16,
            #[tagval(2)]
            pub SceneIdentifierFrom: u8,
        }
    }
    pub mod events {
    }
}
pub mod HEPAFilterMonitoring {
    pub const ID: u32 = 0x0071;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ChangeIndicationEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ChangeIndicationEnum {
            pub const OK: Self = Self(0x0);
            pub const Warning: Self = Self(0x1);
            pub const Critical: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DegradationDirectionEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl DegradationDirectionEnum {
            pub const Up: Self = Self(0x0);
            pub const Down: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ProductIdentifierTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ProductIdentifierTypeEnum {
            pub const UPC: Self = Self(0x0);
            pub const GTIN8: Self = Self(0x1);
            pub const EAN: Self = Self(0x2);
            pub const GTIN14: Self = Self(0x3);
            pub const OEM: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ReplacementProductStruct {
            #[tagval(0)]
            pub ProductIdentifierType: $matter::definitions::HEPAFilterMonitoring::types::ProductIdentifierTypeEnum,
            #[tagval(1)]
            pub ProductIdentifierValue: $matter::tlv::MatterString,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Condition(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DegradationDirection(pub $matter::definitions::HEPAFilterMonitoring::types::DegradationDirectionEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeIndication(pub $matter::definitions::HEPAFilterMonitoring::types::ChangeIndicationEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct InPlaceIndicator(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LastChangedTime(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ReplacementProductList(pub $matter::tlv::MatterList<$matter::definitions::HEPAFilterMonitoring::types::ReplacementProductStruct>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ResetCondition {
        }
    }
    pub mod events {
    }
}
pub mod ActivatedCarbonFilterMonitoring {
    pub const ID: u32 = 0x0072;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ChangeIndicationEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ChangeIndicationEnum {
            pub const OK: Self = Self(0x0);
            pub const Warning: Self = Self(0x1);
            pub const Critical: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DegradationDirectionEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl DegradationDirectionEnum {
            pub const Up: Self = Self(0x0);
            pub const Down: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ProductIdentifierTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ProductIdentifierTypeEnum {
            pub const UPC: Self = Self(0x0);
            pub const GTIN8: Self = Self(0x1);
            pub const EAN: Self = Self(0x2);
            pub const GTIN14: Self = Self(0x3);
            pub const OEM: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ReplacementProductStruct {
            #[tagval(0)]
            pub ProductIdentifierType: $matter::definitions::ActivatedCarbonFilterMonitoring::types::ProductIdentifierTypeEnum,
            #[tagval(1)]
            pub ProductIdentifierValue: $matter::tlv::MatterString,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Condition(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DegradationDirection(pub $matter::definitions::ActivatedCarbonFilterMonitoring::types::DegradationDirectionEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeIndication(pub $matter::definitions::ActivatedCarbonFilterMonitoring::types::ChangeIndicationEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct InPlaceIndicator(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LastChangedTime(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ReplacementProductList(pub $matter::tlv::MatterList<$matter::definitions::ActivatedCarbonFilterMonitoring::types::ReplacementProductStruct>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ResetCondition {
        }
    }
    pub mod events {
    }
}
pub mod WaterTankLevelMonitoring {
    pub const ID: u32 = 0x0079;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ChangeIndicationEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ChangeIndicationEnum {
            pub const OK: Self = Self(0x0);
            pub const Warning: Self = Self(0x1);
            pub const Critical: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DegradationDirectionEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl DegradationDirectionEnum {
            pub const Up: Self = Self(0x0);
            pub const Down: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ProductIdentifierTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ProductIdentifierTypeEnum {
            pub const UPC: Self = Self(0x0);
            pub const GTIN8: Self = Self(0x1);
            pub const EAN: Self = Self(0x2);
            pub const GTIN14: Self = Self(0x3);
            pub const OEM: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ReplacementProductStruct {
            #[tagval(0)]
            pub ProductIdentifierType: $matter::definitions::WaterTankLevelMonitoring::types::ProductIdentifierTypeEnum,
            #[tagval(1)]
            pub ProductIdentifierValue: $matter::tlv::MatterString,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Condition(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DegradationDirection(pub $matter::definitions::WaterTankLevelMonitoring::types::DegradationDirectionEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeIndication(pub $matter::definitions::WaterTankLevelMonitoring::types::ChangeIndicationEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct InPlaceIndicator(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LastChangedTime(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ReplacementProductList(pub $matter::tlv::MatterList<$matter::definitions::WaterTankLevelMonitoring::types::ReplacementProductStruct>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ResetCondition {
        }
    }
    pub mod events {
    }
}
pub mod WakeOnLAN {
    pub const ID: u32 = 0x0503;
    pub mod types {
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MACAddress(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LinkLocalAddress(pub $matter::tlv::MatterBytes);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod PumpConfigurationandControl {
    pub const ID: u32 = 0x0200;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ControlModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ControlModeEnum {
            pub const ConstantSpeed: Self = Self(0x0);
            pub const ConstantPressure: Self = Self(0x1);
            pub const ProportionalPressure: Self = Self(0x2);
            pub const ConstantFlow: Self = Self(0x3);
            pub const ConstantTemperature: Self = Self(0x5);
            pub const Automatic: Self = Self(0x7);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OperationModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl OperationModeEnum {
            pub const Normal: Self = Self(0x0);
            pub const Minimum: Self = Self(0x1);
            pub const Maximum: Self = Self(0x2);
            pub const Local: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct PumpStatusBitmap(pub u16);
        #[allow(non_upper_case_globals)]
        impl PumpStatusBitmap {
            pub const DeviceFault: Self = Self(0x1);
            pub const SupplyFault: Self = Self(0x2);
            pub const SpeedLow: Self = Self(0x4);
            pub const SpeedHigh: Self = Self(0x8);
            pub const LocalOverride: Self = Self(0x10);
            pub const Running: Self = Self(0x20);
            pub const RemotePressure: Self = Self(0x40);
            pub const RemoteFlow: Self = Self(0x80);
            pub const RemoteTemperature: Self = Self(0x100);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxPressure(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxSpeed(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxFlow(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinConstPressure(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxConstPressure(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinCompPressure(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxCompPressure(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinConstSpeed(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxConstSpeed(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinConstFlow(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxConstFlow(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xB, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinConstTemp(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xC, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxConstTemp(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x10, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PumpStatus(pub $matter::definitions::PumpConfigurationandControl::types::PumpStatusBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x11, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EffectiveOperationMode(pub $matter::definitions::PumpConfigurationandControl::types::OperationModeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x12, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EffectiveControlMode(pub $matter::definitions::PumpConfigurationandControl::types::ControlModeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x13, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Capacity(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x14, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Speed(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x15, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LifetimeRunningHours(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x16, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Power(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x17, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LifetimeEnergyConsumed(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x20, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationMode(pub $matter::definitions::PumpConfigurationandControl::types::OperationModeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x21, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ControlMode(pub $matter::definitions::PumpConfigurationandControl::types::ControlModeEnum);
    }
    pub mod commands {
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupplyVoltageLow {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupplyVoltageHigh {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PowerMissingPhase {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SystemPressureLow {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SystemPressureHigh {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DryRunning {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x6)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MotorTemperatureHigh {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x7)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PumpMotorFatalFailure {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x8)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ElectronicTemperatureHigh {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x9)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PumpBlocked {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0xA)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SensorFailure {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0xB)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ElectronicNonFatalFailure {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0xC)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ElectronicFatalFailure {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0xD)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GeneralFault {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0xE)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Leakage {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0xF)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AirDetection {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x10)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TurbineOperation {
        }
    }
}
pub mod TemperatureMeasurement {
    pub const ID: u32 = 0x0402;
    pub mod types {
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasuredValue(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinMeasuredValue(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxMeasuredValue(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Tolerance(pub u16);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod GeneralCommissioning {
    pub const ID: u32 = 0x0030;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct CommissioningErrorEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl CommissioningErrorEnum {
            pub const OK: Self = Self(0x0);
            pub const ValueOutsideRange: Self = Self(0x1);
            pub const InvalidAuthentication: Self = Self(0x2);
            pub const NoFailSafe: Self = Self(0x3);
            pub const BusyWithOtherAdmin: Self = Self(0x4);
            pub const RequiredTCNotAccepted: Self = Self(0x5);
            pub const TCAcknowledgementsNotReceived: Self = Self(0x6);
            pub const TCMinVersionNotMet: Self = Self(0x7);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct NetworkRecoveryReasonEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl NetworkRecoveryReasonEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const Auth: Self = Self(0x1);
            pub const Visibility: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct RegulatoryLocationTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl RegulatoryLocationTypeEnum {
            pub const Indoor: Self = Self(0x0);
            pub const Outdoor: Self = Self(0x1);
            pub const IndoorOutdoor: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BasicCommissioningInfo {
            #[tagval(0)]
            pub FailSafeExpiryLengthSeconds: u16,
            #[tagval(1)]
            pub MaxCumulativeFailsafeSeconds: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Breadcrumb(pub u64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BasicCommissioningInfo(pub $matter::definitions::GeneralCommissioning::types::BasicCommissioningInfo);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RegulatoryConfig(pub $matter::definitions::GeneralCommissioning::types::RegulatoryLocationTypeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LocationCapability(pub $matter::definitions::GeneralCommissioning::types::RegulatoryLocationTypeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportsConcurrentConnection(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TCAcceptedVersion(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TCMinRequiredVersion(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TCAcknowledgements(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TCAcknowledgementsRequired(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TCUpdateDeadline(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RecoveryIdentifier(pub $matter::tlv::MatterBytes);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xB, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NetworkRecoveryReason(pub $matter::tlv::Nullable<$matter::definitions::GeneralCommissioning::types::NetworkRecoveryReasonEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xC, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct IsCommissioningWithoutPower(pub bool);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = ArmFailSafeResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ArmFailSafe {
            #[tagval(0)]
            pub ExpiryLengthSeconds: u16,
            #[tagval(1)]
            pub Breadcrumb: u64,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ArmFailSafeResponse {
            #[tagval(0)]
            pub ErrorCode: $matter::definitions::GeneralCommissioning::types::CommissioningErrorEnum,
            #[tagval(1)]
            pub DebugText: $matter::tlv::MatterString,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = SetRegulatoryConfigResponse, response_id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetRegulatoryConfig {
            #[tagval(0)]
            pub NewRegulatoryConfig: $matter::definitions::GeneralCommissioning::types::RegulatoryLocationTypeEnum,
            #[tagval(1)]
            pub CountryCode: $matter::tlv::MatterString,
            #[tagval(2)]
            pub Breadcrumb: u64,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetRegulatoryConfigResponse {
            #[tagval(0)]
            pub ErrorCode: $matter::definitions::GeneralCommissioning::types::CommissioningErrorEnum,
            #[tagval(1)]
            pub DebugText: $matter::tlv::MatterString,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4, response = CommissioningCompleteResponse, response_id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CommissioningComplete {
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CommissioningCompleteResponse {
            #[tagval(0)]
            pub ErrorCode: $matter::definitions::GeneralCommissioning::types::CommissioningErrorEnum,
            #[tagval(1)]
            pub DebugText: $matter::tlv::MatterString,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6, response = SetTCAcknowledgementsResponse, response_id = 0x7)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetTCAcknowledgements {
            #[tagval(0)]
            pub TCVersion: u16,
            #[tagval(1)]
            pub TCUserResponse: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetTCAcknowledgementsResponse {
            #[tagval(0)]
            pub ErrorCode: $matter::definitions::GeneralCommissioning::types::CommissioningErrorEnum,
        }
    }
    pub mod events {
    }
}
pub mod OperationalCredentials {
    pub const ID: u32 = 0x003E;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct CertificateChainTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl CertificateChainTypeEnum {
            pub const DACCertificate: Self = Self(0x1);
            pub const PAICertificate: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct NodeOperationalCertStatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl NodeOperationalCertStatusEnum {
            pub const OK: Self = Self(0x0);
            pub const InvalidPublicKey: Self = Self(0x1);
            pub const InvalidNodeOpId: Self = Self(0x2);
            pub const InvalidNOC: Self = Self(0x3);
            pub const MissingCsr: Self = Self(0x4);
            pub const TableFull: Self = Self(0x5);
            pub const InvalidAdminSubject: Self = Self(0x6);
            pub const ReservedForFutureUse: Self = Self(0x7);
            pub const ReservedForFutureUse_0x8: Self = Self(0x8);
            pub const FabricConflict: Self = Self(0x9);
            pub const LabelConflict: Self = Self(0xA);
            pub const InvalidFabricIndex: Self = Self(0xB);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FabricDescriptorStruct {
            #[tagval(1)]
            pub RootPublicKey: $matter::tlv::MatterBytes,
            #[tagval(2)]
            pub VendorID: u16,
            #[tagval(3)]
            pub FabricID: u64,
            #[tagval(4)]
            pub NodeID: u64,
            #[tagval(5)]
            pub Label: $matter::tlv::MatterString,
            #[tagval(6)]
            pub VIDVerificationStatement: core::option::Option<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NOCStruct {
            #[tagval(1)]
            pub NOC: $matter::tlv::MatterBytes,
            #[tagval(2)]
            pub ICAC: $matter::tlv::Nullable<$matter::tlv::MatterBytes>,
            #[tagval(3)]
            pub VVSC: $matter::tlv::MatterBytes,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NOCs(pub $matter::tlv::MatterList<$matter::definitions::OperationalCredentials::types::NOCStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Fabrics(pub $matter::tlv::MatterList<$matter::definitions::OperationalCredentials::types::FabricDescriptorStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedFabrics(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CommissionedFabrics(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TrustedRootCertificates(pub $matter::tlv::MatterList<$matter::tlv::MatterBytes>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentFabricIndex(pub u8);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = AttestationResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AttestationRequest {
            #[tagval(0)]
            pub AttestationNonce: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AttestationResponse {
            #[tagval(0)]
            pub AttestationElements: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub AttestationSignature: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = CertificateChainResponse, response_id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CertificateChainRequest {
            #[tagval(0)]
            pub CertificateType: $matter::definitions::OperationalCredentials::types::CertificateChainTypeEnum,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CertificateChainResponse {
            #[tagval(0)]
            pub Certificate: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4, response = CSRResponse, response_id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CSRRequest {
            #[tagval(0)]
            pub CSRNonce: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub IsForUpdateNOC: core::option::Option<bool>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CSRResponse {
            #[tagval(0)]
            pub NOCSRElements: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub AttestationSignature: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6, response = NOCResponse, response_id = 0x8)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddNOC {
            #[tagval(0)]
            pub NOCValue: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub ICACValue: core::option::Option<$matter::tlv::MatterBytes>,
            #[tagval(2)]
            pub IPKValue: $matter::tlv::MatterBytes,
            #[tagval(3)]
            pub CaseAdminSubject: u64,
            #[tagval(4)]
            pub AdminVendorId: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x7, response = NOCResponse, response_id = 0x8)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UpdateNOC {
            #[tagval(0)]
            pub NOCValue: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub ICACValue: core::option::Option<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NOCResponse {
            #[tagval(0)]
            pub StatusCode: $matter::definitions::OperationalCredentials::types::NodeOperationalCertStatusEnum,
            #[tagval(1)]
            pub FabricIndex: u8,
            #[tagval(2)]
            pub DebugText: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x9, response = NOCResponse, response_id = 0x8)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UpdateFabricLabel {
            #[tagval(0)]
            pub Label: $matter::tlv::MatterString,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xA, response = NOCResponse, response_id = 0x8)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveFabric {
            #[tagval(0)]
            pub FabricIndex: u8,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xB)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddTrustedRootCertificate {
            #[tagval(0)]
            pub RootCACertificate: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xC)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetVIDVerificationStatement {
            #[tagval(0)]
            pub VendorID: core::option::Option<u16>,
            #[tagval(1)]
            pub VIDVerificationStatement: core::option::Option<$matter::tlv::MatterBytes>,
            #[tagval(2)]
            pub VVSC: core::option::Option<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xD, response = SignVIDVerificationResponse, response_id = 0xE)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SignVIDVerificationRequest {
            #[tagval(0)]
            pub FabricIndex: u8,
            #[tagval(1)]
            pub ClientChallenge: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SignVIDVerificationResponse {
            #[tagval(0)]
            pub FabricIndex: u8,
            #[tagval(1)]
            pub FabricBindingVersion: u8,
            #[tagval(2)]
            pub Signature: $matter::tlv::MatterBytes,
        }
    }
    pub mod events {
    }
}
pub mod TargetNavigator {
    pub const ID: u32 = 0x0505;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl StatusEnum {
            pub const Success: Self = Self(0x0);
            pub const TargetNotFound: Self = Self(0x1);
            pub const NotAllowed: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TargetInfoStruct {
            #[tagval(0)]
            pub Identifier: u8,
            #[tagval(1)]
            pub Name: $matter::tlv::MatterString,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TargetList(pub $matter::tlv::MatterList<$matter::definitions::TargetNavigator::types::TargetInfoStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentTarget(pub u8);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = NavigateTargetResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NavigateTarget {
            #[tagval(0)]
            pub Target: u8,
            #[tagval(1)]
            pub Data: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NavigateTargetResponse {
            #[tagval(0)]
            pub Status: $matter::definitions::TargetNavigator::types::StatusEnum,
            #[tagval(1)]
            pub Data: core::option::Option<$matter::tlv::MatterString>,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TargetUpdated {
            #[tagval(0)]
            pub TargetList: core::option::Option<$matter::tlv::MatterList<$matter::definitions::TargetNavigator::types::TargetInfoStruct>>,
            #[tagval(1)]
            pub CurrentTarget: core::option::Option<u8>,
            #[tagval(2)]
            pub Data: core::option::Option<$matter::tlv::MatterBytes>,
        }
    }
}
pub mod FanControl {
    pub const ID: u32 = 0x0202;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct AirflowDirectionEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl AirflowDirectionEnum {
            pub const Forward: Self = Self(0x0);
            pub const Reverse: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct FanModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl FanModeEnum {
            pub const Off: Self = Self(0x0);
            pub const Low: Self = Self(0x1);
            pub const Medium: Self = Self(0x2);
            pub const High: Self = Self(0x3);
            pub const On: Self = Self(0x4);
            pub const Auto: Self = Self(0x5);
            pub const Smart: Self = Self(0x6);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct FanModeSequenceEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl FanModeSequenceEnum {
            pub const OffLowMedHigh: Self = Self(0x0);
            pub const OffLowHigh: Self = Self(0x1);
            pub const OffLowMedHighAuto: Self = Self(0x2);
            pub const OffLowHighAuto: Self = Self(0x3);
            pub const OffHighAuto: Self = Self(0x4);
            pub const OffHigh: Self = Self(0x5);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StepDirectionEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl StepDirectionEnum {
            pub const Increase: Self = Self(0x0);
            pub const Decrease: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct RockBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl RockBitmap {
            pub const RockLeftRight: Self = Self(0x1);
            pub const RockUpDown: Self = Self(0x2);
            pub const RockRound: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct WindBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl WindBitmap {
            pub const SleepWind: Self = Self(0x1);
            pub const NaturalWind: Self = Self(0x2);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FanMode(pub $matter::definitions::FanControl::types::FanModeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FanModeSequence(pub $matter::definitions::FanControl::types::FanModeSequenceEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PercentSetting(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PercentCurrent(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SpeedMax(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SpeedSetting(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SpeedCurrent(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RockSupport(pub $matter::definitions::FanControl::types::RockBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RockSetting(pub $matter::definitions::FanControl::types::RockBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WindSupport(pub $matter::definitions::FanControl::types::WindBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WindSetting(pub $matter::definitions::FanControl::types::WindBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xB, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AirflowDirection(pub $matter::definitions::FanControl::types::AirflowDirectionEnum);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Step {
            #[tagval(0)]
            pub Direction: $matter::definitions::FanControl::types::StepDirectionEnum,
            #[tagval(1)]
            pub Wrap: core::option::Option<bool>,
            #[tagval(2)]
            pub LowestOff: core::option::Option<bool>,
        }
    }
    pub mod events {
    }
}
pub mod GlobalElements {
    pub const ID: u32 = 0x0000;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct AtomicRequestTypeEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl AtomicRequestTypeEnum {
            pub const BeginWrite: Self = Self(0x0);
            pub const CommitWrite: Self = Self(0x1);
            pub const RollbackWrite: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct MeasurementTypeEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl MeasurementTypeEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const Voltage: Self = Self(0x1);
            pub const ActiveCurrent: Self = Self(0x2);
            pub const ReactiveCurrent: Self = Self(0x3);
            pub const ApparentCurrent: Self = Self(0x4);
            pub const ActivePower: Self = Self(0x5);
            pub const ReactivePower: Self = Self(0x6);
            pub const ApparentPower: Self = Self(0x7);
            pub const RMSVoltage: Self = Self(0x8);
            pub const RMSCurrent: Self = Self(0x9);
            pub const RMSPower: Self = Self(0xA);
            pub const Frequency: Self = Self(0xB);
            pub const PowerFactor: Self = Self(0xC);
            pub const NeutralCurrent: Self = Self(0xD);
            pub const ElectricalEnergy: Self = Self(0xE);
            pub const ReactiveEnergy: Self = Self(0xF);
            pub const ApparentEnergy: Self = Self(0x10);
            pub const SoilMoisture: Self = Self(0x11);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct PowerThresholdSourceEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl PowerThresholdSourceEnum {
            pub const Contract: Self = Self(0x0);
            pub const Regulator: Self = Self(0x1);
            pub const Equipment: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct SoftwareVersionCertificationStatusEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl SoftwareVersionCertificationStatusEnum {
            pub const devtest: Self = Self(0x0);
            pub const provisional: Self = Self(0x1);
            pub const certified: Self = Self(0x2);
            pub const revoked: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StreamUsageEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl StreamUsageEnum {
            pub const Internal: Self = Self(0x0);
            pub const Recording: Self = Self(0x1);
            pub const Analysis: Self = Self(0x2);
            pub const LiveView: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct TariffPriceTypeEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl TariffPriceTypeEnum {
            pub const Standard: Self = Self(0x0);
            pub const Critical: Self = Self(0x1);
            pub const Virtual: Self = Self(0x2);
            pub const Incentive: Self = Self(0x3);
            pub const IncentiveSignal: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct TariffUnitEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl TariffUnitEnum {
            pub const kWh: Self = Self(0x0);
            pub const kVAh: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ThreeLevelAutoEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl ThreeLevelAutoEnum {
            pub const Auto: Self = Self(0x0);
            pub const Low: Self = Self(0x1);
            pub const Medium: Self = Self(0x2);
            pub const High: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct WebRTCEndReasonEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl WebRTCEndReasonEnum {
            pub const ICEFailed: Self = Self(0x0);
            pub const ICETimeout: Self = Self(0x1);
            pub const UserHangup: Self = Self(0x2);
            pub const UserBusy: Self = Self(0x3);
            pub const Replaced: Self = Self(0x4);
            pub const NoUserMedia: Self = Self(0x5);
            pub const InviteTimeout: Self = Self(0x6);
            pub const AnsweredElsewhere: Self = Self(0x7);
            pub const OutOfResources: Self = Self(0x8);
            pub const MediaTimeout: Self = Self(0x9);
            pub const LowPower: Self = Self(0xA);
            pub const PrivacyMode: Self = Self(0xB);
            pub const UnknownReason: Self = Self(0xC);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct WildcardPathFlagsBitmap(pub u32);
        #[allow(non_upper_case_globals)]
        impl WildcardPathFlagsBitmap {
            pub const WildcardSkipRootNode: Self = Self(0x1);
            pub const WildcardSkipGlobalAttributes: Self = Self(0x2);
            pub const WildcardSkipAttributeList: Self = Self(0x4);
            pub const DoNotUse: Self = Self(0x8);
            pub const WildcardSkipCommandLists: Self = Self(0x10);
            pub const WildcardSkipCustomElements: Self = Self(0x20);
            pub const WildcardSkipFixedAttributes: Self = Self(0x40);
            pub const WildcardSkipChangesOmittedAttributes: Self = Self(0x80);
            pub const WildcardSkipDiagnosticsClusters: Self = Self(0x100);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AtomicAttributeStatusStruct {
            #[tagval(0)]
            pub AttributeID: u32,
            #[tagval(1)]
            pub StatusCode: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrencyStruct {
            #[tagval(0)]
            pub Currency: u16,
            #[tagval(1)]
            pub DecimalPoints: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ICECandidateStruct {
            #[tagval(0)]
            pub Candidate: $matter::tlv::MatterString,
            #[tagval(1)]
            pub SDPMid: $matter::tlv::Nullable<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub SDPMLineIndex: $matter::tlv::Nullable<u16>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ICEServerStruct {
            #[tagval(0)]
            pub URLs: $matter::tlv::MatterList<$matter::tlv::MatterString>,
            #[tagval(1)]
            pub Username: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub Credential: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(3)]
            pub CAID: core::option::Option<u16>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LocationDescriptorStruct {
            #[tagval(0)]
            pub LocationName: $matter::tlv::MatterString,
            #[tagval(1)]
            pub FloorNumber: $matter::tlv::Nullable<i16>,
            #[tagval(2)]
            pub AreaType: $matter::tlv::Nullable<u8>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementAccuracyRangeStruct {
            #[tagval(0)]
            pub RangeMin: i64,
            #[tagval(1)]
            pub RangeMax: i64,
            #[tagval(2)]
            pub PercentMax: core::option::Option<u16>,
            #[tagval(3)]
            pub PercentMin: core::option::Option<u16>,
            #[tagval(4)]
            pub PercentTypical: core::option::Option<u16>,
            #[tagval(5)]
            pub FixedMax: core::option::Option<u64>,
            #[tagval(6)]
            pub FixedMin: core::option::Option<u64>,
            #[tagval(7)]
            pub FixedTypical: core::option::Option<u64>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasurementAccuracyStruct {
            #[tagval(0)]
            pub MeasurementType: $matter::definitions::GlobalElements::types::MeasurementTypeEnum,
            #[tagval(1)]
            pub Measured: bool,
            #[tagval(2)]
            pub MinMeasuredValue: i64,
            #[tagval(3)]
            pub MaxMeasuredValue: i64,
            #[tagval(4)]
            pub AccuracyRanges: $matter::tlv::MatterList<$matter::definitions::GlobalElements::types::MeasurementAccuracyRangeStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PowerThresholdStruct {
            #[tagval(0)]
            pub PowerThreshold: core::option::Option<i64>,
            #[tagval(1)]
            pub ApparentPowerThreshold: core::option::Option<i64>,
            #[tagval(2)]
            pub PowerThresholdSource: $matter::tlv::Nullable<$matter::definitions::GlobalElements::types::PowerThresholdSourceEnum>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PriceStruct {
            #[tagval(0)]
            pub Amount: i64,
            #[tagval(1)]
            pub Currency: $matter::definitions::GlobalElements::types::CurrencyStruct,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SemanticTagStruct {
            #[tagval(0)]
            pub MfgCode: $matter::tlv::Nullable<u16>,
            #[tagval(1)]
            pub NamespaceID: u8,
            #[tagval(2)]
            pub Tag: u8,
            #[tagval(3)]
            pub Label: $matter::tlv::Nullable<$matter::tlv::MatterString>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ViewportStruct {
            #[tagval(0)]
            pub X1: u16,
            #[tagval(1)]
            pub Y1: u16,
            #[tagval(2)]
            pub X2: u16,
            #[tagval(3)]
            pub Y2: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WebRTCSessionStruct {
            #[tagval(0)]
            pub ID: u16,
            #[tagval(1)]
            pub PeerNodeID: u64,
            #[tagval(2)]
            pub PeerEndpointID: u16,
            #[tagval(3)]
            pub StreamUsage: $matter::definitions::GlobalElements::types::StreamUsageEnum,
            #[tagval(4)]
            pub VideoStreamID: core::option::Option<$matter::tlv::Nullable<u16>>,
            #[tagval(5)]
            pub AudioStreamID: core::option::Option<$matter::tlv::Nullable<u16>>,
            #[tagval(6)]
            pub MetadataEnabled: bool,
            #[tagval(7)]
            pub VideoStreams: core::option::Option<$matter::tlv::MatterList<u16>>,
            #[tagval(8)]
            pub AudioStreams: core::option::Option<$matter::tlv::MatterList<u16>>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0xFFFD, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ClusterRevision(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xFFFC, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FeatureMap(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xFFFB, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AttributeList(pub $matter::tlv::MatterList<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xFFFA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EventList(pub $matter::tlv::MatterList<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xFFF9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AcceptedCommandList(pub $matter::tlv::MatterList<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xFFF8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GeneratedCommandList(pub $matter::tlv::MatterList<u32>);
    }
    pub mod commands {
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AtomicResponse {
            #[tagval(0)]
            pub StatusCode: u8,
            #[tagval(1)]
            pub AttributeStatus: $matter::tlv::MatterList<$matter::definitions::GlobalElements::types::AtomicAttributeStatusStruct>,
            #[tagval(2)]
            pub Timeout: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xFE, response = AtomicResponse, response_id = 0xFD)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AtomicRequest {
            #[tagval(0)]
            pub RequestType: $matter::definitions::GlobalElements::types::AtomicRequestTypeEnum,
            #[tagval(1)]
            pub AttributeRequests: $matter::tlv::MatterList<u32>,
            #[tagval(2)]
            pub Timeout: u16,
        }
    }
    pub mod events {
    }
}
pub mod DoorLock {
    pub const ID: u32 = 0x0101;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct AlarmCodeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl AlarmCodeEnum {
            pub const LockJammed: Self = Self(0x0);
            pub const LockFactoryReset: Self = Self(0x1);
            pub const LockRadioPowerCycled: Self = Self(0x3);
            pub const WrongCodeEntryLimit: Self = Self(0x4);
            pub const FrontEsceutcheonRemoved: Self = Self(0x5);
            pub const DoorForcedOpen: Self = Self(0x6);
            pub const DoorAjar: Self = Self(0x7);
            pub const ForcedUser: Self = Self(0x8);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct CredentialRuleEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl CredentialRuleEnum {
            pub const Single: Self = Self(0x0);
            pub const Dual: Self = Self(0x1);
            pub const Tri: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct CredentialTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl CredentialTypeEnum {
            pub const ProgrammingPIN: Self = Self(0x0);
            pub const PIN: Self = Self(0x1);
            pub const RFID: Self = Self(0x2);
            pub const Fingerprint: Self = Self(0x3);
            pub const FingerVein: Self = Self(0x4);
            pub const Face: Self = Self(0x5);
            pub const AliroCredentialIssuerKey: Self = Self(0x6);
            pub const AliroEvictableEndpointKey: Self = Self(0x7);
            pub const AliroNonEvictableEndpointKey: Self = Self(0x8);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DataOperationTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl DataOperationTypeEnum {
            pub const Add: Self = Self(0x0);
            pub const Clear: Self = Self(0x1);
            pub const Modify: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DoorStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl DoorStateEnum {
            pub const DoorOpen: Self = Self(0x0);
            pub const DoorClosed: Self = Self(0x1);
            pub const DoorJammed: Self = Self(0x2);
            pub const DoorForcedOpen: Self = Self(0x3);
            pub const DoorUnspecifiedError: Self = Self(0x4);
            pub const DoorAjar: Self = Self(0x5);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct EventTypeEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl EventTypeEnum {
            pub const Operation: Self = Self(0x0);
            pub const Programming: Self = Self(0x1);
            pub const Alarm: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LEDSettingEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl LEDSettingEnum {
            pub const NoLEDSignal: Self = Self(0x0);
            pub const NoLEDSignalAccessAllowed: Self = Self(0x1);
            pub const LEDSignalAll: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LockDataTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl LockDataTypeEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const ProgrammingCode: Self = Self(0x1);
            pub const UserIndex: Self = Self(0x2);
            pub const WeekDaySchedule: Self = Self(0x3);
            pub const YearDaySchedule: Self = Self(0x4);
            pub const HolidaySchedule: Self = Self(0x5);
            pub const PIN: Self = Self(0x6);
            pub const RFID: Self = Self(0x7);
            pub const Fingerprint: Self = Self(0x8);
            pub const FingerVein: Self = Self(0x9);
            pub const Face: Self = Self(0xA);
            pub const AliroCredentialIssuerKey: Self = Self(0xB);
            pub const AliroEvictableEndpointKey: Self = Self(0xC);
            pub const AliroNonEvictableEndpointKey: Self = Self(0xD);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LockOperationTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl LockOperationTypeEnum {
            pub const Lock: Self = Self(0x0);
            pub const Unlock: Self = Self(0x1);
            pub const NonAccessUserEvent: Self = Self(0x2);
            pub const ForcedUserEvent: Self = Self(0x3);
            pub const Unlatch: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LockStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl LockStateEnum {
            pub const NotFullyLocked: Self = Self(0x0);
            pub const Locked: Self = Self(0x1);
            pub const Unlocked: Self = Self(0x2);
            pub const Unlatched: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LockTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl LockTypeEnum {
            pub const DeadBolt: Self = Self(0x0);
            pub const Magnetic: Self = Self(0x1);
            pub const Other: Self = Self(0x2);
            pub const Mortise: Self = Self(0x3);
            pub const Rim: Self = Self(0x4);
            pub const LatchBolt: Self = Self(0x5);
            pub const CylindricalLock: Self = Self(0x6);
            pub const TubularLock: Self = Self(0x7);
            pub const InterconnectedLock: Self = Self(0x8);
            pub const DeadLatch: Self = Self(0x9);
            pub const DoorFurniture: Self = Self(0xA);
            pub const Eurocylinder: Self = Self(0xB);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OperatingModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl OperatingModeEnum {
            pub const Normal: Self = Self(0x0);
            pub const Vacation: Self = Self(0x1);
            pub const Privacy: Self = Self(0x2);
            pub const NoRemoteLockUnlock: Self = Self(0x3);
            pub const Passage: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OperationErrorEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl OperationErrorEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const InvalidCredential: Self = Self(0x1);
            pub const DisabledUserDenied: Self = Self(0x2);
            pub const Restricted: Self = Self(0x3);
            pub const InsufficientBattery: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OperationSourceEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl OperationSourceEnum {
            pub const Unspecified: Self = Self(0x0);
            pub const Manual: Self = Self(0x1);
            pub const ProprietaryRemote: Self = Self(0x2);
            pub const Keypad: Self = Self(0x3);
            pub const Auto: Self = Self(0x4);
            pub const Button: Self = Self(0x5);
            pub const Schedule: Self = Self(0x6);
            pub const Remote: Self = Self(0x7);
            pub const RFID: Self = Self(0x8);
            pub const Biometric: Self = Self(0x9);
            pub const Aliro: Self = Self(0xA);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct SoundVolumeEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl SoundVolumeEnum {
            pub const Silent: Self = Self(0x0);
            pub const Low: Self = Self(0x1);
            pub const High: Self = Self(0x2);
            pub const Medium: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusCodeEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl StatusCodeEnum {
            pub const DUPLICATE: Self = Self(0x2);
            pub const OCCUPIED: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct UserStatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl UserStatusEnum {
            pub const Available: Self = Self(0x0);
            pub const OccupiedEnabled: Self = Self(0x1);
            pub const OccupiedDisabled: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct UserTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl UserTypeEnum {
            pub const UnrestrictedUser: Self = Self(0x0);
            pub const YearDayScheduleUser: Self = Self(0x1);
            pub const WeekDayScheduleUser: Self = Self(0x2);
            pub const ProgrammingUser: Self = Self(0x3);
            pub const NonAccessUser: Self = Self(0x4);
            pub const ForcedUser: Self = Self(0x5);
            pub const DisposableUser: Self = Self(0x6);
            pub const ExpiringUser: Self = Self(0x7);
            pub const ScheduleRestrictedUser: Self = Self(0x8);
            pub const RemoteOnlyUser: Self = Self(0x9);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct AlarmMaskBitmap(pub u32);
        #[allow(non_upper_case_globals)]
        impl AlarmMaskBitmap {
            pub const LockJammed: Self = Self(0x1);
            pub const LockFactoryReset: Self = Self(0x2);
            pub const LockRadioPowerCycled: Self = Self(0x8);
            pub const WrongCodeEntryLimit: Self = Self(0x10);
            pub const FrontEscutcheonRemoved: Self = Self(0x20);
            pub const DoorForcedOpen: Self = Self(0x40);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ConfigurationRegisterBitmap(pub u16);
        #[allow(non_upper_case_globals)]
        impl ConfigurationRegisterBitmap {
            pub const LocalProgramming: Self = Self(0x1);
            pub const KeypadInterface: Self = Self(0x2);
            pub const RemoteInterface: Self = Self(0x4);
            pub const SoundVolume: Self = Self(0x20);
            pub const AutoRelockTime: Self = Self(0x40);
            pub const LEDSettings: Self = Self(0x80);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct CredentialRulesBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl CredentialRulesBitmap {
            pub const Single: Self = Self(0x1);
            pub const Dual: Self = Self(0x2);
            pub const Tri: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DaysMaskBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl DaysMaskBitmap {
            pub const Sunday: Self = Self(0x1);
            pub const Monday: Self = Self(0x2);
            pub const Tuesday: Self = Self(0x4);
            pub const Wednesday: Self = Self(0x8);
            pub const Thursday: Self = Self(0x10);
            pub const Friday: Self = Self(0x20);
            pub const Saturday: Self = Self(0x40);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LocalProgrammingFeaturesBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl LocalProgrammingFeaturesBitmap {
            pub const AddUsersCredentialsSchedules: Self = Self(0x1);
            pub const ModifyUsersCredentialsSchedules: Self = Self(0x2);
            pub const ClearUsersCredentialsSchedules: Self = Self(0x4);
            pub const AdjustSettings: Self = Self(0x8);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OperatingModesBitmap(pub u16);
        #[allow(non_upper_case_globals)]
        impl OperatingModesBitmap {
            pub const Normal: Self = Self(0x1);
            pub const Vacation: Self = Self(0x2);
            pub const Privacy: Self = Self(0x4);
            pub const NoRemoteLockUnlock: Self = Self(0x8);
            pub const Passage: Self = Self(0x10);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CredentialStruct {
            #[tagval(0)]
            pub CredentialType: $matter::definitions::DoorLock::types::CredentialTypeEnum,
            #[tagval(1)]
            pub CredentialIndex: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LockState(pub $matter::tlv::Nullable<$matter::definitions::DoorLock::types::LockStateEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LockType(pub $matter::definitions::DoorLock::types::LockTypeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActuatorEnabled(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DoorState(pub $matter::tlv::Nullable<$matter::definitions::DoorLock::types::DoorStateEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DoorOpenEvents(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DoorClosedEvents(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OpenPeriod(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x11, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfTotalUsersSupported(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x12, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfPINUsersSupported(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x13, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfRFIDUsersSupported(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x14, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfWeekDaySchedulesSupportedPerUser(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x15, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfYearDaySchedulesSupportedPerUser(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x16, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfHolidaySchedulesSupported(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x17, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxPINCodeLength(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x18, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinPINCodeLength(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x19, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxRFIDCodeLength(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1A, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinRFIDCodeLength(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1B, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CredentialRulesSupport(pub $matter::definitions::DoorLock::types::CredentialRulesBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1C, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfCredentialsSupportedPerUser(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x21, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Language(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x22, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LEDSettings(pub $matter::definitions::DoorLock::types::LEDSettingEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x23, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AutoRelockTime(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x24, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SoundVolume(pub $matter::definitions::DoorLock::types::SoundVolumeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x25, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperatingMode(pub $matter::definitions::DoorLock::types::OperatingModeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x26, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedOperatingModes(pub $matter::definitions::DoorLock::types::OperatingModesBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x27, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DefaultConfigurationRegister(pub $matter::definitions::DoorLock::types::ConfigurationRegisterBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x28, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnableLocalProgramming(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x29, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnableOneTouchLocking(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2A, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnableInsideStatusLED(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2B, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EnablePrivacyModeButton(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2C, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LocalProgrammingFeatures(pub $matter::definitions::DoorLock::types::LocalProgrammingFeaturesBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x30, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WrongCodeEntryLimit(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x31, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UserCodeTemporaryDisableTime(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x32, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SendPINOverTheAir(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x33, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RequirePINforRemoteOperation(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x35, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ExpiringUserTimeout(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x80, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AliroReaderVerificationKey(pub $matter::tlv::Nullable<$matter::tlv::MatterBytes>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x81, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AliroReaderGroupIdentifier(pub $matter::tlv::Nullable<$matter::tlv::MatterBytes>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x82, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AliroReaderGroupSubIdentifier(pub $matter::tlv::MatterBytes);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x83, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AliroExpeditedTransactionSupportedProtocolVersions(pub $matter::tlv::MatterList<$matter::tlv::MatterBytes>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x84, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AliroGroupResolvingKey(pub $matter::tlv::Nullable<$matter::tlv::MatterBytes>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x85, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AliroSupportedBLEUWBProtocolVersions(pub $matter::tlv::MatterList<$matter::tlv::MatterBytes>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x86, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AliroBLEAdvertisingVersion(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x87, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfAliroCredentialIssuerKeysSupported(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x88, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfAliroEndpointKeysSupported(pub u16);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LockDoor {
            #[tagval(0)]
            pub PINCode: core::option::Option<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UnlockDoor {
            #[tagval(0)]
            pub PINCode: core::option::Option<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Toggle {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UnlockWithTimeout {
            #[tagval(0)]
            pub Timeout: u16,
            #[tagval(1)]
            pub PINCode: core::option::Option<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xB)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetWeekDaySchedule {
            #[tagval(0)]
            pub WeekDayIndex: u8,
            #[tagval(1)]
            pub UserIndex: u16,
            #[tagval(2)]
            pub DaysMask: $matter::definitions::DoorLock::types::DaysMaskBitmap,
            #[tagval(3)]
            pub StartHour: u8,
            #[tagval(4)]
            pub StartMinute: u8,
            #[tagval(5)]
            pub EndHour: u8,
            #[tagval(6)]
            pub EndMinute: u8,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xC, response = GetWeekDayScheduleResponse, response_id = 0xC)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetWeekDaySchedule {
            #[tagval(0)]
            pub WeekDayIndex: u8,
            #[tagval(1)]
            pub UserIndex: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetWeekDayScheduleResponse {
            #[tagval(0)]
            pub WeekDayIndex: u8,
            #[tagval(1)]
            pub UserIndex: u16,
            #[tagval(2)]
            pub Status: u8,
            #[tagval(3)]
            pub DaysMask: core::option::Option<$matter::definitions::DoorLock::types::DaysMaskBitmap>,
            #[tagval(4)]
            pub StartHour: core::option::Option<u8>,
            #[tagval(5)]
            pub StartMinute: core::option::Option<u8>,
            #[tagval(6)]
            pub EndHour: core::option::Option<u8>,
            #[tagval(7)]
            pub EndMinute: core::option::Option<u8>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xD)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ClearWeekDaySchedule {
            #[tagval(0)]
            pub WeekDayIndex: u8,
            #[tagval(1)]
            pub UserIndex: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xE)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetYearDaySchedule {
            #[tagval(0)]
            pub YearDayIndex: u8,
            #[tagval(1)]
            pub UserIndex: u16,
            #[tagval(2)]
            pub LocalStartTime: u32,
            #[tagval(3)]
            pub LocalEndTime: u32,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xF, response = GetYearDayScheduleResponse, response_id = 0xF)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetYearDaySchedule {
            #[tagval(0)]
            pub YearDayIndex: u8,
            #[tagval(1)]
            pub UserIndex: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetYearDayScheduleResponse {
            #[tagval(0)]
            pub YearDayIndex: u8,
            #[tagval(1)]
            pub UserIndex: u16,
            #[tagval(2)]
            pub Status: u8,
            #[tagval(3)]
            pub LocalStartTime: core::option::Option<u32>,
            #[tagval(4)]
            pub LocalEndTime: core::option::Option<u32>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x10)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ClearYearDaySchedule {
            #[tagval(0)]
            pub YearDayIndex: u8,
            #[tagval(1)]
            pub UserIndex: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x11)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetHolidaySchedule {
            #[tagval(0)]
            pub HolidayIndex: u8,
            #[tagval(1)]
            pub LocalStartTime: u32,
            #[tagval(2)]
            pub LocalEndTime: u32,
            #[tagval(3)]
            pub OperatingMode: $matter::definitions::DoorLock::types::OperatingModeEnum,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x12, response = GetHolidayScheduleResponse, response_id = 0x12)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetHolidaySchedule {
            #[tagval(0)]
            pub HolidayIndex: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetHolidayScheduleResponse {
            #[tagval(0)]
            pub HolidayIndex: u8,
            #[tagval(1)]
            pub Status: u8,
            #[tagval(2)]
            pub LocalStartTime: core::option::Option<$matter::tlv::Nullable<u32>>,
            #[tagval(3)]
            pub LocalEndTime: core::option::Option<$matter::tlv::Nullable<u32>>,
            #[tagval(4)]
            pub OperatingMode: core::option::Option<$matter::tlv::Nullable<$matter::definitions::DoorLock::types::OperatingModeEnum>>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x13)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ClearHolidaySchedule {
            #[tagval(0)]
            pub HolidayIndex: u8,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1A)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetUser {
            #[tagval(0)]
            pub OperationType: $matter::definitions::DoorLock::types::DataOperationTypeEnum,
            #[tagval(1)]
            pub UserIndex: u16,
            #[tagval(2)]
            pub UserName: $matter::tlv::Nullable<$matter::tlv::MatterString>,
            #[tagval(3)]
            pub UserUniqueID: $matter::tlv::Nullable<u32>,
            #[tagval(4)]
            pub UserStatus: $matter::tlv::Nullable<$matter::definitions::DoorLock::types::UserStatusEnum>,
            #[tagval(5)]
            pub UserType: $matter::tlv::Nullable<$matter::definitions::DoorLock::types::UserTypeEnum>,
            #[tagval(6)]
            pub CredentialRule: $matter::tlv::Nullable<$matter::definitions::DoorLock::types::CredentialRuleEnum>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1B, response = GetUserResponse, response_id = 0x1C)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetUser {
            #[tagval(0)]
            pub UserIndex: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetUserResponse {
            #[tagval(0)]
            pub UserIndex: u16,
            #[tagval(1)]
            pub UserName: $matter::tlv::Nullable<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub UserUniqueID: $matter::tlv::Nullable<u32>,
            #[tagval(3)]
            pub UserStatus: $matter::tlv::Nullable<$matter::definitions::DoorLock::types::UserStatusEnum>,
            #[tagval(4)]
            pub UserType: $matter::tlv::Nullable<$matter::definitions::DoorLock::types::UserTypeEnum>,
            #[tagval(5)]
            pub CredentialRule: $matter::tlv::Nullable<$matter::definitions::DoorLock::types::CredentialRuleEnum>,
            #[tagval(6)]
            pub Credentials: $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::DoorLock::types::CredentialStruct>>,
            #[tagval(7)]
            pub CreatorFabricIndex: $matter::tlv::Nullable<u8>,
            #[tagval(8)]
            pub LastModifiedFabricIndex: $matter::tlv::Nullable<u8>,
            #[tagval(9)]
            pub NextUserIndex: $matter::tlv::Nullable<u16>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1D)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ClearUser {
            #[tagval(0)]
            pub UserIndex: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x22, response = SetCredentialResponse, response_id = 0x23)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetCredential {
            #[tagval(0)]
            pub OperationType: $matter::definitions::DoorLock::types::DataOperationTypeEnum,
            #[tagval(1)]
            pub Credential: $matter::definitions::DoorLock::types::CredentialStruct,
            #[tagval(2)]
            pub CredentialData: $matter::tlv::MatterBytes,
            #[tagval(3)]
            pub UserIndex: $matter::tlv::Nullable<u16>,
            #[tagval(4)]
            pub UserStatus: $matter::tlv::Nullable<$matter::definitions::DoorLock::types::UserStatusEnum>,
            #[tagval(5)]
            pub UserType: $matter::tlv::Nullable<$matter::definitions::DoorLock::types::UserTypeEnum>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetCredentialResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub UserIndex: $matter::tlv::Nullable<u16>,
            #[tagval(2)]
            pub NextCredentialIndex: core::option::Option<$matter::tlv::Nullable<u16>>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x24, response = GetCredentialStatusResponse, response_id = 0x25)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetCredentialStatus {
            #[tagval(0)]
            pub Credential: $matter::definitions::DoorLock::types::CredentialStruct,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetCredentialStatusResponse {
            #[tagval(0)]
            pub CredentialExists: bool,
            #[tagval(1)]
            pub UserIndex: $matter::tlv::Nullable<u16>,
            #[tagval(2)]
            pub CreatorFabricIndex: $matter::tlv::Nullable<u8>,
            #[tagval(3)]
            pub LastModifiedFabricIndex: $matter::tlv::Nullable<u8>,
            #[tagval(4)]
            pub NextCredentialIndex: core::option::Option<$matter::tlv::Nullable<u16>>,
            #[tagval(5)]
            pub CredentialData: core::option::Option<$matter::tlv::Nullable<$matter::tlv::MatterBytes>>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x26)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ClearCredential {
            #[tagval(0)]
            pub Credential: $matter::tlv::Nullable<$matter::definitions::DoorLock::types::CredentialStruct>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x27)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UnboltDoor {
            #[tagval(0)]
            pub PINCode: core::option::Option<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x28)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetAliroReaderConfig {
            #[tagval(0)]
            pub SigningKey: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub VerificationKey: $matter::tlv::MatterBytes,
            #[tagval(2)]
            pub GroupIdentifier: $matter::tlv::MatterBytes,
            #[tagval(3)]
            pub GroupResolvingKey: core::option::Option<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x29)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ClearAliroReaderConfig {
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DoorLockAlarm {
            #[tagval(0)]
            pub AlarmCode: $matter::definitions::DoorLock::types::AlarmCodeEnum,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DoorStateChange {
            #[tagval(0)]
            pub DoorState: $matter::definitions::DoorLock::types::DoorStateEnum,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LockOperation {
            #[tagval(0)]
            pub LockOperationType: $matter::definitions::DoorLock::types::LockOperationTypeEnum,
            #[tagval(1)]
            pub OperationSource: $matter::definitions::DoorLock::types::OperationSourceEnum,
            #[tagval(2)]
            pub UserIndex: $matter::tlv::Nullable<u16>,
            #[tagval(3)]
            pub FabricIndex: $matter::tlv::Nullable<u8>,
            #[tagval(4)]
            pub SourceNode: $matter::tlv::Nullable<u64>,
            #[tagval(5)]
            pub Credentials: core::option::Option<$matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::DoorLock::types::CredentialStruct>>>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LockOperationError {
            #[tagval(0)]
            pub LockOperationType: $matter::definitions::DoorLock::types::LockOperationTypeEnum,
            #[tagval(1)]
            pub OperationSource: $matter::definitions::DoorLock::types::OperationSourceEnum,
            #[tagval(2)]
            pub OperationError: $matter::definitions::DoorLock::types::OperationErrorEnum,
            #[tagval(3)]
            pub UserIndex: $matter::tlv::Nullable<u16>,
            #[tagval(4)]
            pub FabricIndex: $matter::tlv::Nullable<u8>,
            #[tagval(5)]
            pub SourceNode: $matter::tlv::Nullable<u64>,
            #[tagval(6)]
            pub Credentials: core::option::Option<$matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::DoorLock::types::CredentialStruct>>>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LockUserChange {
            #[tagval(0)]
            pub LockDataType: $matter::definitions::DoorLock::types::LockDataTypeEnum,
            #[tagval(1)]
            pub DataOperationType: $matter::definitions::DoorLock::types::DataOperationTypeEnum,
            #[tagval(2)]
            pub OperationSource: $matter::definitions::DoorLock::types::OperationSourceEnum,
            #[tagval(3)]
            pub UserIndex: $matter::tlv::Nullable<u16>,
            #[tagval(4)]
            pub FabricIndex: $matter::tlv::Nullable<u8>,
            #[tagval(5)]
            pub SourceNode: $matter::tlv::Nullable<u64>,
            #[tagval(6)]
            pub DataIndex: $matter::tlv::Nullable<u16>,
        }
    }
}
pub mod FlowMeasurement {
    pub const ID: u32 = 0x0404;
    pub mod types {
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasuredValue(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinMeasuredValue(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxMeasuredValue(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Tolerance(pub u16);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod WebRTCTransportProvider {
    pub const ID: u32 = 0x0553;
    pub mod types {
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SFrameStruct {
            #[tagval(0)]
            pub CipherSuite: u16,
            #[tagval(1)]
            pub BaseKey: $matter::tlv::MatterBytes,
            #[tagval(2)]
            pub KID: $matter::tlv::MatterBytes,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentSessions(pub $matter::tlv::MatterList<$matter::definitions::GlobalElements::types::WebRTCSessionStruct>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = SolicitOfferResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SolicitOffer {
            #[tagval(0)]
            pub StreamUsage: $matter::definitions::GlobalElements::types::StreamUsageEnum,
            #[tagval(1)]
            pub OriginatingEndpointID: u16,
            #[tagval(2)]
            pub VideoStreamID: core::option::Option<$matter::tlv::Nullable<u16>>,
            #[tagval(3)]
            pub AudioStreamID: core::option::Option<$matter::tlv::Nullable<u16>>,
            #[tagval(4)]
            pub ICEServers: core::option::Option<$matter::tlv::MatterList<$matter::definitions::GlobalElements::types::ICEServerStruct>>,
            #[tagval(5)]
            pub ICETransportPolicy: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(6)]
            pub MetadataEnabled: core::option::Option<bool>,
            #[tagval(7)]
            pub SFrameConfig: core::option::Option<$matter::definitions::WebRTCTransportProvider::types::SFrameStruct>,
            #[tagval(8)]
            pub VideoStreams: core::option::Option<$matter::tlv::MatterList<u16>>,
            #[tagval(9)]
            pub AudioStreams: core::option::Option<$matter::tlv::MatterList<u16>>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SolicitOfferResponse {
            #[tagval(0)]
            pub WebRTCSessionID: u16,
            #[tagval(1)]
            pub DeferredOffer: bool,
            #[tagval(2)]
            pub VideoStreamID: $matter::tlv::Nullable<u16>,
            #[tagval(3)]
            pub AudioStreamID: $matter::tlv::Nullable<u16>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = ProvideOfferResponse, response_id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProvideOffer {
            #[tagval(0)]
            pub WebRTCSessionID: $matter::tlv::Nullable<u16>,
            #[tagval(1)]
            pub SDP: $matter::tlv::MatterString,
            #[tagval(2)]
            pub StreamUsage: $matter::definitions::GlobalElements::types::StreamUsageEnum,
            #[tagval(3)]
            pub OriginatingEndpointID: u16,
            #[tagval(4)]
            pub VideoStreamID: core::option::Option<$matter::tlv::Nullable<u16>>,
            #[tagval(5)]
            pub AudioStreamID: core::option::Option<$matter::tlv::Nullable<u16>>,
            #[tagval(6)]
            pub ICEServers: core::option::Option<$matter::tlv::MatterList<$matter::definitions::GlobalElements::types::ICEServerStruct>>,
            #[tagval(7)]
            pub ICETransportPolicy: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(8)]
            pub MetadataEnabled: core::option::Option<bool>,
            #[tagval(9)]
            pub SFrameConfig: core::option::Option<$matter::definitions::WebRTCTransportProvider::types::SFrameStruct>,
            #[tagval(10)]
            pub VideoStreams: core::option::Option<$matter::tlv::MatterList<u16>>,
            #[tagval(11)]
            pub AudioStreams: core::option::Option<$matter::tlv::MatterList<u16>>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProvideOfferResponse {
            #[tagval(0)]
            pub WebRTCSessionID: u16,
            #[tagval(1)]
            pub VideoStreamID: $matter::tlv::Nullable<u16>,
            #[tagval(2)]
            pub AudioStreamID: $matter::tlv::Nullable<u16>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProvideAnswer {
            #[tagval(0)]
            pub WebRTCSessionID: u16,
            #[tagval(1)]
            pub SDP: $matter::tlv::MatterString,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProvideICECandidates {
            #[tagval(0)]
            pub WebRTCSessionID: u16,
            #[tagval(1)]
            pub ICECandidates: $matter::tlv::MatterList<$matter::definitions::GlobalElements::types::ICECandidateStruct>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EndSession {
            #[tagval(0)]
            pub WebRTCSessionID: u16,
            #[tagval(1)]
            pub Reason: $matter::definitions::GlobalElements::types::WebRTCEndReasonEnum,
        }
    }
    pub mod events {
    }
}
pub mod ThreadBorderRouterManagement {
    pub const ID: u32 = 0x0452;
    pub mod types {
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BorderRouterName(pub $matter::tlv::MatterString);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct BorderAgentID(pub $matter::tlv::MatterBytes);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ThreadVersion(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct InterfaceEnabled(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveDatasetTimestamp(pub $matter::tlv::Nullable<u64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PendingDatasetTimestamp(pub $matter::tlv::Nullable<u64>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = DatasetResponse, response_id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetActiveDatasetRequest {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1, response = DatasetResponse, response_id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetPendingDatasetRequest {
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DatasetResponse {
            #[tagval(0)]
            pub Dataset: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetActiveDatasetRequest {
            #[tagval(0)]
            pub ActiveDataset: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub Breadcrumb: core::option::Option<u64>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetPendingDatasetRequest {
            #[tagval(0)]
            pub PendingDataset: $matter::tlv::MatterBytes,
        }
    }
    pub mod events {
    }
}
pub mod CameraAVStreamManagement {
    pub const ID: u32 = 0x0551;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct AudioCodecEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl AudioCodecEnum {
            pub const OPUS: Self = Self(0x0);
            pub const AACLC: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ImageCodecEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ImageCodecEnum {
            pub const JPEG: Self = Self(0x0);
            pub const HEIC: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct TriStateAutoEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl TriStateAutoEnum {
            pub const Off: Self = Self(0x0);
            pub const On: Self = Self(0x1);
            pub const Auto: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct TwoWayTalkSupportTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl TwoWayTalkSupportTypeEnum {
            pub const NotSupported: Self = Self(0x0);
            pub const HalfDuplex: Self = Self(0x1);
            pub const FullDuplex: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct VideoCodecEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl VideoCodecEnum {
            pub const H264: Self = Self(0x0);
            pub const HEVC: Self = Self(0x1);
            pub const VVC: Self = Self(0x2);
            pub const AV1: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AVMetadataStruct {
            #[tagval(1)]
            pub UTCTime: $matter::tlv::Nullable<u64>,
            #[tagval(2)]
            pub MotionZonesActive: core::option::Option<$matter::tlv::MatterList<u16>>,
            #[tagval(3)]
            pub BlackAndWhiteActive: core::option::Option<bool>,
            #[tagval(4)]
            pub UserDefined: core::option::Option<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AudioCapabilitiesStruct {
            #[tagval(0)]
            pub MaxNumberOfChannels: u8,
            #[tagval(1)]
            pub SupportedCodecs: $matter::tlv::MatterList<$matter::definitions::CameraAVStreamManagement::types::AudioCodecEnum>,
            #[tagval(2)]
            pub SupportedSampleRates: $matter::tlv::MatterList<u32>,
            #[tagval(3)]
            pub SupportedBitDepths: $matter::tlv::MatterList<u8>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AudioStreamStruct {
            #[tagval(0)]
            pub AudioStreamID: u16,
            #[tagval(1)]
            pub StreamUsage: $matter::definitions::GlobalElements::types::StreamUsageEnum,
            #[tagval(2)]
            pub AudioCodec: $matter::definitions::CameraAVStreamManagement::types::AudioCodecEnum,
            #[tagval(3)]
            pub ChannelCount: u8,
            #[tagval(4)]
            pub SampleRate: u32,
            #[tagval(5)]
            pub BitRate: u32,
            #[tagval(6)]
            pub BitDepth: u8,
            #[tagval(7)]
            pub ReferenceCount: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RateDistortionTradeOffPointsStruct {
            #[tagval(0)]
            pub Codec: $matter::definitions::CameraAVStreamManagement::types::VideoCodecEnum,
            #[tagval(1)]
            pub Resolution: $matter::definitions::CameraAVStreamManagement::types::VideoResolutionStruct,
            #[tagval(2)]
            pub MinBitRate: u32,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SnapshotCapabilitiesStruct {
            #[tagval(0)]
            pub Resolution: $matter::definitions::CameraAVStreamManagement::types::VideoResolutionStruct,
            #[tagval(1)]
            pub MaxFrameRate: u16,
            #[tagval(2)]
            pub ImageCodec: $matter::definitions::CameraAVStreamManagement::types::ImageCodecEnum,
            #[tagval(3)]
            pub RequiresEncodedPixels: bool,
            #[tagval(4)]
            pub RequiresHardwareEncoder: bool,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SnapshotStreamStruct {
            #[tagval(0)]
            pub SnapshotStreamID: u16,
            #[tagval(1)]
            pub ImageCodec: $matter::definitions::CameraAVStreamManagement::types::ImageCodecEnum,
            #[tagval(2)]
            pub FrameRate: u16,
            #[tagval(3)]
            pub MinResolution: $matter::definitions::CameraAVStreamManagement::types::VideoResolutionStruct,
            #[tagval(4)]
            pub MaxResolution: $matter::definitions::CameraAVStreamManagement::types::VideoResolutionStruct,
            #[tagval(5)]
            pub Quality: u8,
            #[tagval(6)]
            pub ReferenceCount: u8,
            #[tagval(7)]
            pub EncodedPixels: bool,
            #[tagval(8)]
            pub HardwareEncoder: bool,
            #[tagval(9)]
            pub WatermarkEnabled: core::option::Option<bool>,
            #[tagval(10)]
            pub OSDEnabled: core::option::Option<bool>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct VideoResolutionStruct {
            #[tagval(0)]
            pub Width: u16,
            #[tagval(1)]
            pub Height: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct VideoSensorParamsStruct {
            #[tagval(0)]
            pub SensorWidth: u16,
            #[tagval(1)]
            pub SensorHeight: u16,
            #[tagval(2)]
            pub MaxFPS: u16,
            #[tagval(3)]
            pub MaxHDRFPS: core::option::Option<u16>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct VideoStreamStruct {
            #[tagval(0)]
            pub VideoStreamID: u16,
            #[tagval(1)]
            pub StreamUsage: $matter::definitions::GlobalElements::types::StreamUsageEnum,
            #[tagval(2)]
            pub VideoCodec: $matter::definitions::CameraAVStreamManagement::types::VideoCodecEnum,
            #[tagval(3)]
            pub MinFrameRate: u16,
            #[tagval(4)]
            pub MaxFrameRate: u16,
            #[tagval(5)]
            pub MinResolution: $matter::definitions::CameraAVStreamManagement::types::VideoResolutionStruct,
            #[tagval(6)]
            pub MaxResolution: $matter::definitions::CameraAVStreamManagement::types::VideoResolutionStruct,
            #[tagval(7)]
            pub MinBitRate: u32,
            #[tagval(8)]
            pub MaxBitRate: u32,
            #[tagval(9)]
            pub KeyFrameInterval: u16,
            #[tagval(10)]
            pub WatermarkEnabled: core::option::Option<bool>,
            #[tagval(11)]
            pub OSDEnabled: core::option::Option<bool>,
            #[tagval(12)]
            pub ReferenceCount: u8,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxConcurrentEncoders(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxEncodedPixelRate(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct VideoSensorParams(pub $matter::definitions::CameraAVStreamManagement::types::VideoSensorParamsStruct);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NightVisionUsesInfrared(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinViewportResolution(pub $matter::definitions::CameraAVStreamManagement::types::VideoResolutionStruct);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RateDistortionTradeOffPoints(pub $matter::tlv::MatterList<$matter::definitions::CameraAVStreamManagement::types::RateDistortionTradeOffPointsStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxContentBufferSize(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MicrophoneCapabilities(pub $matter::definitions::CameraAVStreamManagement::types::AudioCapabilitiesStruct);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SpeakerCapabilities(pub $matter::definitions::CameraAVStreamManagement::types::AudioCapabilitiesStruct);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TwoWayTalkSupport(pub $matter::definitions::CameraAVStreamManagement::types::TwoWayTalkSupportTypeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SnapshotCapabilities(pub $matter::tlv::MatterList<$matter::definitions::CameraAVStreamManagement::types::SnapshotCapabilitiesStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xB, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxNetworkBandwidth(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xC, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentFrameRate(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xD, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HDRModeEnabled(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xE, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedStreamUsages(pub $matter::tlv::MatterList<$matter::definitions::GlobalElements::types::StreamUsageEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xF, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AllocatedVideoStreams(pub $matter::tlv::MatterList<$matter::definitions::CameraAVStreamManagement::types::VideoStreamStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x10, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AllocatedAudioStreams(pub $matter::tlv::MatterList<$matter::definitions::CameraAVStreamManagement::types::AudioStreamStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x11, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AllocatedSnapshotStreams(pub $matter::tlv::MatterList<$matter::definitions::CameraAVStreamManagement::types::SnapshotStreamStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x12, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StreamUsagePriorities(pub $matter::tlv::MatterList<$matter::definitions::GlobalElements::types::StreamUsageEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x13, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SoftRecordingPrivacyModeEnabled(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x14, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SoftLivestreamPrivacyModeEnabled(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x15, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HardPrivacyModeOn(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x16, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NightVision(pub $matter::definitions::CameraAVStreamManagement::types::TriStateAutoEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x17, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NightVisionIllum(pub $matter::definitions::CameraAVStreamManagement::types::TriStateAutoEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x18, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Viewport(pub $matter::definitions::GlobalElements::types::ViewportStruct);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x19, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SpeakerMuted(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1A, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SpeakerVolumeLevel(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1B, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SpeakerMaxLevel(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1C, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SpeakerMinLevel(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1D, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MicrophoneMuted(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1E, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MicrophoneVolumeLevel(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1F, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MicrophoneMaxLevel(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x20, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MicrophoneMinLevel(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x21, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MicrophoneAGCEnabled(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x22, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ImageRotation(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x23, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ImageFlipHorizontal(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x24, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ImageFlipVertical(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x25, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LocalVideoRecordingEnabled(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x26, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LocalSnapshotRecordingEnabled(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x27, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StatusLightEnabled(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x28, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StatusLightBrightness(pub $matter::definitions::GlobalElements::types::ThreeLevelAutoEnum);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = AudioStreamAllocateResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AudioStreamAllocate {
            #[tagval(0)]
            pub StreamUsage: $matter::definitions::GlobalElements::types::StreamUsageEnum,
            #[tagval(1)]
            pub AudioCodec: $matter::definitions::CameraAVStreamManagement::types::AudioCodecEnum,
            #[tagval(2)]
            pub ChannelCount: u8,
            #[tagval(3)]
            pub SampleRate: u32,
            #[tagval(4)]
            pub BitRate: u32,
            #[tagval(5)]
            pub BitDepth: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AudioStreamAllocateResponse {
            #[tagval(0)]
            pub AudioStreamID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AudioStreamDeallocate {
            #[tagval(0)]
            pub AudioStreamID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3, response = VideoStreamAllocateResponse, response_id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct VideoStreamAllocate {
            #[tagval(0)]
            pub StreamUsage: $matter::definitions::GlobalElements::types::StreamUsageEnum,
            #[tagval(1)]
            pub VideoCodec: $matter::definitions::CameraAVStreamManagement::types::VideoCodecEnum,
            #[tagval(2)]
            pub MinFrameRate: u16,
            #[tagval(3)]
            pub MaxFrameRate: u16,
            #[tagval(4)]
            pub MinResolution: $matter::definitions::CameraAVStreamManagement::types::VideoResolutionStruct,
            #[tagval(5)]
            pub MaxResolution: $matter::definitions::CameraAVStreamManagement::types::VideoResolutionStruct,
            #[tagval(6)]
            pub MinBitRate: u32,
            #[tagval(7)]
            pub MaxBitRate: u32,
            #[tagval(8)]
            pub KeyFrameInterval: u16,
            #[tagval(9)]
            pub WatermarkEnabled: core::option::Option<bool>,
            #[tagval(10)]
            pub OSDEnabled: core::option::Option<bool>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct VideoStreamAllocateResponse {
            #[tagval(0)]
            pub VideoStreamID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct VideoStreamModify {
            #[tagval(0)]
            pub VideoStreamID: u16,
            #[tagval(1)]
            pub WatermarkEnabled: core::option::Option<bool>,
            #[tagval(2)]
            pub OSDEnabled: core::option::Option<bool>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct VideoStreamDeallocate {
            #[tagval(0)]
            pub VideoStreamID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x7, response = SnapshotStreamAllocateResponse, response_id = 0x8)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SnapshotStreamAllocate {
            #[tagval(0)]
            pub ImageCodec: $matter::definitions::CameraAVStreamManagement::types::ImageCodecEnum,
            #[tagval(1)]
            pub MaxFrameRate: u16,
            #[tagval(2)]
            pub MinResolution: $matter::definitions::CameraAVStreamManagement::types::VideoResolutionStruct,
            #[tagval(3)]
            pub MaxResolution: $matter::definitions::CameraAVStreamManagement::types::VideoResolutionStruct,
            #[tagval(4)]
            pub Quality: u8,
            #[tagval(5)]
            pub WatermarkEnabled: core::option::Option<bool>,
            #[tagval(6)]
            pub OSDEnabled: core::option::Option<bool>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SnapshotStreamAllocateResponse {
            #[tagval(0)]
            pub SnapshotStreamID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x9)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SnapshotStreamModify {
            #[tagval(0)]
            pub SnapshotStreamID: u16,
            #[tagval(1)]
            pub WatermarkEnabled: core::option::Option<bool>,
            #[tagval(2)]
            pub OSDEnabled: core::option::Option<bool>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xA)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SnapshotStreamDeallocate {
            #[tagval(0)]
            pub SnapshotStreamID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xB)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetStreamPriorities {
            #[tagval(0)]
            pub StreamPriorities: $matter::tlv::MatterList<$matter::definitions::GlobalElements::types::StreamUsageEnum>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xC, response = CaptureSnapshotResponse, response_id = 0xD)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CaptureSnapshot {
            #[tagval(0)]
            pub SnapshotStreamID: $matter::tlv::Nullable<u16>,
            #[tagval(1)]
            pub RequestedResolution: $matter::definitions::CameraAVStreamManagement::types::VideoResolutionStruct,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CaptureSnapshotResponse {
            #[tagval(0)]
            pub Data: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub ImageCodec: $matter::definitions::CameraAVStreamManagement::types::ImageCodecEnum,
            #[tagval(2)]
            pub Resolution: $matter::definitions::CameraAVStreamManagement::types::VideoResolutionStruct,
        }
    }
    pub mod events {
    }
}
pub mod JointFabricAdministrator {
    pub const ID: u32 = 0x0753;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ICACResponseStatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ICACResponseStatusEnum {
            pub const OK: Self = Self(0x0);
            pub const InvalidPublicKey: Self = Self(0x1);
            pub const InvalidICAC: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusCodeEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl StatusCodeEnum {
            pub const Busy: Self = Self(0x2);
            pub const PAKEParameterError: Self = Self(0x3);
            pub const WindowNotOpen: Self = Self(0x4);
            pub const VIDNotVerified: Self = Self(0x5);
            pub const InvalidAdministratorFabricIndex: Self = Self(0x6);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct TransferAnchorResponseStatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl TransferAnchorResponseStatusEnum {
            pub const OK: Self = Self(0x0);
            pub const TransferAnchorStatusDatastoreBusy: Self = Self(0x1);
            pub const TransferAnchorStatusNoUserConsent: Self = Self(0x2);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AdministratorFabricIndex(pub $matter::tlv::Nullable<u8>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = ICACCSRResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ICACCSRRequest {
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ICACCSRResponse {
            #[tagval(0)]
            pub ICACCSR: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = ICACResponse, response_id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddICAC {
            #[tagval(1)]
            pub ICACValue: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ICACResponse {
            #[tagval(0)]
            pub StatusCode: $matter::definitions::JointFabricAdministrator::types::ICACResponseStatusEnum,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OpenJointCommissioningWindow {
            #[tagval(0)]
            pub CommissioningTimeout: u16,
            #[tagval(1)]
            pub PAKEPasscodeVerifier: $matter::tlv::MatterBytes,
            #[tagval(2)]
            pub Discriminator: u16,
            #[tagval(3)]
            pub Iterations: u32,
            #[tagval(4)]
            pub Salt: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5, response = TransferAnchorResponse, response_id = 0x6)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TransferAnchorRequest {
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TransferAnchorResponse {
            #[tagval(0)]
            pub StatusCode: $matter::definitions::JointFabricAdministrator::types::TransferAnchorResponseStatusEnum,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x7)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TransferAnchorComplete {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x8)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AnnounceJointFabricAdministrator {
            #[tagval(0)]
            pub EndpointID: u16,
        }
    }
    pub mod events {
    }
}
pub mod RVCOperationalState {
    pub const ID: u32 = 0x0061;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ErrorStateEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl ErrorStateEnum {
            pub const NoError: Self = Self(0x0);
            pub const UnableToStartOrResume: Self = Self(0x1);
            pub const UnableToCompleteOperation: Self = Self(0x2);
            pub const CommandInvalidInState: Self = Self(0x3);
            pub const FailedToFindChargingDock: Self = Self(0x40);
            pub const Stuck: Self = Self(0x41);
            pub const DustBinMissing: Self = Self(0x42);
            pub const DustBinFull: Self = Self(0x43);
            pub const WaterTankEmpty: Self = Self(0x44);
            pub const WaterTankMissing: Self = Self(0x45);
            pub const WaterTankLidOpen: Self = Self(0x46);
            pub const MopCleaningPadMissing: Self = Self(0x47);
            pub const LowBattery: Self = Self(0x48);
            pub const CannotReachTargetArea: Self = Self(0x49);
            pub const DirtyWaterTankFull: Self = Self(0x4A);
            pub const DirtyWaterTankMissing: Self = Self(0x4B);
            pub const WheelsJammed: Self = Self(0x4C);
            pub const BrushJammed: Self = Self(0x4D);
            pub const NavigationSensorObscured: Self = Self(0x4E);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OperationalStateEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl OperationalStateEnum {
            pub const Stopped: Self = Self(0x0);
            pub const Running: Self = Self(0x1);
            pub const Paused: Self = Self(0x2);
            pub const Error: Self = Self(0x3);
            pub const SeekingCharger: Self = Self(0x40);
            pub const Charging: Self = Self(0x41);
            pub const Docked: Self = Self(0x42);
            pub const EmptyingDustBin: Self = Self(0x43);
            pub const CleaningMop: Self = Self(0x44);
            pub const FillingWaterTank: Self = Self(0x45);
            pub const UpdatingMaps: Self = Self(0x46);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ErrorStateStruct {
            #[tagval(0)]
            pub ErrorStateID: $matter::definitions::RVCOperationalState::types::ErrorStateEnum,
            #[tagval(1)]
            pub ErrorStateLabel: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub ErrorStateDetails: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalStateStruct {
            #[tagval(0)]
            pub OperationalStateID: $matter::definitions::RVCOperationalState::types::OperationalStateEnum,
            #[tagval(1)]
            pub OperationalStateLabel: core::option::Option<$matter::tlv::MatterString>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PhaseList(pub $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::tlv::MatterString>>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentPhase(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CountdownTime(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalStateList(pub $matter::tlv::MatterList<$matter::definitions::RVCOperationalState::types::OperationalStateStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalState(pub $matter::definitions::RVCOperationalState::types::OperationalStateEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalError(pub $matter::definitions::RVCOperationalState::types::ErrorStateStruct);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = OperationalCommandResponse, response_id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Pause {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1, response = OperationalCommandResponse, response_id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Stop {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = OperationalCommandResponse, response_id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Start {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3, response = OperationalCommandResponse, response_id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Resume {
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalCommandResponse {
            #[tagval(0)]
            pub CommandResponseState: $matter::definitions::RVCOperationalState::types::ErrorStateStruct,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x80, response = OperationalCommandResponse, response_id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GoHome {
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalError {
            #[tagval(0)]
            pub ErrorState: $matter::definitions::RVCOperationalState::types::ErrorStateStruct,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationCompletion {
            #[tagval(0)]
            pub CompletionErrorCode: u8,
            #[tagval(1)]
            pub TotalOperationalTime: core::option::Option<$matter::tlv::Nullable<u32>>,
            #[tagval(2)]
            pub PausedTime: core::option::Option<$matter::tlv::Nullable<u32>>,
        }
    }
}
pub mod LaundryWasherControls {
    pub const ID: u32 = 0x0053;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct NumberOfRinsesEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl NumberOfRinsesEnum {
            pub const None: Self = Self(0x0);
            pub const Normal: Self = Self(0x1);
            pub const Extra: Self = Self(0x2);
            pub const Max: Self = Self(0x3);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SpinSpeeds(pub $matter::tlv::MatterList<$matter::tlv::MatterString>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SpinSpeedCurrent(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfRinses(pub $matter::definitions::LaundryWasherControls::types::NumberOfRinsesEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedRinses(pub $matter::tlv::MatterList<$matter::definitions::LaundryWasherControls::types::NumberOfRinsesEnum>);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod KeypadInput {
    pub const ID: u32 = 0x0509;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct CecKeyCodeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl CecKeyCodeEnum {
            pub const Select: Self = Self(0x0);
            pub const Up: Self = Self(0x1);
            pub const Down: Self = Self(0x2);
            pub const Left: Self = Self(0x3);
            pub const Right: Self = Self(0x4);
            pub const RightUp: Self = Self(0x5);
            pub const RightDown: Self = Self(0x6);
            pub const LeftUp: Self = Self(0x7);
            pub const LeftDown: Self = Self(0x8);
            pub const RootMenu: Self = Self(0x9);
            pub const SetupMenu: Self = Self(0xA);
            pub const ContentsMenu: Self = Self(0xB);
            pub const FavoriteMenu: Self = Self(0xC);
            pub const Exit: Self = Self(0xD);
            pub const MediaTopMenu: Self = Self(0x10);
            pub const MediaContextSensitiveMenu: Self = Self(0x11);
            pub const NumberEntryMode: Self = Self(0x1D);
            pub const Number11: Self = Self(0x1E);
            pub const Number12: Self = Self(0x1F);
            pub const Number0OrNumber10: Self = Self(0x20);
            pub const Numbers1: Self = Self(0x21);
            pub const Numbers2: Self = Self(0x22);
            pub const Numbers3: Self = Self(0x23);
            pub const Numbers4: Self = Self(0x24);
            pub const Numbers5: Self = Self(0x25);
            pub const Numbers6: Self = Self(0x26);
            pub const Numbers7: Self = Self(0x27);
            pub const Numbers8: Self = Self(0x28);
            pub const Numbers9: Self = Self(0x29);
            pub const Dot: Self = Self(0x2A);
            pub const Enter: Self = Self(0x2B);
            pub const Clear: Self = Self(0x2C);
            pub const NextFavorite: Self = Self(0x2F);
            pub const ChannelUp: Self = Self(0x30);
            pub const ChannelDown: Self = Self(0x31);
            pub const PreviousChannel: Self = Self(0x32);
            pub const SoundSelect: Self = Self(0x33);
            pub const InputSelect: Self = Self(0x34);
            pub const DisplayInformation: Self = Self(0x35);
            pub const Help: Self = Self(0x36);
            pub const PageUp: Self = Self(0x37);
            pub const PageDown: Self = Self(0x38);
            pub const Power: Self = Self(0x40);
            pub const VolumeUp: Self = Self(0x41);
            pub const VolumeDown: Self = Self(0x42);
            pub const Mute: Self = Self(0x43);
            pub const Play: Self = Self(0x44);
            pub const Stop: Self = Self(0x45);
            pub const Pause: Self = Self(0x46);
            pub const Record: Self = Self(0x47);
            pub const Rewind: Self = Self(0x48);
            pub const FastForward: Self = Self(0x49);
            pub const Eject: Self = Self(0x4A);
            pub const Forward: Self = Self(0x4B);
            pub const Backward: Self = Self(0x4C);
            pub const StopRecord: Self = Self(0x4D);
            pub const PauseRecord: Self = Self(0x4E);
            pub const Reserved: Self = Self(0x4F);
            pub const Angle: Self = Self(0x50);
            pub const SubPicture: Self = Self(0x51);
            pub const VideoOnDemand: Self = Self(0x52);
            pub const ElectronicProgramGuide: Self = Self(0x53);
            pub const TimerProgramming: Self = Self(0x54);
            pub const InitialConfiguration: Self = Self(0x55);
            pub const SelectBroadcastType: Self = Self(0x56);
            pub const SelectSoundPresentation: Self = Self(0x57);
            pub const PlayFunction: Self = Self(0x60);
            pub const PausePlayFunction: Self = Self(0x61);
            pub const RecordFunction: Self = Self(0x62);
            pub const PauseRecordFunction: Self = Self(0x63);
            pub const StopFunction: Self = Self(0x64);
            pub const MuteFunction: Self = Self(0x65);
            pub const RestoreVolumeFunction: Self = Self(0x66);
            pub const TuneFunction: Self = Self(0x67);
            pub const SelectMediaFunction: Self = Self(0x68);
            pub const SelectAvInputFunction: Self = Self(0x69);
            pub const SelectAudioInputFunction: Self = Self(0x6A);
            pub const PowerToggleFunction: Self = Self(0x6B);
            pub const PowerOffFunction: Self = Self(0x6C);
            pub const PowerOnFunction: Self = Self(0x6D);
            pub const F1Blue: Self = Self(0x71);
            pub const F2Red: Self = Self(0x72);
            pub const F3Green: Self = Self(0x73);
            pub const F4Yellow: Self = Self(0x74);
            pub const F5: Self = Self(0x75);
            pub const Data: Self = Self(0x76);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl StatusEnum {
            pub const Success: Self = Self(0x0);
            pub const UnsupportedKey: Self = Self(0x1);
            pub const InvalidKeyInCurrentState: Self = Self(0x2);
        }
    }
    pub mod attributes {
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = SendKeyResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SendKey {
            #[tagval(0)]
            pub KeyCode: $matter::definitions::KeypadInput::types::CecKeyCodeEnum,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SendKeyResponse {
            #[tagval(0)]
            pub Status: $matter::definitions::KeypadInput::types::StatusEnum,
        }
    }
    pub mod events {
    }
}
pub mod Groups {
    pub const ID: u32 = 0x0004;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct NameSupportBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl NameSupportBitmap {
            pub const GroupNames: Self = Self(0x80);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NameSupport(pub $matter::definitions::Groups::types::NameSupportBitmap);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = AddGroupResponse, response_id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddGroup {
            #[tagval(0)]
            pub GroupID: u16,
            #[tagval(1)]
            pub GroupName: $matter::tlv::MatterString,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddGroupResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub GroupID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1, response = ViewGroupResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ViewGroup {
            #[tagval(0)]
            pub GroupID: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ViewGroupResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub GroupID: u16,
            #[tagval(2)]
            pub GroupName: $matter::tlv::MatterString,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = GetGroupMembershipResponse, response_id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetGroupMembership {
            #[tagval(0)]
            pub GroupList: $matter::tlv::MatterList<u16>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetGroupMembershipResponse {
            #[tagval(0)]
            pub Capacity: $matter::tlv::Nullable<u8>,
            #[tagval(1)]
            pub GroupList: $matter::tlv::MatterList<u16>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3, response = RemoveGroupResponse, response_id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveGroup {
            #[tagval(0)]
            pub GroupID: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveGroupResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub GroupID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveAllGroups {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AddGroupIfIdentifying {
            #[tagval(0)]
            pub GroupID: u16,
            #[tagval(1)]
            pub GroupName: $matter::tlv::MatterString,
        }
    }
    pub mod events {
    }
}
pub mod ClosureDimension {
    pub const ID: u32 = 0x0105;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ClosureUnitEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ClosureUnitEnum {
            pub const Millimeter: Self = Self(0x0);
            pub const Degree: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ModulationTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ModulationTypeEnum {
            pub const SlatsOrientation: Self = Self(0x0);
            pub const SlatsOpenwork: Self = Self(0x1);
            pub const StripesAlignment: Self = Self(0x2);
            pub const Opacity: Self = Self(0x3);
            pub const Ventilation: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OverflowEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl OverflowEnum {
            pub const NoOverflow: Self = Self(0x0);
            pub const Inside: Self = Self(0x1);
            pub const Outside: Self = Self(0x2);
            pub const TopInside: Self = Self(0x3);
            pub const TopOutside: Self = Self(0x4);
            pub const BottomInside: Self = Self(0x5);
            pub const BottomOutside: Self = Self(0x6);
            pub const LeftInside: Self = Self(0x7);
            pub const LeftOutside: Self = Self(0x8);
            pub const RightInside: Self = Self(0x9);
            pub const RightOutside: Self = Self(0xA);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct RotationAxisEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl RotationAxisEnum {
            pub const Left: Self = Self(0x0);
            pub const CenteredVertical: Self = Self(0x1);
            pub const LeftAndRight: Self = Self(0x2);
            pub const Right: Self = Self(0x3);
            pub const Top: Self = Self(0x4);
            pub const CenteredHorizontal: Self = Self(0x5);
            pub const TopAndBottom: Self = Self(0x6);
            pub const Bottom: Self = Self(0x7);
            pub const LeftBarrier: Self = Self(0x8);
            pub const LeftAndRightBarriers: Self = Self(0x9);
            pub const RightBarrier: Self = Self(0xA);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StepDirectionEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl StepDirectionEnum {
            pub const Decrease: Self = Self(0x0);
            pub const Increase: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct TranslationDirectionEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl TranslationDirectionEnum {
            pub const Downward: Self = Self(0x0);
            pub const Upward: Self = Self(0x1);
            pub const VerticalMask: Self = Self(0x2);
            pub const VerticalSymmetry: Self = Self(0x3);
            pub const Leftward: Self = Self(0x4);
            pub const Rightward: Self = Self(0x5);
            pub const HorizontalMask: Self = Self(0x6);
            pub const HorizontalSymmetry: Self = Self(0x7);
            pub const Forward: Self = Self(0x8);
            pub const Backward: Self = Self(0x9);
            pub const DepthMask: Self = Self(0xA);
            pub const DepthSymmetry: Self = Self(0xB);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LatchControlModesBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl LatchControlModesBitmap {
            pub const RemoteLatching: Self = Self(0x1);
            pub const RemoteUnlatching: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DimensionStateStruct {
            #[tagval(0)]
            pub Position: core::option::Option<$matter::tlv::Nullable<u16>>,
            #[tagval(1)]
            pub Latch: core::option::Option<$matter::tlv::Nullable<bool>>,
            #[tagval(2)]
            pub Speed: core::option::Option<$matter::definitions::GlobalElements::types::ThreeLevelAutoEnum>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RangePercent100thsStruct {
            #[tagval(0)]
            pub Min: u16,
            #[tagval(1)]
            pub Max: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UnitRangeStruct {
            #[tagval(0)]
            pub Min: i16,
            #[tagval(1)]
            pub Max: i16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentState(pub $matter::tlv::Nullable<$matter::definitions::ClosureDimension::types::DimensionStateStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TargetState(pub $matter::tlv::Nullable<$matter::definitions::ClosureDimension::types::DimensionStateStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Resolution(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StepValue(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Unit(pub $matter::definitions::ClosureDimension::types::ClosureUnitEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UnitRange(pub $matter::tlv::Nullable<$matter::definitions::ClosureDimension::types::UnitRangeStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LimitRange(pub $matter::definitions::ClosureDimension::types::RangePercent100thsStruct);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TranslationDirection(pub $matter::definitions::ClosureDimension::types::TranslationDirectionEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RotationAxis(pub $matter::definitions::ClosureDimension::types::RotationAxisEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Overflow(pub $matter::definitions::ClosureDimension::types::OverflowEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModulationType(pub $matter::definitions::ClosureDimension::types::ModulationTypeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xB, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LatchControlModes(pub $matter::definitions::ClosureDimension::types::LatchControlModesBitmap);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetTarget {
            #[tagval(0)]
            pub Position: core::option::Option<u16>,
            #[tagval(1)]
            pub Latch: core::option::Option<bool>,
            #[tagval(2)]
            pub Speed: core::option::Option<$matter::definitions::GlobalElements::types::ThreeLevelAutoEnum>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Step {
            #[tagval(0)]
            pub Direction: $matter::definitions::ClosureDimension::types::StepDirectionEnum,
            #[tagval(1)]
            pub NumberOfSteps: u16,
            #[tagval(2)]
            pub Speed: core::option::Option<$matter::definitions::GlobalElements::types::ThreeLevelAutoEnum>,
        }
    }
    pub mod events {
    }
}
pub mod RefrigeratorAlarm {
    pub const ID: u32 = 0x0057;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct AlarmBitmap(pub u32);
        #[allow(non_upper_case_globals)]
        impl AlarmBitmap {
            pub const DoorOpen: Self = Self(0x1);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Mask(pub $matter::definitions::RefrigeratorAlarm::types::AlarmBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Latch(pub $matter::definitions::RefrigeratorAlarm::types::AlarmBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct State(pub $matter::definitions::RefrigeratorAlarm::types::AlarmBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Supported(pub $matter::definitions::RefrigeratorAlarm::types::AlarmBitmap);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Reset {
            #[tagval(0)]
            pub Alarms: $matter::definitions::RefrigeratorAlarm::types::AlarmBitmap,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModifyEnabledAlarms {
            #[tagval(0)]
            pub Mask: $matter::definitions::RefrigeratorAlarm::types::AlarmBitmap,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Notify {
            #[tagval(0)]
            pub Active: $matter::definitions::RefrigeratorAlarm::types::AlarmBitmap,
            #[tagval(1)]
            pub Inactive: $matter::definitions::RefrigeratorAlarm::types::AlarmBitmap,
            #[tagval(2)]
            pub State: $matter::definitions::RefrigeratorAlarm::types::AlarmBitmap,
            #[tagval(3)]
            pub Mask: $matter::definitions::RefrigeratorAlarm::types::AlarmBitmap,
        }
    }
}
pub mod ThermostatUserInterfaceConfiguration {
    pub const ID: u32 = 0x0204;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct KeypadLockoutEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl KeypadLockoutEnum {
            pub const NoLockout: Self = Self(0x0);
            pub const Lockout1: Self = Self(0x1);
            pub const Lockout2: Self = Self(0x2);
            pub const Lockout3: Self = Self(0x3);
            pub const Lockout4: Self = Self(0x4);
            pub const Lockout5: Self = Self(0x5);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ScheduleProgrammingVisibilityEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ScheduleProgrammingVisibilityEnum {
            pub const ScheduleProgrammingPermitted: Self = Self(0x0);
            pub const ScheduleProgrammingDenied: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct TemperatureDisplayModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl TemperatureDisplayModeEnum {
            pub const Celsius: Self = Self(0x0);
            pub const Fahrenheit: Self = Self(0x1);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TemperatureDisplayMode(pub $matter::definitions::ThermostatUserInterfaceConfiguration::types::TemperatureDisplayModeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct KeypadLockout(pub $matter::definitions::ThermostatUserInterfaceConfiguration::types::KeypadLockoutEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ScheduleProgrammingVisibility(pub $matter::definitions::ThermostatUserInterfaceConfiguration::types::ScheduleProgrammingVisibilityEnum);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod MediaInput {
    pub const ID: u32 = 0x0507;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct InputTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl InputTypeEnum {
            pub const Internal: Self = Self(0x0);
            pub const Aux: Self = Self(0x1);
            pub const Coax: Self = Self(0x2);
            pub const Composite: Self = Self(0x3);
            pub const HDMI: Self = Self(0x4);
            pub const Input: Self = Self(0x5);
            pub const Line: Self = Self(0x6);
            pub const Optical: Self = Self(0x7);
            pub const Video: Self = Self(0x8);
            pub const SCART: Self = Self(0x9);
            pub const USB: Self = Self(0xA);
            pub const Other: Self = Self(0xB);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct InputInfoStruct {
            #[tagval(0)]
            pub Index: u8,
            #[tagval(1)]
            pub InputType: $matter::definitions::MediaInput::types::InputTypeEnum,
            #[tagval(2)]
            pub Name: $matter::tlv::MatterString,
            #[tagval(3)]
            pub Description: $matter::tlv::MatterString,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct InputList(pub $matter::tlv::MatterList<$matter::definitions::MediaInput::types::InputInfoStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentInput(pub u8);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SelectInput {
            #[tagval(0)]
            pub Index: u8,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ShowInputStatus {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HideInputStatus {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RenameInput {
            #[tagval(0)]
            pub Index: u8,
            #[tagval(1)]
            pub Name: $matter::tlv::MatterString,
        }
    }
    pub mod events {
    }
}
pub mod OccupancySensing {
    pub const ID: u32 = 0x0406;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OccupancySensorTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl OccupancySensorTypeEnum {
            pub const PIR: Self = Self(0x0);
            pub const Ultrasonic: Self = Self(0x1);
            pub const PIRAndUltrasonic: Self = Self(0x2);
            pub const PhysicalContact: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OccupancyBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl OccupancyBitmap {
            pub const Occupied: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OccupancySensorTypeBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl OccupancySensorTypeBitmap {
            pub const PIR: Self = Self(0x1);
            pub const Ultrasonic: Self = Self(0x2);
            pub const PhysicalContact: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HoldTimeLimitsStruct {
            #[tagval(0)]
            pub HoldTimeMin: u16,
            #[tagval(1)]
            pub HoldTimeMax: u16,
            #[tagval(2)]
            pub HoldTimeDefault: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Occupancy(pub $matter::definitions::OccupancySensing::types::OccupancyBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OccupancySensorType(pub $matter::definitions::OccupancySensing::types::OccupancySensorTypeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OccupancySensorTypeBitmap(pub $matter::definitions::OccupancySensing::types::OccupancySensorTypeBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HoldTime(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct HoldTimeLimits(pub $matter::definitions::OccupancySensing::types::HoldTimeLimitsStruct);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x10, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PIROccupiedToUnoccupiedDelay(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x11, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PIRUnoccupiedToOccupiedDelay(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x12, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PIRUnoccupiedToOccupiedThreshold(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x20, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UltrasonicOccupiedToUnoccupiedDelay(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x21, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UltrasonicUnoccupiedToOccupiedDelay(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x22, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UltrasonicUnoccupiedToOccupiedThreshold(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x30, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PhysicalContactOccupiedToUnoccupiedDelay(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x31, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PhysicalContactUnoccupiedToOccupiedDelay(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x32, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PhysicalContactUnoccupiedToOccupiedThreshold(pub u8);
    }
    pub mod commands {
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OccupancyChanged {
            #[tagval(0)]
            pub Occupancy: $matter::definitions::OccupancySensing::types::OccupancyBitmap,
        }
    }
}
pub mod TLSCertificateManagement {
    pub const ID: u32 = 0x0801;
    pub mod types {
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TLSCertStruct {
            #[tagval(0)]
            pub CAID: u16,
            #[tagval(1)]
            pub Certificate: core::option::Option<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TLSClientCertificateDetailStruct {
            #[tagval(0)]
            pub CCDID: u16,
            #[tagval(1)]
            pub ClientCertificate: core::option::Option<$matter::tlv::Nullable<$matter::tlv::MatterBytes>>,
            #[tagval(2)]
            pub IntermediateCertificates: core::option::Option<$matter::tlv::MatterList<$matter::tlv::MatterBytes>>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxRootCertificates(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProvisionedRootCertificates(pub $matter::tlv::MatterList<$matter::definitions::TLSCertificateManagement::types::TLSCertStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxClientCertificates(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProvisionedClientCertificates(pub $matter::tlv::MatterList<$matter::definitions::TLSCertificateManagement::types::TLSClientCertificateDetailStruct>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = ProvisionRootCertificateResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProvisionRootCertificate {
            #[tagval(0)]
            pub Certificate: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub CAID: $matter::tlv::Nullable<u16>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProvisionRootCertificateResponse {
            #[tagval(0)]
            pub CAID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = FindRootCertificateResponse, response_id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FindRootCertificate {
            #[tagval(0)]
            pub CAID: $matter::tlv::Nullable<u16>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FindRootCertificateResponse {
            #[tagval(0)]
            pub CertificateDetails: $matter::tlv::MatterList<$matter::definitions::TLSCertificateManagement::types::TLSCertStruct>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4, response = LookupRootCertificateResponse, response_id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LookupRootCertificate {
            #[tagval(0)]
            pub Fingerprint: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LookupRootCertificateResponse {
            #[tagval(0)]
            pub CAID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveRootCertificate {
            #[tagval(0)]
            pub CAID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x7, response = ClientCSRResponse, response_id = 0x8)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ClientCSR {
            #[tagval(0)]
            pub Nonce: $matter::tlv::MatterBytes,
            #[tagval(1)]
            pub CCDID: $matter::tlv::Nullable<u16>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ClientCSRResponse {
            #[tagval(0)]
            pub CCDID: u16,
            #[tagval(1)]
            pub CSR: $matter::tlv::MatterBytes,
            #[tagval(2)]
            pub NonceSignature: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x9)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProvisionClientCertificate {
            #[tagval(0)]
            pub CCDID: u16,
            #[tagval(1)]
            pub ClientCertificate: $matter::tlv::MatterBytes,
            #[tagval(2)]
            pub IntermediateCertificates: $matter::tlv::MatterList<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xA, response = FindClientCertificateResponse, response_id = 0xB)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FindClientCertificate {
            #[tagval(0)]
            pub CCDID: $matter::tlv::Nullable<u16>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct FindClientCertificateResponse {
            #[tagval(0)]
            pub CertificateDetails: $matter::tlv::MatterList<$matter::definitions::TLSCertificateManagement::types::TLSClientCertificateDetailStruct>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xC, response = LookupClientCertificateResponse, response_id = 0xD)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LookupClientCertificate {
            #[tagval(0)]
            pub Fingerprint: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LookupClientCertificateResponse {
            #[tagval(0)]
            pub CCDID: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0xE)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoveClientCertificate {
            #[tagval(0)]
            pub CCDID: u16,
        }
    }
    pub mod events {
    }
}
pub mod CommodityTariff {
    pub const ID: u32 = 0x0700;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct AuxiliaryLoadSettingEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl AuxiliaryLoadSettingEnum {
            pub const Off: Self = Self(0x0);
            pub const On: Self = Self(0x1);
            pub const None: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct BlockModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl BlockModeEnum {
            pub const NoBlock: Self = Self(0x0);
            pub const Combined: Self = Self(0x1);
            pub const Individual: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DayEntryRandomizationTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl DayEntryRandomizationTypeEnum {
            pub const None: Self = Self(0x0);
            pub const Fixed: Self = Self(0x1);
            pub const Random: Self = Self(0x2);
            pub const RandomPositive: Self = Self(0x3);
            pub const RandomNegative: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DayTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl DayTypeEnum {
            pub const Standard: Self = Self(0x0);
            pub const Holiday: Self = Self(0x1);
            pub const Dynamic: Self = Self(0x2);
            pub const Event: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct PeakPeriodSeverityEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl PeakPeriodSeverityEnum {
            pub const Unused: Self = Self(0x0);
            pub const Low: Self = Self(0x1);
            pub const Medium: Self = Self(0x2);
            pub const High: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct DayPatternDayOfWeekBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl DayPatternDayOfWeekBitmap {
            pub const Sunday: Self = Self(0x1);
            pub const Monday: Self = Self(0x2);
            pub const Tuesday: Self = Self(0x4);
            pub const Wednesday: Self = Self(0x8);
            pub const Thursday: Self = Self(0x10);
            pub const Friday: Self = Self(0x20);
            pub const Saturday: Self = Self(0x40);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AuxiliaryLoadSwitchSettingsStruct {
            #[tagval(0)]
            pub Number: u8,
            #[tagval(1)]
            pub RequiredState: $matter::definitions::CommodityTariff::types::AuxiliaryLoadSettingEnum,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AuxiliaryLoadSwitchesSettingsStruct {
            #[tagval(0)]
            pub SwitchStates: $matter::tlv::MatterList<$matter::definitions::CommodityTariff::types::AuxiliaryLoadSwitchSettingsStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CalendarPeriodStruct {
            #[tagval(0)]
            pub StartDate: $matter::tlv::Nullable<u32>,
            #[tagval(1)]
            pub DayPatternIDs: $matter::tlv::MatterList<u32>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DayEntryStruct {
            #[tagval(0)]
            pub DayEntryID: u32,
            #[tagval(1)]
            pub StartTime: u16,
            #[tagval(2)]
            pub Duration: core::option::Option<u16>,
            #[tagval(3)]
            pub RandomizationOffset: core::option::Option<i16>,
            #[tagval(4)]
            pub RandomizationType: core::option::Option<$matter::definitions::CommodityTariff::types::DayEntryRandomizationTypeEnum>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DayPatternStruct {
            #[tagval(0)]
            pub DayPatternID: u32,
            #[tagval(1)]
            pub DaysOfWeek: $matter::definitions::CommodityTariff::types::DayPatternDayOfWeekBitmap,
            #[tagval(2)]
            pub DayEntryIDs: $matter::tlv::MatterList<u32>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DayStruct {
            #[tagval(0)]
            pub Date: u32,
            #[tagval(1)]
            pub DayType: $matter::definitions::CommodityTariff::types::DayTypeEnum,
            #[tagval(2)]
            pub DayEntryIDs: $matter::tlv::MatterList<u32>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PeakPeriodStruct {
            #[tagval(0)]
            pub Severity: $matter::definitions::CommodityTariff::types::PeakPeriodSeverityEnum,
            #[tagval(1)]
            pub PeakPeriod: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TariffComponentStruct {
            #[tagval(0)]
            pub TariffComponentID: u32,
            #[tagval(1)]
            pub Price: core::option::Option<$matter::tlv::Nullable<$matter::definitions::CommodityTariff::types::TariffPriceStruct>>,
            #[tagval(2)]
            pub FriendlyCredit: core::option::Option<bool>,
            #[tagval(3)]
            pub AuxiliaryLoad: core::option::Option<$matter::definitions::CommodityTariff::types::AuxiliaryLoadSwitchSettingsStruct>,
            #[tagval(4)]
            pub PeakPeriod: core::option::Option<$matter::definitions::CommodityTariff::types::PeakPeriodStruct>,
            #[tagval(5)]
            pub PowerThreshold: core::option::Option<$matter::definitions::GlobalElements::types::PowerThresholdStruct>,
            #[tagval(6)]
            pub Threshold: $matter::tlv::Nullable<i64>,
            #[tagval(7)]
            pub Label: core::option::Option<$matter::tlv::Nullable<$matter::tlv::MatterString>>,
            #[tagval(8)]
            pub Predicted: core::option::Option<bool>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TariffInformationStruct {
            #[tagval(0)]
            pub TariffLabel: $matter::tlv::Nullable<$matter::tlv::MatterString>,
            #[tagval(1)]
            pub ProviderName: $matter::tlv::Nullable<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub Currency: core::option::Option<$matter::tlv::Nullable<$matter::definitions::GlobalElements::types::CurrencyStruct>>,
            #[tagval(3)]
            pub BlockMode: $matter::tlv::Nullable<$matter::definitions::CommodityTariff::types::BlockModeEnum>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TariffPeriodStruct {
            #[tagval(0)]
            pub Label: $matter::tlv::Nullable<$matter::tlv::MatterString>,
            #[tagval(1)]
            pub DayEntryIDs: $matter::tlv::MatterList<u32>,
            #[tagval(2)]
            pub TariffComponentIDs: $matter::tlv::MatterList<u32>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TariffPriceStruct {
            #[tagval(0)]
            pub PriceType: $matter::definitions::GlobalElements::types::TariffPriceTypeEnum,
            #[tagval(1)]
            pub Price: core::option::Option<i64>,
            #[tagval(2)]
            pub PriceLevel: core::option::Option<i16>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TariffInfo(pub $matter::tlv::Nullable<$matter::definitions::CommodityTariff::types::TariffInformationStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TariffUnit(pub $matter::tlv::Nullable<$matter::definitions::GlobalElements::types::TariffUnitEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartDate(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DayEntries(pub $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::CommodityTariff::types::DayEntryStruct>>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DayPatterns(pub $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::CommodityTariff::types::DayPatternStruct>>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CalendarPeriods(pub $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::CommodityTariff::types::CalendarPeriodStruct>>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct IndividualDays(pub $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::CommodityTariff::types::DayStruct>>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentDay(pub $matter::tlv::Nullable<$matter::definitions::CommodityTariff::types::DayStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NextDay(pub $matter::tlv::Nullable<$matter::definitions::CommodityTariff::types::DayStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentDayEntry(pub $matter::tlv::Nullable<$matter::definitions::CommodityTariff::types::DayEntryStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentDayEntryDate(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xB, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NextDayEntry(pub $matter::tlv::Nullable<$matter::definitions::CommodityTariff::types::DayEntryStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xC, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NextDayEntryDate(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xD, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TariffComponents(pub $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::CommodityTariff::types::TariffComponentStruct>>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xE, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TariffPeriods(pub $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::CommodityTariff::types::TariffPeriodStruct>>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xF, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentTariffComponents(pub $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::CommodityTariff::types::TariffComponentStruct>>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x10, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NextTariffComponents(pub $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::CommodityTariff::types::TariffComponentStruct>>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x11, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DefaultRandomizationOffset(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x12, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DefaultRandomizationType(pub $matter::tlv::Nullable<$matter::definitions::CommodityTariff::types::DayEntryRandomizationTypeEnum>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = GetTariffComponentResponse, response_id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetTariffComponent {
            #[tagval(0)]
            pub TariffComponentID: u32,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetTariffComponentResponse {
            #[tagval(0)]
            pub Label: $matter::tlv::Nullable<$matter::tlv::MatterString>,
            #[tagval(1)]
            pub DayEntryIDs: $matter::tlv::MatterList<u32>,
            #[tagval(2)]
            pub TariffComponent: $matter::definitions::CommodityTariff::types::TariffComponentStruct,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1, response = GetDayEntryResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetDayEntry {
            #[tagval(0)]
            pub DayEntryID: u32,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetDayEntryResponse {
            #[tagval(0)]
            pub DayEntry: $matter::definitions::CommodityTariff::types::DayEntryStruct,
        }
    }
    pub mod events {
    }
}
pub mod PressureMeasurement {
    pub const ID: u32 = 0x0403;
    pub mod types {
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MeasuredValue(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinMeasuredValue(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxMeasuredValue(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Tolerance(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x10, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ScaledValue(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x11, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinScaledValue(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x12, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxScaledValue(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x13, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ScaledTolerance(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x14, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Scale(pub i8);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod Thermostat {
    pub const ID: u32 = 0x0201;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ACCapacityFormatEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ACCapacityFormatEnum {
            pub const BTUh: Self = Self(0x0);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ACCompressorTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ACCompressorTypeEnum {
            pub const Unknown: Self = Self(0x0);
            pub const T1: Self = Self(0x1);
            pub const T2: Self = Self(0x2);
            pub const T3: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ACLouverPositionEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ACLouverPositionEnum {
            pub const Closed: Self = Self(0x1);
            pub const Open: Self = Self(0x2);
            pub const Quarter: Self = Self(0x3);
            pub const Half: Self = Self(0x4);
            pub const ThreeQuarters: Self = Self(0x5);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ACRefrigerantTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ACRefrigerantTypeEnum {
            pub const Unknown: Self = Self(0x0);
            pub const R22: Self = Self(0x1);
            pub const R410a: Self = Self(0x2);
            pub const R407c: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ACTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ACTypeEnum {
            pub const Unknown: Self = Self(0x0);
            pub const CoolingFixed: Self = Self(0x1);
            pub const HeatPumpFixed: Self = Self(0x2);
            pub const CoolingInverter: Self = Self(0x3);
            pub const HeatPumpInverter: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ControlSequenceOfOperationEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ControlSequenceOfOperationEnum {
            pub const CoolingOnly: Self = Self(0x0);
            pub const CoolingWithReheat: Self = Self(0x1);
            pub const HeatingOnly: Self = Self(0x2);
            pub const HeatingWithReheat: Self = Self(0x3);
            pub const CoolingAndHeating: Self = Self(0x4);
            pub const CoolingAndHeatingWithReheat: Self = Self(0x5);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct PresetScenarioEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl PresetScenarioEnum {
            pub const Occupied: Self = Self(0x1);
            pub const Unoccupied: Self = Self(0x2);
            pub const Sleep: Self = Self(0x3);
            pub const Wake: Self = Self(0x4);
            pub const Vacation: Self = Self(0x5);
            pub const GoingToSleep: Self = Self(0x6);
            pub const UserDefined: Self = Self(0xFE);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct SetpointChangeSourceEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl SetpointChangeSourceEnum {
            pub const Manual: Self = Self(0x0);
            pub const Schedule: Self = Self(0x1);
            pub const External: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct SetpointRaiseLowerModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl SetpointRaiseLowerModeEnum {
            pub const Heat: Self = Self(0x0);
            pub const Cool: Self = Self(0x1);
            pub const Both: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StartOfWeekEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl StartOfWeekEnum {
            pub const Sunday: Self = Self(0x0);
            pub const Monday: Self = Self(0x1);
            pub const Tuesday: Self = Self(0x2);
            pub const Wednesday: Self = Self(0x3);
            pub const Thursday: Self = Self(0x4);
            pub const Friday: Self = Self(0x5);
            pub const Saturday: Self = Self(0x6);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct SystemModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl SystemModeEnum {
            pub const Off: Self = Self(0x0);
            pub const Auto: Self = Self(0x1);
            pub const Cool: Self = Self(0x3);
            pub const Heat: Self = Self(0x4);
            pub const EmergencyHeat: Self = Self(0x5);
            pub const Precooling: Self = Self(0x6);
            pub const FanOnly: Self = Self(0x7);
            pub const Dry: Self = Self(0x8);
            pub const Sleep: Self = Self(0x9);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct TemperatureSetpointHoldEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl TemperatureSetpointHoldEnum {
            pub const SetpointHoldOff: Self = Self(0x0);
            pub const SetpointHoldOn: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ThermostatRunningModeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ThermostatRunningModeEnum {
            pub const Off: Self = Self(0x0);
            pub const Cool: Self = Self(0x3);
            pub const Heat: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ACErrorCodeBitmap(pub u32);
        #[allow(non_upper_case_globals)]
        impl ACErrorCodeBitmap {
            pub const CompressorFail: Self = Self(0x1);
            pub const RoomSensorFail: Self = Self(0x2);
            pub const OutdoorSensorFail: Self = Self(0x4);
            pub const CoilSensorFail: Self = Self(0x8);
            pub const FanFail: Self = Self(0x10);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OccupancyBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl OccupancyBitmap {
            pub const Occupied: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct PresetTypeFeaturesBitmap(pub u16);
        #[allow(non_upper_case_globals)]
        impl PresetTypeFeaturesBitmap {
            pub const Automatic: Self = Self(0x1);
            pub const SupportsNames: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ProgrammingOperationModeBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl ProgrammingOperationModeBitmap {
            pub const ScheduleActive: Self = Self(0x1);
            pub const AutoRecovery: Self = Self(0x2);
            pub const Economy: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct RelayStateBitmap(pub u16);
        #[allow(non_upper_case_globals)]
        impl RelayStateBitmap {
            pub const Heat: Self = Self(0x1);
            pub const Cool: Self = Self(0x2);
            pub const Fan: Self = Self(0x4);
            pub const HeatStage2: Self = Self(0x8);
            pub const CoolStage2: Self = Self(0x10);
            pub const FanStage2: Self = Self(0x20);
            pub const FanStage3: Self = Self(0x40);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct RemoteSensingBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl RemoteSensingBitmap {
            pub const LocalTemperature: Self = Self(0x1);
            pub const OutdoorTemperature: Self = Self(0x2);
            pub const Occupancy: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ScheduleDayOfWeekBitmap(pub u8);
        #[allow(non_upper_case_globals)]
        impl ScheduleDayOfWeekBitmap {
            pub const Sunday: Self = Self(0x1);
            pub const Monday: Self = Self(0x2);
            pub const Tuesday: Self = Self(0x4);
            pub const Wednesday: Self = Self(0x8);
            pub const Thursday: Self = Self(0x10);
            pub const Friday: Self = Self(0x20);
            pub const Saturday: Self = Self(0x40);
            pub const Away: Self = Self(0x80);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ScheduleModeBitmap(pub u32);
        #[allow(non_upper_case_globals)]
        impl ScheduleModeBitmap {
            pub const HeatSetpointPresent: Self = Self(0x1);
            pub const CoolSetpointPresent: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ScheduleTypeFeaturesBitmap(pub u16);
        #[allow(non_upper_case_globals)]
        impl ScheduleTypeFeaturesBitmap {
            pub const SupportsPresets: Self = Self(0x1);
            pub const SupportsSetpoints: Self = Self(0x2);
            pub const SupportsNames: Self = Self(0x4);
            pub const SupportsOff: Self = Self(0x8);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PresetStruct {
            #[tagval(0)]
            pub PresetHandle: $matter::tlv::Nullable<$matter::tlv::MatterBytes>,
            #[tagval(1)]
            pub PresetScenario: $matter::definitions::Thermostat::types::PresetScenarioEnum,
            #[tagval(2)]
            pub Name: core::option::Option<$matter::tlv::Nullable<$matter::tlv::MatterString>>,
            #[tagval(3)]
            pub CoolingSetpoint: core::option::Option<i16>,
            #[tagval(4)]
            pub HeatingSetpoint: core::option::Option<i16>,
            #[tagval(5)]
            pub BuiltIn: $matter::tlv::Nullable<bool>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PresetTypeStruct {
            #[tagval(0)]
            pub PresetScenario: $matter::definitions::Thermostat::types::PresetScenarioEnum,
            #[tagval(1)]
            pub NumberOfPresets: u8,
            #[tagval(2)]
            pub PresetTypeFeatures: $matter::definitions::Thermostat::types::PresetTypeFeaturesBitmap,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ScheduleStruct {
            #[tagval(0)]
            pub ScheduleHandle: $matter::tlv::Nullable<$matter::tlv::MatterBytes>,
            #[tagval(1)]
            pub SystemMode: $matter::definitions::Thermostat::types::SystemModeEnum,
            #[tagval(2)]
            pub Name: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(3)]
            pub PresetHandle: core::option::Option<$matter::tlv::MatterBytes>,
            #[tagval(4)]
            pub Transitions: $matter::tlv::MatterList<$matter::definitions::Thermostat::types::ScheduleTransitionStruct>,
            #[tagval(5)]
            pub BuiltIn: $matter::tlv::Nullable<bool>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ScheduleTransitionStruct {
            #[tagval(0)]
            pub DayOfWeek: $matter::definitions::Thermostat::types::ScheduleDayOfWeekBitmap,
            #[tagval(1)]
            pub TransitionTime: u16,
            #[tagval(2)]
            pub PresetHandle: core::option::Option<$matter::tlv::MatterBytes>,
            #[tagval(3)]
            pub SystemMode: core::option::Option<$matter::definitions::Thermostat::types::SystemModeEnum>,
            #[tagval(4)]
            pub CoolingSetpoint: core::option::Option<i16>,
            #[tagval(5)]
            pub HeatingSetpoint: core::option::Option<i16>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ScheduleTypeStruct {
            #[tagval(0)]
            pub SystemMode: $matter::definitions::Thermostat::types::SystemModeEnum,
            #[tagval(1)]
            pub NumberOfSchedules: u8,
            #[tagval(2)]
            pub ScheduleTypeFeatures: $matter::definitions::Thermostat::types::ScheduleTypeFeaturesBitmap,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct WeeklyScheduleTransitionStruct {
            #[tagval(0)]
            pub TransitionTime: u16,
            #[tagval(1)]
            pub HeatSetpoint: $matter::tlv::Nullable<i16>,
            #[tagval(2)]
            pub CoolSetpoint: $matter::tlv::Nullable<i16>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LocalTemperature(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OutdoorTemperature(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Occupancy(pub $matter::definitions::Thermostat::types::OccupancyBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AbsMinHeatSetpointLimit(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AbsMaxHeatSetpointLimit(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AbsMinCoolSetpointLimit(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AbsMaxCoolSetpointLimit(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x10, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LocalTemperatureCalibration(pub i8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x11, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OccupiedCoolingSetpoint(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x12, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OccupiedHeatingSetpoint(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x13, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UnoccupiedCoolingSetpoint(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x14, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct UnoccupiedHeatingSetpoint(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x15, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinHeatSetpointLimit(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x16, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxHeatSetpointLimit(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x17, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinCoolSetpointLimit(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x18, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxCoolSetpointLimit(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x19, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinSetpointDeadBand(pub i8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1A, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemoteSensing(pub $matter::definitions::Thermostat::types::RemoteSensingBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1B, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ControlSequenceOfOperation(pub $matter::definitions::Thermostat::types::ControlSequenceOfOperationEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1C, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SystemMode(pub $matter::definitions::Thermostat::types::SystemModeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1E, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ThermostatRunningMode(pub $matter::definitions::Thermostat::types::ThermostatRunningModeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x23, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TemperatureSetpointHold(pub $matter::definitions::Thermostat::types::TemperatureSetpointHoldEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x24, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TemperatureSetpointHoldDuration(pub $matter::tlv::Nullable<u16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x25, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ThermostatProgrammingOperationMode(pub $matter::definitions::Thermostat::types::ProgrammingOperationModeBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x29, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ThermostatRunningState(pub $matter::definitions::Thermostat::types::RelayStateBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x30, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetpointChangeSource(pub $matter::definitions::Thermostat::types::SetpointChangeSourceEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x31, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetpointChangeAmount(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x32, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetpointChangeSourceTimestamp(pub u32);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3A, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EmergencyHeatDelta(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x40, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ACType(pub $matter::definitions::Thermostat::types::ACTypeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x41, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ACCapacity(pub u16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x42, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ACRefrigerantType(pub $matter::definitions::Thermostat::types::ACRefrigerantTypeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x43, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ACCompressorType(pub $matter::definitions::Thermostat::types::ACCompressorTypeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x44, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ACErrorCode(pub $matter::definitions::Thermostat::types::ACErrorCodeBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x45, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ACLouverPosition(pub $matter::definitions::Thermostat::types::ACLouverPositionEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x46, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ACCoilTemperature(pub $matter::tlv::Nullable<i16>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x47, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ACCapacityFormat(pub $matter::definitions::Thermostat::types::ACCapacityFormatEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x48, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PresetTypes(pub $matter::tlv::MatterList<$matter::definitions::Thermostat::types::PresetTypeStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x49, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ScheduleTypes(pub $matter::tlv::MatterList<$matter::definitions::Thermostat::types::ScheduleTypeStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4A, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfPresets(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4B, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfSchedules(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4C, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfScheduleTransitions(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4D, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct NumberOfScheduleTransitionPerDay(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4E, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActivePresetHandle(pub $matter::tlv::Nullable<$matter::tlv::MatterBytes>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4F, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ActiveScheduleHandle(pub $matter::tlv::Nullable<$matter::tlv::MatterBytes>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x50, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Presets(pub $matter::tlv::MatterList<$matter::definitions::Thermostat::types::PresetStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x51, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Schedules(pub $matter::tlv::MatterList<$matter::definitions::Thermostat::types::ScheduleStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x52, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetpointHoldExpiryTimestamp(pub $matter::tlv::Nullable<u32>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetpointRaiseLower {
            #[tagval(0)]
            pub Mode: $matter::definitions::Thermostat::types::SetpointRaiseLowerModeEnum,
            #[tagval(1)]
            pub Amount: i8,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetActiveScheduleRequest {
            #[tagval(0)]
            pub ScheduleHandle: $matter::tlv::MatterBytes,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetActivePresetRequest {
            #[tagval(0)]
            pub PresetHandle: $matter::tlv::Nullable<$matter::tlv::MatterBytes>,
        }
    }
    pub mod events {
    }
}
pub mod Channel {
    pub const ID: u32 = 0x0504;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ChannelTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ChannelTypeEnum {
            pub const Satellite: Self = Self(0x0);
            pub const Cable: Self = Self(0x1);
            pub const Terrestrial: Self = Self(0x2);
            pub const OTT: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct LineupInfoTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl LineupInfoTypeEnum {
            pub const MSO: Self = Self(0x0);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl StatusEnum {
            pub const Success: Self = Self(0x0);
            pub const MultipleMatches: Self = Self(0x1);
            pub const NoMatches: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct RecordingFlagBitmap(pub u32);
        #[allow(non_upper_case_globals)]
        impl RecordingFlagBitmap {
            pub const Scheduled: Self = Self(0x1);
            pub const RecordSeries: Self = Self(0x2);
            pub const Recorded: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChannelInfoStruct {
            #[tagval(0)]
            pub MajorNumber: u16,
            #[tagval(1)]
            pub MinorNumber: u16,
            #[tagval(2)]
            pub Name: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(3)]
            pub CallSign: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(4)]
            pub AffiliateCallSign: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(5)]
            pub Identifier: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(6)]
            pub Type: core::option::Option<$matter::definitions::Channel::types::ChannelTypeEnum>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChannelPagingStruct {
            #[tagval(0)]
            pub PreviousToken: core::option::Option<$matter::tlv::Nullable<$matter::definitions::Channel::types::PageTokenStruct>>,
            #[tagval(1)]
            pub NextToken: core::option::Option<$matter::tlv::Nullable<$matter::definitions::Channel::types::PageTokenStruct>>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LineupInfoStruct {
            #[tagval(0)]
            pub OperatorName: $matter::tlv::MatterString,
            #[tagval(1)]
            pub LineupName: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub PostalCode: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(3)]
            pub LineupInfoType: $matter::definitions::Channel::types::LineupInfoTypeEnum,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PageTokenStruct {
            #[tagval(0)]
            pub Limit: core::option::Option<u16>,
            #[tagval(1)]
            pub After: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub Before: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProgramCastStruct {
            #[tagval(0)]
            pub Name: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Role: $matter::tlv::MatterString,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProgramCategoryStruct {
            #[tagval(0)]
            pub Category: $matter::tlv::MatterString,
            #[tagval(1)]
            pub SubCategory: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProgramStruct {
            #[tagval(0)]
            pub Identifier: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Channel: $matter::definitions::Channel::types::ChannelInfoStruct,
            #[tagval(2)]
            pub StartTime: u32,
            #[tagval(3)]
            pub EndTime: u32,
            #[tagval(4)]
            pub Title: $matter::tlv::MatterString,
            #[tagval(5)]
            pub Subtitle: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(6)]
            pub Description: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(7)]
            pub AudioLanguages: core::option::Option<$matter::tlv::MatterList<$matter::tlv::MatterString>>,
            #[tagval(8)]
            pub Ratings: core::option::Option<$matter::tlv::MatterList<$matter::tlv::MatterString>>,
            #[tagval(9)]
            pub ThumbnailUrl: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(10)]
            pub PosterArtUrl: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(11)]
            pub DvbiUrl: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(12)]
            pub ReleaseDate: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(13)]
            pub ParentalGuidanceText: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(14)]
            pub RecordingFlag: core::option::Option<$matter::definitions::Channel::types::RecordingFlagBitmap>,
            #[tagval(15)]
            pub SeriesInfo: core::option::Option<$matter::tlv::Nullable<$matter::definitions::Channel::types::SeriesInfoStruct>>,
            #[tagval(16)]
            pub CategoryList: core::option::Option<$matter::tlv::MatterList<$matter::definitions::Channel::types::ProgramCategoryStruct>>,
            #[tagval(17)]
            pub CastList: core::option::Option<$matter::tlv::MatterList<$matter::definitions::Channel::types::ProgramCastStruct>>,
            #[tagval(18)]
            pub ExternalIDList: core::option::Option<$matter::tlv::MatterList<$matter::tlv::MatterTlv>>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SeriesInfoStruct {
            #[tagval(0)]
            pub Season: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Episode: $matter::tlv::MatterString,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChannelList(pub $matter::tlv::MatterList<$matter::definitions::Channel::types::ChannelInfoStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Lineup(pub $matter::tlv::Nullable<$matter::definitions::Channel::types::LineupInfoStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentChannel(pub $matter::tlv::Nullable<$matter::definitions::Channel::types::ChannelInfoStruct>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = ChangeChannelResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeChannel {
            #[tagval(0)]
            pub Match: $matter::tlv::MatterString,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeChannelResponse {
            #[tagval(0)]
            pub Status: $matter::definitions::Channel::types::StatusEnum,
            #[tagval(1)]
            pub Data: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeChannelByNumber {
            #[tagval(0)]
            pub MajorNumber: u16,
            #[tagval(1)]
            pub MinorNumber: u16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SkipChannel {
            #[tagval(0)]
            pub Count: i16,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4, response = ProgramGuideResponse, response_id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct GetProgramGuide {
            #[tagval(0)]
            pub StartTime: u32,
            #[tagval(1)]
            pub EndTime: u32,
            #[tagval(2)]
            pub ChannelList: core::option::Option<$matter::tlv::MatterList<$matter::definitions::Channel::types::ChannelInfoStruct>>,
            #[tagval(3)]
            pub PageToken: core::option::Option<$matter::tlv::Nullable<$matter::definitions::Channel::types::PageTokenStruct>>,
            #[tagval(5)]
            pub RecordingFlag: core::option::Option<$matter::tlv::Nullable<$matter::definitions::Channel::types::RecordingFlagBitmap>>,
            #[tagval(6)]
            pub ExternalIDList: core::option::Option<$matter::tlv::MatterList<$matter::tlv::MatterTlv>>,
            #[tagval(7)]
            pub Data: core::option::Option<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ProgramGuideResponse {
            #[tagval(0)]
            pub Paging: $matter::definitions::Channel::types::ChannelPagingStruct,
            #[tagval(1)]
            pub ProgramList: $matter::tlv::MatterList<$matter::definitions::Channel::types::ProgramStruct>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RecordProgram {
            #[tagval(0)]
            pub ProgramIdentifier: $matter::tlv::MatterString,
            #[tagval(1)]
            pub ShouldRecordSeries: bool,
            #[tagval(2)]
            pub ExternalIDList: core::option::Option<$matter::tlv::MatterList<$matter::tlv::MatterTlv>>,
            #[tagval(3)]
            pub Data: core::option::Option<$matter::tlv::MatterBytes>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x7)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CancelRecordProgram {
            #[tagval(0)]
            pub ProgramIdentifier: $matter::tlv::MatterString,
            #[tagval(1)]
            pub ShouldRecordSeries: bool,
            #[tagval(2)]
            pub ExternalIDList: core::option::Option<$matter::tlv::MatterList<$matter::tlv::MatterTlv>>,
            #[tagval(3)]
            pub Data: core::option::Option<$matter::tlv::MatterBytes>,
        }
    }
    pub mod events {
    }
}
pub mod EcosystemInformation {
    pub const ID: u32 = 0x0750;
    pub mod types {
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DeviceTypeStruct {
            #[tagval(0)]
            pub DeviceType: u32,
            #[tagval(1)]
            pub Revision: u16,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EcosystemDeviceStruct {
            #[tagval(0)]
            pub DeviceName: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(1)]
            pub DeviceNameLastEdit: u64,
            #[tagval(2)]
            pub BridgedEndpoint: u16,
            #[tagval(3)]
            pub OriginalEndpoint: u16,
            #[tagval(4)]
            pub DeviceTypes: $matter::tlv::MatterList<$matter::definitions::EcosystemInformation::types::DeviceTypeStruct>,
            #[tagval(5)]
            pub UniqueLocationIDs: $matter::tlv::MatterList<$matter::tlv::MatterString>,
            #[tagval(6)]
            pub UniqueLocationIDsLastEdit: u64,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct EcosystemLocationStruct {
            #[tagval(0)]
            pub UniqueLocationID: $matter::tlv::MatterString,
            #[tagval(1)]
            pub LocationDescriptor: $matter::definitions::GlobalElements::types::LocationDescriptorStruct,
            #[tagval(2)]
            pub LocationDescriptorLastEdit: u64,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DeviceDirectory(pub $matter::tlv::MatterList<$matter::definitions::EcosystemInformation::types::EcosystemDeviceStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LocationDirectory(pub $matter::tlv::MatterList<$matter::definitions::EcosystemInformation::types::EcosystemLocationStruct>);
    }
    pub mod commands {
    }
    pub mod events {
    }
}
pub mod OvenMode {
    pub const ID: u32 = 0x0049;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ModeTag(pub u16);
        #[allow(non_upper_case_globals)]
        impl ModeTag {
            pub const Auto: Self = Self(0x0);
            pub const Quick: Self = Self(0x1);
            pub const Quiet: Self = Self(0x2);
            pub const LowNoise: Self = Self(0x3);
            pub const LowEnergy: Self = Self(0x4);
            pub const Vacation: Self = Self(0x5);
            pub const Min: Self = Self(0x6);
            pub const Max: Self = Self(0x7);
            pub const Night: Self = Self(0x8);
            pub const Day: Self = Self(0x9);
            pub const Bake: Self = Self(0x4000);
            pub const Convection: Self = Self(0x4001);
            pub const Grill: Self = Self(0x4002);
            pub const Roast: Self = Self(0x4003);
            pub const Clean: Self = Self(0x4004);
            pub const ConvectionBake: Self = Self(0x4005);
            pub const ConvectionRoast: Self = Self(0x4006);
            pub const Warming: Self = Self(0x4007);
            pub const Proofing: Self = Self(0x4008);
            pub const Steam: Self = Self(0x4009);
            pub const AirFry: Self = Self(0x400A);
            pub const AirSousVide: Self = Self(0x400B);
            pub const FrozenFood: Self = Self(0x400C);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeOptionStruct {
            #[tagval(0)]
            pub Label: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Mode: u8,
            #[tagval(2)]
            pub ModeTags: $matter::tlv::MatterList<$matter::definitions::OvenMode::types::ModeTagStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeTagStruct {
            #[tagval(0)]
            pub MfgCode: core::option::Option<u16>,
            #[tagval(1)]
            pub Value: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedModes(pub $matter::tlv::MatterList<$matter::definitions::OvenMode::types::ModeOptionStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentMode(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartUpMode(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnMode(pub $matter::tlv::Nullable<u8>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = ChangeToModeResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToMode {
            #[tagval(0)]
            pub NewMode: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToModeResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub StatusText: $matter::tlv::MatterString,
        }
    }
    pub mod events {
    }
}
pub mod DeviceEnergyManagement {
    pub const ID: u32 = 0x0098;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct AdjustmentCauseEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl AdjustmentCauseEnum {
            pub const LocalOptimization: Self = Self(0x0);
            pub const GridOptimization: Self = Self(0x1);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct CauseEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl CauseEnum {
            pub const NormalCompletion: Self = Self(0x0);
            pub const Offline: Self = Self(0x1);
            pub const Fault: Self = Self(0x2);
            pub const UserOptOut: Self = Self(0x3);
            pub const Cancelled: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct CostTypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl CostTypeEnum {
            pub const Financial: Self = Self(0x0);
            pub const GHGEmissions: Self = Self(0x1);
            pub const Comfort: Self = Self(0x2);
            pub const Temperature: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ESAStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ESAStateEnum {
            pub const Offline: Self = Self(0x0);
            pub const Online: Self = Self(0x1);
            pub const Fault: Self = Self(0x2);
            pub const PowerAdjustActive: Self = Self(0x3);
            pub const Paused: Self = Self(0x4);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ESATypeEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ESATypeEnum {
            pub const EVSE: Self = Self(0x0);
            pub const SpaceHeating: Self = Self(0x1);
            pub const WaterHeating: Self = Self(0x2);
            pub const SpaceCooling: Self = Self(0x3);
            pub const SpaceHeatingCooling: Self = Self(0x4);
            pub const BatteryStorage: Self = Self(0x5);
            pub const SolarPV: Self = Self(0x6);
            pub const FridgeFreezer: Self = Self(0x7);
            pub const WashingMachine: Self = Self(0x8);
            pub const Dishwasher: Self = Self(0x9);
            pub const Cooking: Self = Self(0xA);
            pub const HomeWaterPump: Self = Self(0xB);
            pub const IrrigationWaterPump: Self = Self(0xC);
            pub const PoolPump: Self = Self(0xD);
            pub const Other: Self = Self(0xFF);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ForecastUpdateReasonEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ForecastUpdateReasonEnum {
            pub const InternalOptimization: Self = Self(0x0);
            pub const LocalOptimization: Self = Self(0x1);
            pub const GridOptimization: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OptOutStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl OptOutStateEnum {
            pub const NoOptOut: Self = Self(0x0);
            pub const LocalOptOut: Self = Self(0x1);
            pub const GridOptOut: Self = Self(0x2);
            pub const OptOut: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct PowerAdjustReasonEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl PowerAdjustReasonEnum {
            pub const NoAdjustment: Self = Self(0x0);
            pub const LocalOptimizationAdjustment: Self = Self(0x1);
            pub const GridOptimizationAdjustment: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ConstraintsStruct {
            #[tagval(0)]
            pub StartTime: u32,
            #[tagval(1)]
            pub Duration: u32,
            #[tagval(2)]
            pub NominalPower: core::option::Option<i64>,
            #[tagval(3)]
            pub MaximumEnergy: core::option::Option<i64>,
            #[tagval(4)]
            pub LoadControl: core::option::Option<i8>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CostStruct {
            #[tagval(0)]
            pub CostType: $matter::definitions::DeviceEnergyManagement::types::CostTypeEnum,
            #[tagval(1)]
            pub Value: i32,
            #[tagval(2)]
            pub DecimalPoints: u8,
            #[tagval(3)]
            pub Currency: core::option::Option<u16>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ForecastStruct {
            #[tagval(0)]
            pub ForecastID: u32,
            #[tagval(1)]
            pub ActiveSlotNumber: $matter::tlv::Nullable<u16>,
            #[tagval(2)]
            pub StartTime: u32,
            #[tagval(3)]
            pub EndTime: u32,
            #[tagval(4)]
            pub EarliestStartTime: core::option::Option<$matter::tlv::Nullable<u32>>,
            #[tagval(5)]
            pub LatestEndTime: core::option::Option<u32>,
            #[tagval(6)]
            pub IsPausable: bool,
            #[tagval(7)]
            pub Slots: $matter::tlv::MatterList<$matter::definitions::DeviceEnergyManagement::types::SlotStruct>,
            #[tagval(8)]
            pub ForecastUpdateReason: $matter::definitions::DeviceEnergyManagement::types::ForecastUpdateReasonEnum,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PowerAdjustCapabilityStruct {
            #[tagval(0)]
            pub PowerAdjustCapability: $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::definitions::DeviceEnergyManagement::types::PowerAdjustStruct>>,
            #[tagval(1)]
            pub Cause: $matter::definitions::DeviceEnergyManagement::types::PowerAdjustReasonEnum,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PowerAdjustStruct {
            #[tagval(0)]
            pub MinPower: i64,
            #[tagval(1)]
            pub MaxPower: i64,
            #[tagval(2)]
            pub MinDuration: u32,
            #[tagval(3)]
            pub MaxDuration: u32,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SlotAdjustmentStruct {
            #[tagval(0)]
            pub SlotIndex: u8,
            #[tagval(1)]
            pub NominalPower: core::option::Option<i64>,
            #[tagval(2)]
            pub Duration: u32,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SlotStruct {
            #[tagval(0)]
            pub MinDuration: u32,
            #[tagval(1)]
            pub MaxDuration: u32,
            #[tagval(2)]
            pub DefaultDuration: u32,
            #[tagval(3)]
            pub ElapsedSlotTime: u32,
            #[tagval(4)]
            pub RemainingSlotTime: u32,
            #[tagval(5)]
            pub SlotIsPausable: core::option::Option<bool>,
            #[tagval(6)]
            pub MinPauseDuration: core::option::Option<u32>,
            #[tagval(7)]
            pub MaxPauseDuration: core::option::Option<u32>,
            #[tagval(8)]
            pub ManufacturerESAState: core::option::Option<u16>,
            #[tagval(9)]
            pub NominalPower: core::option::Option<i64>,
            #[tagval(10)]
            pub MinPower: core::option::Option<i64>,
            #[tagval(11)]
            pub MaxPower: core::option::Option<i64>,
            #[tagval(12)]
            pub NominalEnergy: core::option::Option<i64>,
            #[tagval(13)]
            pub Costs: core::option::Option<$matter::tlv::MatterList<$matter::definitions::DeviceEnergyManagement::types::CostStruct>>,
            #[tagval(14)]
            pub MinPowerAdjustment: core::option::Option<i64>,
            #[tagval(15)]
            pub MaxPowerAdjustment: core::option::Option<i64>,
            #[tagval(16)]
            pub MinDurationAdjustment: core::option::Option<u32>,
            #[tagval(17)]
            pub MaxDurationAdjustment: core::option::Option<u32>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ESAType(pub $matter::definitions::DeviceEnergyManagement::types::ESATypeEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ESACanGenerate(pub bool);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ESAState(pub $matter::definitions::DeviceEnergyManagement::types::ESAStateEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AbsMinPower(pub i64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AbsMaxPower(pub i64);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PowerAdjustmentCapability(pub $matter::tlv::Nullable<$matter::definitions::DeviceEnergyManagement::types::PowerAdjustCapabilityStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Forecast(pub $matter::tlv::Nullable<$matter::definitions::DeviceEnergyManagement::types::ForecastStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OptOutState(pub $matter::definitions::DeviceEnergyManagement::types::OptOutStateEnum);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PowerAdjustRequest {
            #[tagval(0)]
            pub Power: i64,
            #[tagval(1)]
            pub Duration: u32,
            #[tagval(2)]
            pub Cause: $matter::definitions::DeviceEnergyManagement::types::AdjustmentCauseEnum,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CancelPowerAdjustRequest {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartTimeAdjustRequest {
            #[tagval(0)]
            pub RequestedStartTime: u32,
            #[tagval(1)]
            pub Cause: $matter::definitions::DeviceEnergyManagement::types::AdjustmentCauseEnum,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PauseRequest {
            #[tagval(0)]
            pub Duration: u32,
            #[tagval(1)]
            pub Cause: $matter::definitions::DeviceEnergyManagement::types::AdjustmentCauseEnum,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ResumeRequest {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x5)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModifyForecastRequest {
            #[tagval(0)]
            pub ForecastID: u32,
            #[tagval(1)]
            pub SlotAdjustments: $matter::tlv::MatterList<$matter::definitions::DeviceEnergyManagement::types::SlotAdjustmentStruct>,
            #[tagval(2)]
            pub Cause: $matter::definitions::DeviceEnergyManagement::types::AdjustmentCauseEnum,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x6)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RequestConstraintBasedForecast {
            #[tagval(0)]
            pub Constraints: $matter::tlv::MatterList<$matter::definitions::DeviceEnergyManagement::types::ConstraintsStruct>,
            #[tagval(1)]
            pub Cause: $matter::definitions::DeviceEnergyManagement::types::AdjustmentCauseEnum,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x7)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CancelRequest {
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PowerAdjustStart {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PowerAdjustEnd {
            #[tagval(0)]
            pub Cause: $matter::definitions::DeviceEnergyManagement::types::CauseEnum,
            #[tagval(1)]
            pub Duration: u32,
            #[tagval(2)]
            pub EnergyUse: i64,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x2)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Paused {
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x3)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Resumed {
            #[tagval(0)]
            pub Cause: $matter::definitions::DeviceEnergyManagement::types::CauseEnum,
        }
    }
}
pub mod TemperatureControl {
    pub const ID: u32 = 0x0056;
    pub mod types {
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TemperatureSetpoint(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MinTemperature(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct MaxTemperature(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Step(pub i16);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SelectedTemperatureLevel(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedTemperatureLevels(pub $matter::tlv::MatterList<$matter::tlv::MatterString>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SetTemperature {
            #[tagval(0)]
            pub TargetTemperature: core::option::Option<i16>,
            #[tagval(1)]
            pub TargetTemperatureLevel: core::option::Option<u8>,
        }
    }
    pub mod events {
    }
}
pub mod DeviceEnergyManagementMode {
    pub const ID: u32 = 0x009F;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ModeTag(pub u16);
        #[allow(non_upper_case_globals)]
        impl ModeTag {
            pub const Auto: Self = Self(0x0);
            pub const Quick: Self = Self(0x1);
            pub const Quiet: Self = Self(0x2);
            pub const LowNoise: Self = Self(0x3);
            pub const LowEnergy: Self = Self(0x4);
            pub const Vacation: Self = Self(0x5);
            pub const Min: Self = Self(0x6);
            pub const Max: Self = Self(0x7);
            pub const Night: Self = Self(0x8);
            pub const Day: Self = Self(0x9);
            pub const NoOptimization: Self = Self(0x4000);
            pub const DeviceOptimization: Self = Self(0x4001);
            pub const LocalOptimization: Self = Self(0x4002);
            pub const GridOptimization: Self = Self(0x4003);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeOptionStruct {
            #[tagval(0)]
            pub Label: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Mode: u8,
            #[tagval(2)]
            pub ModeTags: $matter::tlv::MatterList<$matter::definitions::DeviceEnergyManagementMode::types::ModeTagStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeTagStruct {
            #[tagval(0)]
            pub MfgCode: core::option::Option<u16>,
            #[tagval(1)]
            pub Value: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedModes(pub $matter::tlv::MatterList<$matter::definitions::DeviceEnergyManagementMode::types::ModeOptionStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentMode(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartUpMode(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnMode(pub $matter::tlv::Nullable<u8>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = ChangeToModeResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToMode {
            #[tagval(0)]
            pub NewMode: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToModeResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub StatusText: $matter::tlv::MatterString,
        }
    }
    pub mod events {
    }
}
pub mod Chime {
    pub const ID: u32 = 0x0556;
    pub mod types {
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChimeSoundStruct {
            #[tagval(0)]
            pub ChimeID: u8,
            #[tagval(1)]
            pub Name: $matter::tlv::MatterString,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct InstalledChimeSounds(pub $matter::tlv::MatterList<$matter::definitions::Chime::types::ChimeSoundStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SelectedChime(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Enabled(pub bool);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PlayChimeSound {
        }
    }
    pub mod events {
    }
}
pub mod LaundryWasherMode {
    pub const ID: u32 = 0x0051;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ModeTag(pub u16);
        #[allow(non_upper_case_globals)]
        impl ModeTag {
            pub const Auto: Self = Self(0x0);
            pub const Quick: Self = Self(0x1);
            pub const Quiet: Self = Self(0x2);
            pub const LowNoise: Self = Self(0x3);
            pub const LowEnergy: Self = Self(0x4);
            pub const Vacation: Self = Self(0x5);
            pub const Min: Self = Self(0x6);
            pub const Max: Self = Self(0x7);
            pub const Night: Self = Self(0x8);
            pub const Day: Self = Self(0x9);
            pub const Normal: Self = Self(0x4000);
            pub const Delicate: Self = Self(0x4001);
            pub const Heavy: Self = Self(0x4002);
            pub const Whites: Self = Self(0x4003);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeOptionStruct {
            #[tagval(0)]
            pub Label: $matter::tlv::MatterString,
            #[tagval(1)]
            pub Mode: u8,
            #[tagval(2)]
            pub ModeTags: $matter::tlv::MatterList<$matter::definitions::LaundryWasherMode::types::ModeTagStruct>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ModeTagStruct {
            #[tagval(0)]
            pub MfgCode: core::option::Option<u16>,
            #[tagval(1)]
            pub Value: u16,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedModes(pub $matter::tlv::MatterList<$matter::definitions::LaundryWasherMode::types::ModeOptionStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentMode(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct StartUpMode(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OnMode(pub $matter::tlv::Nullable<u8>);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = ChangeToModeResponse, response_id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToMode {
            #[tagval(0)]
            pub NewMode: u8,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ChangeToModeResponse {
            #[tagval(0)]
            pub Status: u8,
            #[tagval(1)]
            pub StatusText: $matter::tlv::MatterString,
        }
    }
    pub mod events {
    }
}
pub mod ValveConfigurationandControl {
    pub const ID: u32 = 0x0081;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct StatusCodeEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl StatusCodeEnum {
            pub const FailureDueToFault: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ValveStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl ValveStateEnum {
            pub const Closed: Self = Self(0x0);
            pub const Open: Self = Self(0x1);
            pub const Transitioning: Self = Self(0x2);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ValveFaultBitmap(pub u16);
        #[allow(non_upper_case_globals)]
        impl ValveFaultBitmap {
            pub const GeneralFault: Self = Self(0x1);
            pub const Blocked: Self = Self(0x2);
            pub const Leaking: Self = Self(0x4);
            pub const NotConnected: Self = Self(0x8);
            pub const ShortCircuit: Self = Self(0x10);
            pub const CurrentExceeded: Self = Self(0x20);
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OpenDuration(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DefaultOpenDuration(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct AutoCloseTime(pub $matter::tlv::Nullable<u64>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct RemainingDuration(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentState(pub $matter::tlv::Nullable<$matter::definitions::ValveConfigurationandControl::types::ValveStateEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TargetState(pub $matter::tlv::Nullable<$matter::definitions::ValveConfigurationandControl::types::ValveStateEnum>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x6, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentLevel(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x7, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct TargetLevel(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x8, readable = true, writable = true)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct DefaultOpenLevel(pub u8);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x9, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ValveFault(pub $matter::definitions::ValveConfigurationandControl::types::ValveFaultBitmap);
        #[$matter::matter_attribute(cluster = super::ID, id = 0xA, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct LevelStep(pub u8);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Open {
            #[tagval(0)]
            pub OpenDuration: core::option::Option<$matter::tlv::Nullable<u32>>,
            #[tagval(1)]
            pub TargetLevel: core::option::Option<u8>,
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Close {
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ValveStateChanged {
            #[tagval(0)]
            pub ValveState: $matter::definitions::ValveConfigurationandControl::types::ValveStateEnum,
            #[tagval(1)]
            pub ValveLevel: core::option::Option<u8>,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ValveFault {
            #[tagval(0)]
            pub ValveFault: $matter::definitions::ValveConfigurationandControl::types::ValveFaultBitmap,
        }
    }
}
pub mod OvenCavityOperationalState {
    pub const ID: u32 = 0x0048;
    pub mod types {
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct ErrorStateEnum(pub u16);
        #[allow(non_upper_case_globals)]
        impl ErrorStateEnum {
            pub const NoError: Self = Self(0x0);
            pub const UnableToStartOrResume: Self = Self(0x1);
            pub const UnableToCompleteOperation: Self = Self(0x2);
            pub const CommandInvalidInState: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct OperationalStateEnum(pub u8);
        #[allow(non_upper_case_globals)]
        impl OperationalStateEnum {
            pub const Stopped: Self = Self(0x0);
            pub const Running: Self = Self(0x1);
            pub const Paused: Self = Self(0x2);
            pub const Error: Self = Self(0x3);
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct ErrorStateStruct {
            #[tagval(0)]
            pub ErrorStateID: $matter::definitions::OvenCavityOperationalState::types::ErrorStateEnum,
            #[tagval(1)]
            pub ErrorStateLabel: core::option::Option<$matter::tlv::MatterString>,
            #[tagval(2)]
            pub ErrorStateDetails: core::option::Option<$matter::tlv::MatterString>,
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalStateStruct {
            #[tagval(0)]
            pub OperationalStateID: $matter::definitions::OvenCavityOperationalState::types::OperationalStateEnum,
            #[tagval(1)]
            pub OperationalStateLabel: core::option::Option<$matter::tlv::MatterString>,
        }
    }
    pub mod attributes {
        #[$matter::matter_attribute(cluster = super::ID, id = 0x0, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct PhaseList(pub $matter::tlv::Nullable<$matter::tlv::MatterList<$matter::tlv::MatterString>>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x1, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CurrentPhase(pub $matter::tlv::Nullable<u8>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x2, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct CountdownTime(pub $matter::tlv::Nullable<u32>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x3, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalStateList(pub $matter::tlv::MatterList<$matter::definitions::OvenCavityOperationalState::types::OperationalStateStruct>);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x4, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalState(pub $matter::definitions::OvenCavityOperationalState::types::OperationalStateEnum);
        #[$matter::matter_attribute(cluster = super::ID, id = 0x5, readable = true, writable = false)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalError(pub $matter::definitions::OvenCavityOperationalState::types::ErrorStateStruct);
    }
    pub mod commands {
        #[$matter::matter_command(cluster = super::ID, id = 0x0, response = OperationalCommandResponse, response_id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Pause {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x1, response = OperationalCommandResponse, response_id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Stop {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x2, response = OperationalCommandResponse, response_id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Start {
        }
        #[$matter::matter_command(cluster = super::ID, id = 0x3, response = OperationalCommandResponse, response_id = 0x4)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct Resume {
        }
        #[$matter::matter_tlv]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalCommandResponse {
            #[tagval(0)]
            pub CommandResponseState: $matter::definitions::OvenCavityOperationalState::types::ErrorStateStruct,
        }
    }
    pub mod events {
        #[$matter::matter_event(cluster = super::ID, id = 0x0)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationalError {
            #[tagval(0)]
            pub ErrorState: $matter::definitions::OvenCavityOperationalState::types::ErrorStateStruct,
        }
        #[$matter::matter_event(cluster = super::ID, id = 0x1)]
        #[tlvargs(unordered)]
        #[derive(Debug, Clone, PartialEq)]
        pub struct OperationCompletion {
            #[tagval(0)]
            pub CompletionErrorCode: u8,
            #[tagval(1)]
            pub TotalOperationalTime: core::option::Option<$matter::tlv::Nullable<u32>>,
            #[tagval(2)]
            pub PausedTime: core::option::Option<$matter::tlv::Nullable<u32>>,
        }
    }
}
    };
}
