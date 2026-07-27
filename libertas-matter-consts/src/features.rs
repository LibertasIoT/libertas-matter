// Copyright (c) 2026 Smartonlabs Inc.
// SPDX-License-Identifier: MIT

/** This cluster is used for managing the content control (including "parental control") settings on a media device such as a TV, or Set-top Box. */
pub mod ContentControl {
    /** Supports managing screen time limits. */
    pub const ScreenTime: u32 = 0x0001;
    /** Supports managing a PIN code which is used for restricting access to configuration of this feature. */
    pub const PINManagement: u32 = 0x0002;
    /** Supports managing content controls for unrated content. */
    pub const BlockUnrated: u32 = 0x0004;
    /** Supports managing content controls based upon rating threshold for on demand content. */
    pub const OnDemandContentRating: u32 = 0x0008;
    /** Supports managing content controls based upon rating threshold for scheduled content. */
    pub const ScheduledContentRating: u32 = 0x0010;
    /** Supports managing a set of channels that are prohibited. */
    pub const BlockChannels: u32 = 0x0020;
    /** Supports managing a set of applications that are prohibited. */
    pub const BlockApplications: u32 = 0x0040;
    /** Supports managing content controls based upon setting time window in which all contents and applications SHALL be blocked. */
    pub const BlockContentTimeWindow: u32 = 0x0080;
}
/** Attributes and commands for configuring the microwave oven control, and reporting cooking stats. */
pub mod MicrowaveOvenControl {
    /** Power is specified as a unitless number or a percentage */
    pub const PowerAsNumber: u32 = 0x0001;
    /** Power is specified in Watts */
    pub const PowerInWatts: u32 = 0x0002;
    /** Supports the limit attributes used with the PWRNUM feature */
    pub const PowerNumberLimits: u32 = 0x0004;
}
/** This cluster exposes interactions with a switch device, for the purpose of using those interactions by other devices.
 * Two types of switch devices are supported: latching switch (e.g. rocker switch) and momentary switch (e.g. push button), distinguished with their feature flags.
 * Interactions with the switch device are exposed as attributes (for the latching switch) and as events (for both types of switches). An interested party MAY subscribe to these attributes/events and thus be informed of the interactions, and can perform actions based on this, for example by sending commands to perform an action such as controlling a light or a window shade. */
pub mod Switch {
    /** Switch is latching */
    pub const LatchingSwitch: u32 = 0x0001;
    /** Switch is momentary */
    pub const MomentarySwitch: u32 = 0x0002;
    /** Switch supports release events generation */
    pub const MomentarySwitchRelease: u32 = 0x0004;
    /** Switch supports long press detection */
    pub const MomentarySwitchLongPress: u32 = 0x0008;
    /** Switch supports multi-press detection */
    pub const MomentarySwitchMultiPress: u32 = 0x0010;
    /** Switch is momentary, targeted at specific user actions (focus on multi-press and optionally long press) with a reduced event generation scheme */
    pub const ActionSwitch: u32 = 0x0020;
}
/** This cluster is used to allow clients to control the operation of a hot water heating appliance so that it can be used with energy management. */
pub mod WaterHeaterManagement {
    /** Allows energy management control of the tank */
    pub const EnergyManagement: u32 = 0x0001;
    /** Supports monitoring the percentage of hot water in the tank */
    pub const TankPercent: u32 = 0x0002;
}
/** The Ethernet Network Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub mod EthernetNetworkDiagnostics {
    /** Node makes available the counts for the number of received and transmitted packets on the ethernet interface. */
    pub const PacketCounts: u32 = 0x0001;
    /** Node makes available the counts for the number of errors that have occurred during the reception and transmission of packets on the ethernet interface. */
    pub const ErrorCounts: u32 = 0x0002;
}
/** This cluster provides an interface for launching content on a media player device such as a TV or Speaker. */
pub mod ContentLauncher {
    /** Device supports content search (non-app specific) */
    pub const ContentSearch: u32 = 0x0001;
    /** Device supports basic URL-based file playback */
    pub const URLPlayback: u32 = 0x0002;
    /** Enables clients to implement more advanced media seeking behavior in their user interface, such as for example a "seek bar". */
    pub const AdvancedSeek: u32 = 0x0004;
    /** Device or app supports Text Tracks. */
    pub const TextTracks: u32 = 0x0008;
    /** Device or app supports Audio Tracks. */
    pub const AudioTracks: u32 = 0x0010;
}
/** The General Diagnostics Cluster, along with other diagnostics clusters, provide a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub mod GeneralDiagnostics {
    /** Support specific testing needs for extended Data Model features */
    pub const DataModelTest: u32 = 0x0001;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod FormaldehydeConcentrationMeasurement {
    /** Cluster supports numeric measurement of substance */
    pub const NumericMeasurement: u32 = 0x0001;
    /** Cluster supports basic level indication for substance using the ConcentrationLevel enum */
    pub const LevelIndication: u32 = 0x0002;
    /** Cluster supports the Medium Concentration Level */
    pub const MediumLevel: u32 = 0x0004;
    /** Cluster supports the Critical Concentration Level */
    pub const CriticalLevel: u32 = 0x0008;
    /** Cluster supports peak numeric measurement of substance */
    pub const PeakMeasurement: u32 = 0x0010;
    /** Cluster supports average numeric measurement of substance */
    pub const AverageMeasurement: u32 = 0x0020;
}
/** Allows servers to ensure that listed clients are notified when a server is available for communication. */
pub mod ICDManagement {
    /** Device supports attributes and commands for the Check-In Protocol support. */
    pub const CheckInProtocolSupport: u32 = 0x0001;
    /** Device supports the user active mode trigger feature. */
    pub const UserActiveModeTrigger: u32 = 0x0002;
    /** Device supports operating as a Long Idle Time ICD. */
    pub const LongIdleTimeSupport: u32 = 0x0004;
    /** Device supports dynamic switching from SIT to LIT operating modes. */
    pub const DynamicSitLitSupport: u32 = 0x0008;
}
/** Functionality to configure, enable, disable network credentials and access on a Matter device. */
pub mod NetworkCommissioning {
    /** Wi-Fi related features */
    pub const WiFiNetworkInterface: u32 = 0x0001;
    /** Thread related features */
    pub const ThreadNetworkInterface: u32 = 0x0002;
    /** Ethernet related features */
    pub const EthernetNetworkInterface: u32 = 0x0004;
}
/** Accurate time is required for a number of reasons, including scheduling, display and validating security materials. */
pub mod TimeSynchronization {
    /** Server supports time zone. */
    pub const TimeZone: u32 = 0x0001;
    /** Server supports an NTP or SNTP client. */
    pub const NTPClient: u32 = 0x0002;
    /** Server supports an NTP server role. */
    pub const NTPServer: u32 = 0x0004;
    /** Time synchronization client cluster is present. */
    pub const TimeSyncClient: u32 = 0x0008;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod RVCRunMode {
    /** Dependency with the OnOff cluster */
    pub const OnOff: u32 = 0x0001;
    /** Cluster supports changing run modes from non-Idle states */
    pub const DirectModeChange: u32 = 0x100000;
}
/** The Commodity Price Cluster provides the mechanism for communicating Gas, Energy, or Water pricing information within the premises. */
pub mod CommodityPrice {
    /** Forecasts upcoming pricing */
    pub const Forecasting: u32 = 0x0001;
}
/** This cluster provides an interface for launching content on a media player device such as a TV or Speaker. */
pub mod ApplicationLauncher {
    /** Support for attributes and commands required for endpoint to support launching any application within the supported application catalogs */
    pub const ApplicationPlatform: u32 = 0x0001;
}
/** The Thread Network Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems */
pub mod ThreadNetworkDiagnostics {
    /** Server supports the counts for the number of received and transmitted packets on the Thread interface. */
    pub const PacketCounts: u32 = 0x0001;
    /** Server supports the counts for the number of errors that have occurred during the reception and transmission of packets on the Thread interface. */
    pub const ErrorCounts: u32 = 0x0002;
    /** Server supports the counts for various MLE layer happenings. */
    pub const MLECounts: u32 = 0x0004;
    /** Server supports the counts for various MAC layer happenings. */
    pub const MACCounts: u32 = 0x0008;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod PM25ConcentrationMeasurement {
    /** Cluster supports numeric measurement of substance */
    pub const NumericMeasurement: u32 = 0x0001;
    /** Cluster supports basic level indication for substance using the ConcentrationLevel enum */
    pub const LevelIndication: u32 = 0x0002;
    /** Cluster supports the Medium Concentration Level */
    pub const MediumLevel: u32 = 0x0004;
    /** Cluster supports the Critical Concentration Level */
    pub const CriticalLevel: u32 = 0x0008;
    /** Cluster supports peak numeric measurement of substance */
    pub const PeakMeasurement: u32 = 0x0010;
    /** Cluster supports average numeric measurement of substance */
    pub const AverageMeasurement: u32 = 0x0020;
}
/** The Group Key Management Cluster is the mechanism by which group keys are managed. */
pub mod GroupKeyManagement {
    /** The ability to support CacheAndSync security policy and MCSP. */
    pub const CacheAndSync: u32 = 0x0001;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod CarbonMonoxideConcentrationMeasurement {
    /** Cluster supports numeric measurement of substance */
    pub const NumericMeasurement: u32 = 0x0001;
    /** Cluster supports basic level indication for substance using the ConcentrationLevel enum */
    pub const LevelIndication: u32 = 0x0002;
    /** Cluster supports the Medium Concentration Level */
    pub const MediumLevel: u32 = 0x0004;
    /** Cluster supports the Critical Concentration Level */
    pub const CriticalLevel: u32 = 0x0008;
    /** Cluster supports peak numeric measurement of substance */
    pub const PeakMeasurement: u32 = 0x0010;
    /** Cluster supports average numeric measurement of substance */
    pub const AverageMeasurement: u32 = 0x0020;
}
/** Attributes and commands for controlling devices that can be set to a level between fully 'On' and fully 'Off.' */
pub mod LevelControl {
    /** Dependency with the On/Off cluster */
    pub const OnOff: u32 = 0x0001;
    /** Behavior that supports lighting applications */
    pub const Lighting: u32 = 0x0002;
    /** Supports frequency attributes and behavior. */
    pub const Frequency: u32 = 0x0004;
}
/** Electric Vehicle Supply Equipment (EVSE) is equipment used to charge an Electric Vehicle (EV) or Plug-In Hybrid Electric Vehicle. This cluster provides an interface to the functionality of Electric Vehicle Supply Equipment (EVSE) management. */
pub mod EnergyEVSE {
    /** EVSE supports storing user charging preferences */
    pub const ChargingPreferences: u32 = 0x0001;
    /** EVSE supports reporting of vehicle State of Charge (SoC) */
    pub const SoCReporting: u32 = 0x0002;
    /** EVSE supports PLC to support Plug and Charge */
    pub const PlugAndCharge: u32 = 0x0004;
    /** EVSE is fitted with an RFID reader */
    pub const RFID: u32 = 0x0008;
    /** EVSE supports bi-directional charging / discharging */
    pub const V2X: u32 = 0x0010;
}
/** This Cluster serves two purposes towards a Node communicating with a Bridge: indicate that the functionality on
 * the Endpoint where it is placed (and its Parts) is bridged from a non-CHIP technology; and provide a centralized
 * collection of attributes that the Node MAY collect to aid in conveying information regarding the Bridged Device to a user,
 * such as the vendor name, the model name, or user-assigned name. */
pub mod BridgedDeviceBasicInformation {
    /** Support bridged ICDs. */
    pub const BridgedICDSupport: u32 = 0x100000;
}
/** The Software Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub mod SoftwareDiagnostics {
    /** Node makes available the metrics for high watermark related to memory consumption. */
    pub const Watermarks: u32 = 0x0001;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod DishwasherMode {
    /** Dependency with the OnOff cluster */
    pub const OnOff: u32 = 0x0001;
}
/** Commands to trigger a Node to allow a new Administrator to commission it. */
pub mod AdministratorCommissioning {
    /** Node supports Basic Commissioning Method. */
    pub const Basic: u32 = 0x0001;
}
/** This cluster provides an interface to manage regions of interest, or Zones, which can be either manufacturer or user defined. */
pub mod ZoneManagement {
    /** Supports Two Dimensional Cartesian Zones */
    pub const TwoDimensionalCartesianZone: u32 = 0x0001;
    /** Supports a sensitivity value per Zone */
    pub const PerZoneSensitivity: u32 = 0x0002;
    /** Supports user defined zones */
    pub const UserDefined: u32 = 0x0004;
    /** Supports user defined focus zones */
    pub const FocusZones: u32 = 0x0008;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod MicrowaveOvenMode {
    /** Dependency with the OnOff cluster */
    pub const OnOff: u32 = 0x0001;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod ModeSelect {
    /** Dependency with the OnOff cluster */
    pub const OnOff: u32 = 0x0001;
}
/** This cluster implements the upload of Audio and Video streams from the Push AV Stream Transport Cluster using suitable push-based transports. */
pub mod PushAVStreamTransport {
    /** Supports a sensitivity value per Zone */
    pub const PerZoneSensitivity: u32 = 0x0001;
    /** Supports metadata transmission in Push transports */
    pub const Metadata: u32 = 0x0002;
}
/** Nodes should be expected to be deployed to any and all regions of the world. These global regions
 * may have differing preferences for how dates and times are conveyed. As such, Nodes that visually
 * or audibly convey time information need a mechanism by which they can be configured to use a
 * user’s preferred format. */
pub mod TimeFormatLocalization {
    /** The Node can be configured to use different calendar formats when conveying values to a user. */
    pub const CalendarFormat: u32 = 0x0001;
}
/** This cluster provides an interface for controlling the Output on a media device such as a TV. */
pub mod AudioOutput {
    /** Supports updates to output names */
    pub const NameUpdates: u32 = 0x0001;
}
/** Attributes and commands for switching devices between 'On' and 'Off' states. */
pub mod OnOff {
    /** Behavior that supports lighting applications. */
    pub const Lighting: u32 = 0x0001;
    /** Device has Dead Front behavior */
    pub const DeadFrontBehavior: u32 = 0x0002;
    /** Device supports the OffOnly Feature feature */
    pub const OffOnly: u32 = 0x0004;
}
/** Attributes and commands for controlling the color properties of a color-capable light. */
pub mod ColorControl {
    /** Supports color specification via hue/saturation. */
    pub const HueSaturation: u32 = 0x0001;
    /** Enhanced hue is supported. */
    pub const EnhancedHue: u32 = 0x0002;
    /** Color loop is supported. */
    pub const ColorLoop: u32 = 0x0004;
    /** Supports color specification via XY. */
    pub const XY: u32 = 0x0008;
    /** Supports specification of color temperature. */
    pub const ColorTemperature: u32 = 0x0010;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod PM10ConcentrationMeasurement {
    /** Cluster supports numeric measurement of substance */
    pub const NumericMeasurement: u32 = 0x0001;
    /** Cluster supports basic level indication for substance using the ConcentrationLevel enum */
    pub const LevelIndication: u32 = 0x0002;
    /** Cluster supports the Medium Concentration Level */
    pub const MediumLevel: u32 = 0x0004;
    /** Cluster supports the Critical Concentration Level */
    pub const CriticalLevel: u32 = 0x0008;
    /** Cluster supports peak numeric measurement of substance */
    pub const PeakMeasurement: u32 = 0x0010;
    /** Cluster supports average numeric measurement of substance */
    pub const AverageMeasurement: u32 = 0x0020;
}
/** Attributes and commands for configuring the Dishwasher alarm. */
pub mod DishwasherAlarm {
    /** Supports the ability to reset alarms */
    pub const Reset: u32 = 0x0001;
}
/** This cluster provides an interface for observing and managing the state of smoke and CO alarms. */
pub mod SmokeCOAlarm {
    /** Supports Smoke alarm */
    pub const SmokeAlarm: u32 = 0x0001;
    /** Supports CO alarm */
    pub const COAlarm: u32 = 0x0002;
}
/** This cluster provides an interface into controls associated with the operation of a device that provides pan, tilt, and zoom functions, either mechanically, or against a digital image. */
pub mod CameraAVSettingsUserLevelManagement {
    /** Digital PTZ support */
    pub const DigitalPTZ: u32 = 0x0001;
    /** Mechanical Pan support */
    pub const MechanicalPan: u32 = 0x0002;
    /** Mechanical Tilt support */
    pub const MechanicalTilt: u32 = 0x0004;
    /** Mechanical Zoom support */
    pub const MechanicalZoom: u32 = 0x0008;
    /** Mechanical saved presets support */
    pub const MechanicalPresets: u32 = 0x0010;
}
/** This cluster provides an interface for passing messages to be presented by a device. */
pub mod Messages {
    pub const ReceivedConfirmation: u32 = 0x0001;
    pub const ConfirmationResponse: u32 = 0x0002;
    pub const ConfirmationReply: u32 = 0x0004;
    pub const ProtectedMessages: u32 = 0x0008;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod CarbonDioxideConcentrationMeasurement {
    /** Cluster supports numeric measurement of substance */
    pub const NumericMeasurement: u32 = 0x0001;
    /** Cluster supports basic level indication for substance using the ConcentrationLevel enum */
    pub const LevelIndication: u32 = 0x0002;
    /** Cluster supports the Medium Concentration Level */
    pub const MediumLevel: u32 = 0x0004;
    /** Cluster supports the Critical Concentration Level */
    pub const CriticalLevel: u32 = 0x0008;
    /** Cluster supports peak numeric measurement of substance */
    pub const PeakMeasurement: u32 = 0x0010;
    /** Cluster supports average numeric measurement of substance */
    pub const AverageMeasurement: u32 = 0x0020;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod RVCCleanMode {
    /** Dependency with the OnOff cluster */
    pub const OnOff: u32 = 0x0001;
    /** Cluster supports changing clean modes from non-Idle states */
    pub const DirectModeChange: u32 = 0x100000;
}
/** This cluster provides a mechanism for querying data about electrical power as measured by the server. */
pub mod ElectricalPowerMeasurement {
    /** Supports measurement of direct current */
    pub const DirectCurrent: u32 = 0x0001;
    /** Supports measurement of alternating current */
    pub const AlternatingCurrent: u32 = 0x0002;
    /** Supports polyphase measurements */
    pub const PolyphasePower: u32 = 0x0004;
    /** Supports measurement of AC harmonics */
    pub const Harmonics: u32 = 0x0008;
    /** Supports measurement of AC harmonic phases */
    pub const PowerQuality: u32 = 0x0010;
}
/** Nodes should be expected to be deployed to any and all regions of the world. These global regions
 * may have differing preferences for the units in which values are conveyed in communication to a
 * user. As such, Nodes that visually or audibly convey measurable values to the user need a
 * mechanism by which they can be configured to use a user’s preferred unit. */
pub mod UnitLocalization {
    /** The Node can be configured to use different units of temperature when conveying values to a user. */
    pub const TemperatureUnit: u32 = 0x0001;
}
/** This cluster is used to describe the configuration and capabilities of a physical power source that provides power to the Node. */
pub mod PowerSource {
    /** A wired power source */
    pub const Wired: u32 = 0x0001;
    /** A battery power source */
    pub const Battery: u32 = 0x0002;
    /** A rechargeable battery power source */
    pub const Rechargeable: u32 = 0x0004;
    /** A replaceable battery power source */
    pub const Replaceable: u32 = 0x0008;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod OzoneConcentrationMeasurement {
    /** Cluster supports numeric measurement of substance */
    pub const NumericMeasurement: u32 = 0x0001;
    /** Cluster supports basic level indication for substance using the ConcentrationLevel enum */
    pub const LevelIndication: u32 = 0x0002;
    /** Cluster supports the Medium Concentration Level */
    pub const MediumLevel: u32 = 0x0004;
    /** Cluster supports the Critical Concentration Level */
    pub const CriticalLevel: u32 = 0x0008;
    /** Cluster supports peak numeric measurement of substance */
    pub const PeakMeasurement: u32 = 0x0010;
    /** Cluster supports average numeric measurement of substance */
    pub const AverageMeasurement: u32 = 0x0020;
}
/** The Power Topology Cluster provides a mechanism for expressing how power is flowing between endpoints. */
pub mod PowerTopology {
    /** This endpoint provides or consumes power to/from the entire node */
    pub const NodeTopology: u32 = 0x0001;
    /** This endpoint provides or consumes power to/from itself and its child endpoints */
    pub const TreeTopology: u32 = 0x0002;
    /** This endpoint provides or consumes power to/from a specified set of endpoints */
    pub const SetTopology: u32 = 0x0004;
    /** The specified set of endpoints may change */
    pub const DynamicPowerFlow: u32 = 0x0008;
}
/** The Descriptor Cluster is meant to replace the support from the Zigbee Device Object (ZDO) for describing a node, its endpoints and clusters. */
pub mod Descriptor {
    /** The TagList attribute is present */
    pub const TagList: u32 = 0x0001;
}
/** The Electrical Grid Conditions Cluster provides the mechanism for communicating electricity grid carbon intensity to devices within the premises in units of Grams of CO2e per kWh. */
pub mod ElectricalGridConditions {
    /** Forecasts upcoming */
    pub const Forecasting: u32 = 0x0001;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod NitrogenDioxideConcentrationMeasurement {
    /** Cluster supports numeric measurement of substance */
    pub const NumericMeasurement: u32 = 0x0001;
    /** Cluster supports basic level indication for substance using the ConcentrationLevel enum */
    pub const LevelIndication: u32 = 0x0002;
    /** Cluster supports the Medium Concentration Level */
    pub const MediumLevel: u32 = 0x0004;
    /** Cluster supports the Critical Concentration Level */
    pub const CriticalLevel: u32 = 0x0008;
    /** Cluster supports peak numeric measurement of substance */
    pub const PeakMeasurement: u32 = 0x0010;
    /** Cluster supports average numeric measurement of substance */
    pub const AverageMeasurement: u32 = 0x0020;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod PM1ConcentrationMeasurement {
    /** Cluster supports numeric measurement of substance */
    pub const NumericMeasurement: u32 = 0x0001;
    /** Cluster supports basic level indication for substance using the ConcentrationLevel enum */
    pub const LevelIndication: u32 = 0x0002;
    /** Cluster supports the Medium Concentration Level */
    pub const MediumLevel: u32 = 0x0004;
    /** Cluster supports the Critical Concentration Level */
    pub const CriticalLevel: u32 = 0x0008;
    /** Cluster supports peak numeric measurement of substance */
    pub const PeakMeasurement: u32 = 0x0010;
    /** Cluster supports average numeric measurement of substance */
    pub const AverageMeasurement: u32 = 0x0020;
}
/** This cluster provides an interface for controlling Media Playback (PLAY, PAUSE, etc) on a media device such as a TV or Speaker. */
pub mod MediaPlayback {
    /** Advanced media seeking */
    pub const AdvancedSeek: u32 = 0x0001;
    /** Variable speed playback */
    pub const VariableSpeed: u32 = 0x0002;
    /** Text Tracks */
    pub const TextTracks: u32 = 0x0004;
    /** Audio Tracks */
    pub const AudioTracks: u32 = 0x0008;
    /** Can play audio during fast and slow playback speeds */
    pub const AudioAdvance: u32 = 0x0010;
}
/** Provides an interface for controlling and adjusting automatic window coverings. */
pub mod WindowCovering {
    /** Lift control and behavior for lifting/sliding window coverings */
    pub const Lift: u32 = 0x0001;
    /** Tilt control and behavior for tilting window coverings */
    pub const Tilt: u32 = 0x0002;
    /** Position aware lift control is supported. */
    pub const PositionAwareLift: u32 = 0x0004;
    /** Position aware tilt control is supported. */
    pub const PositionAwareTilt: u32 = 0x0010;
}
/** The Wi-Fi Network Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub mod WiFiNetworkDiagnostics {
    /** Node makes available the counts for the number of received and transmitted packets on the Wi-Fi interface. */
    pub const PacketCounts: u32 = 0x0001;
    /** Node makes available the counts for the number of errors that have occurred during the reception and transmission of packets on the Wi-Fi interface. */
    pub const ErrorCounts: u32 = 0x0002;
}
/** Attributes for reporting air quality classification */
pub mod AirQuality {
    /** Cluster supports the Fair air quality level */
    pub const Fair: u32 = 0x0001;
    /** Cluster supports the Moderate air quality level */
    pub const Moderate: u32 = 0x0002;
    /** Cluster supports the Very poor air quality level */
    pub const VeryPoor: u32 = 0x0004;
    /** Cluster supports the Extremely poor air quality level */
    pub const ExtremelyPoor: u32 = 0x0008;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod TotalVolatileOrganicCompoundsConcentrationMeasurement {
    /** Cluster supports numeric measurement of substance */
    pub const NumericMeasurement: u32 = 0x0001;
    /** Cluster supports basic level indication for substance using the ConcentrationLevel enum */
    pub const LevelIndication: u32 = 0x0002;
    /** Cluster supports the Medium Concentration Level */
    pub const MediumLevel: u32 = 0x0004;
    /** Cluster supports the Critical Concentration Level */
    pub const CriticalLevel: u32 = 0x0008;
    /** Cluster supports peak numeric measurement of substance */
    pub const PeakMeasurement: u32 = 0x0010;
    /** Cluster supports average numeric measurement of substance */
    pub const AverageMeasurement: u32 = 0x0020;
}
/** The Service Area cluster provides an interface for controlling the areas where a device should operate, and for querying the current area being serviced. */
pub mod ServiceArea {
    /** The device allows changing the selected areas while running */
    pub const SelectWhileRunning: u32 = 0x0001;
    /** The device implements the progress reporting feature */
    pub const ProgressReporting: u32 = 0x0002;
    /** The device has map support */
    pub const Maps: u32 = 0x0004;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod RefrigeratorAndTemperatureControlledCabinetMode {
    /** Dependency with the OnOff cluster */
    pub const OnOff: u32 = 0x0001;
}
/** The Access Control Cluster exposes a data model view of a
 * Node's Access Control List (ACL), which codifies the rules used to manage
 * and enforce Access Control for the Node's endpoints and their associated
 * cluster instances. */
pub mod AccessControl {
    /** Device provides ACL Extension attribute */
    pub const Extension: u32 = 0x0001;
    /** Device is managed */
    pub const ManagedDevice: u32 = 0x0002;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod WaterHeaterMode {
    /** Dependency with the OnOff cluster */
    pub const OnOff: u32 = 0x0001;
}
/** This cluster provides a mechanism for querying data about the electrical energy imported or provided by the server. */
pub mod ElectricalEnergyMeasurement {
    /** Measurement of energy imported by the server */
    pub const ImportedEnergy: u32 = 0x0001;
    /** Measurement of energy provided by the server */
    pub const ExportedEnergy: u32 = 0x0002;
    /** Measurements are cumulative */
    pub const CumulativeEnergy: u32 = 0x0004;
    /** Measurements are periodic */
    pub const PeriodicEnergy: u32 = 0x0008;
    /** Measurements report apparent energy */
    pub const ApparentEnergy: u32 = 0x0010;
    /** Measurements report reactive energy */
    pub const ReactiveEnergy: u32 = 0x0020;
}
/** This cluster provides an interface for controlling a Closure. */
pub mod ClosureControl {
    /** Supports Positioning with at least Fully Opened (0%) and Fully Closed (100%) discrete positions */
    pub const Positioning: u32 = 0x0001;
    /** Supports a latch (securing a position, or a state) */
    pub const MotionLatching: u32 = 0x0002;
    /** Supports the Instantaneous feature */
    pub const Instantaneous: u32 = 0x0004;
    /** Supports Speed motion throttling */
    pub const Speed: u32 = 0x0008;
    /** Supports Ventilation discrete state */
    pub const Ventilation: u32 = 0x0010;
    /** Supports Pedestrian discrete state */
    pub const Pedestrian: u32 = 0x0020;
    /** Supports the Calibration feature */
    pub const Calibration: u32 = 0x0040;
    /** Supports the Protection feature */
    pub const Protection: u32 = 0x0080;
    /** Supports the manual operation feature */
    pub const ManuallyOperable: u32 = 0x0100;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod EnergyEVSEMode {
    /** Dependency with the OnOff cluster */
    pub const OnOff: u32 = 0x0001;
}
/** This cluster is used to configure a boolean sensor. */
pub mod BooleanStateConfiguration {
    /** Supports visual alarms */
    pub const Visual: u32 = 0x0001;
    /** Supports audible alarms */
    pub const Audible: u32 = 0x0002;
    /** Supports ability to suppress or acknowledge alarms */
    pub const AlarmSuppress: u32 = 0x0004;
    /** Supports ability to set sensor sensitivity */
    pub const SensitivityLevel: u32 = 0x0008;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod RadonConcentrationMeasurement {
    /** Cluster supports numeric measurement of substance */
    pub const NumericMeasurement: u32 = 0x0001;
    /** Cluster supports basic level indication for substance using the ConcentrationLevel enum */
    pub const LevelIndication: u32 = 0x0002;
    /** Cluster supports the Medium Concentration Level */
    pub const MediumLevel: u32 = 0x0004;
    /** Cluster supports the Critical Concentration Level */
    pub const CriticalLevel: u32 = 0x0008;
    /** Cluster supports peak numeric measurement of substance */
    pub const PeakMeasurement: u32 = 0x0010;
    /** Cluster supports average numeric measurement of substance */
    pub const AverageMeasurement: u32 = 0x0020;
}
/** This Meter Identification Cluster provides attributes for determining advanced information about utility metering device. */
pub mod MeterIdentification {
    /** Supports information about power threshold */
    pub const PowerThreshold: u32 = 0x0001;
}
/** This cluster provides an interface to specify preferences for how devices should consume energy. */
pub mod EnergyPreference {
    /** Device can balance energy consumption vs. another priority */
    pub const EnergyBalance: u32 = 0x0001;
    /** Device can adjust the conditions for entering a low power mode */
    pub const LowPowerModeSensitivity: u32 = 0x0002;
}
/** Attributes and commands for scene configuration and manipulation. */
pub mod ScenesManagement {
    /** The ability to store a name for a scene. */
    pub const SceneNames: u32 = 0x0001;
}
/** Attributes and commands for monitoring HEPA filters in a device */
pub mod HEPAFilterMonitoring {
    /** Supports monitoring the condition of the resource in percentage */
    pub const Condition: u32 = 0x0001;
    /** Supports warning indication */
    pub const Warning: u32 = 0x0002;
    /** Supports specifying the list of replacement products */
    pub const ReplacementProductList: u32 = 0x0004;
}
/** Attributes and commands for monitoring HEPA filters in a device */
pub mod ActivatedCarbonFilterMonitoring {
    /** Supports monitoring the condition of the resource in percentage */
    pub const Condition: u32 = 0x0001;
    /** Supports warning indication */
    pub const Warning: u32 = 0x0002;
    /** Supports specifying the list of replacement products */
    pub const ReplacementProductList: u32 = 0x0004;
}
/** Attributes and commands for monitoring HEPA filters in a device */
pub mod WaterTankLevelMonitoring {
    /** Supports monitoring the condition of the resource in percentage */
    pub const Condition: u32 = 0x0001;
    /** Supports warning indication */
    pub const Warning: u32 = 0x0002;
    /** Supports specifying the list of replacement products */
    pub const ReplacementProductList: u32 = 0x0004;
}
/** An interface for configuring and controlling pumps. */
pub mod PumpConfigurationandControl {
    /** Supports operating in constant pressure mode */
    pub const ConstantPressure: u32 = 0x0001;
    /** Supports operating in compensated pressure mode */
    pub const CompensatedPressure: u32 = 0x0002;
    /** Supports operating in constant flow mode */
    pub const ConstantFlow: u32 = 0x0004;
    /** Supports operating in constant speed mode */
    pub const ConstantSpeed: u32 = 0x0008;
    /** Supports operating in constant temperature mode */
    pub const ConstantTemperature: u32 = 0x0010;
    /** Supports operating in automatic mode */
    pub const Automatic: u32 = 0x0020;
    /** Supports operating using local settings */
    pub const LocalOperation: u32 = 0x0040;
}
/** This cluster is used to manage global aspects of the Commissioning flow. */
pub mod GeneralCommissioning {
    /** Supports Terms & Conditions acknowledgement */
    pub const TermsAndConditions: u32 = 0x0001;
    /** Supports Network Recovery */
    pub const NetworkRecovery: u32 = 0x0002;
}
/** An interface for controlling a fan in a heating/cooling system. */
pub mod FanControl {
    /** 0-SpeedMax Fan Speeds */
    pub const MultiSpeed: u32 = 0x0001;
    /** Automatic mode supported for fan speed */
    pub const Auto: u32 = 0x0002;
    /** Rocking movement supported */
    pub const Rocking: u32 = 0x0004;
    /** Wind emulation supported */
    pub const Wind: u32 = 0x0008;
    /** Step command supported */
    pub const Step: u32 = 0x0010;
    /** Airflow Direction attribute is supported */
    pub const AirflowDirection: u32 = 0x0020;
}
/** An interface to a generic way to secure a door */
pub mod DoorLock {
    /** Lock supports PIN credentials (via keypad, or over-the-air) */
    pub const PINCredential: u32 = 0x0001;
    /** Lock supports RFID credentials */
    pub const RFIDCredential: u32 = 0x0002;
    /** Lock supports finger related credentials (fingerprint, finger vein) */
    pub const FingerCredentials: u32 = 0x0004;
    /** Lock supports week day user access schedules */
    pub const WeekDayAccessSchedules: u32 = 0x0010;
    /** Lock supports a door position sensor that indicates door's state */
    pub const DoorPositionSensor: u32 = 0x0020;
    /** Lock supports face related credentials (face, iris, retina) */
    pub const FaceCredentials: u32 = 0x0040;
    /** PIN codes over-the-air supported for lock/unlock operations */
    pub const CredentialOverTheAirAccess: u32 = 0x0080;
    /** Lock supports the user commands and database */
    pub const User: u32 = 0x0100;
    /** Lock supports year day user access schedules */
    pub const YearDayAccessSchedules: u32 = 0x0400;
    /** Lock supports holiday schedules */
    pub const HolidaySchedules: u32 = 0x0800;
    /** Lock supports unbolting */
    pub const Unbolting: u32 = 0x1000;
    /** Lock supports Aliro credential provisioning as defined in Aliro */
    pub const AliroProvisioning: u32 = 0x2000;
    /** Lock supports the Bluetooth LE + UWB Access Control Flow as defined in Aliro */
    pub const AliroBLEUWB: u32 = 0x4000;
}
/** The WebRTC transport provider cluster provides a way for stream providers (e.g. Cameras) to stream or receive their data through WebRTC. */
pub mod WebRTCTransportProvider {
    /** Supports metadata transmission in WebRTC sessions */
    pub const Metadata: u32 = 0x0001;
}
/** Manage the Thread network of Thread Border Router */
pub mod ThreadBorderRouterManagement {
    /** The ability to change PAN configuration with pending dataset setting request. */
    pub const PANChange: u32 = 0x0001;
}
/** The Camera AV Stream Management cluster is used to allow clients to manage, control, and configure various audio, video, and snapshot streams on a camera. */
pub mod CameraAVStreamManagement {
    /** Audio Streams supported */
    pub const Audio: u32 = 0x0001;
    /** Video Streams supported */
    pub const Video: u32 = 0x0002;
    /** Snapshot Streams supported */
    pub const Snapshot: u32 = 0x0004;
    /** Privacy supported */
    pub const Privacy: u32 = 0x0008;
    /** Speaker supported */
    pub const Speaker: u32 = 0x0010;
    /** Image control supported */
    pub const ImageControl: u32 = 0x0020;
    /** Watermark supported */
    pub const Watermark: u32 = 0x0040;
    /** OSD supported */
    pub const OnScreenDisplay: u32 = 0x0080;
    /** Local Storage available */
    pub const LocalStorage: u32 = 0x0100;
    /** High Dynamic Range supported */
    pub const HighDynamicRange: u32 = 0x0200;
    /** Night Vision mode supported */
    pub const NightVision: u32 = 0x0400;
}
/** This cluster supports remotely monitoring and controlling the different types of functionality available to a washing device, such as a washing machine. */
pub mod LaundryWasherControls {
    /** Multiple spin speeds supported */
    pub const Spin: u32 = 0x0001;
    /** Multiple rinse cycles supported */
    pub const Rinse: u32 = 0x0002;
}
/** This cluster provides an interface for controlling a device like a TV using action commands such as UP, DOWN, and SELECT. */
pub mod KeypadInput {
    /** Supports UP, DOWN, LEFT, RIGHT, SELECT, BACK, EXIT, MENU */
    pub const NavigationKeyCodes: u32 = 0x0001;
    /** Supports CEC keys 0x0A (Settings) and 0x09 (Home) */
    pub const LocationKeys: u32 = 0x0002;
    /** Supports numeric input 0..9 */
    pub const NumberKeys: u32 = 0x0004;
}
/** Attributes and commands for group configuration and manipulation. */
pub mod Groups {
    /** The ability to store a name for a group. */
    pub const GroupNames: u32 = 0x0001;
}
/** This cluster provides an interface to reflect and control a closure's range of movement, usually involving a panel, by using 6-axis framework. */
pub mod ClosureDimension {
    /** Supports Positioning in the range from 0.00% to 100.00% */
    pub const Positioning: u32 = 0x0001;
    /** Supports a latch to secure the closure to a position or state */
    pub const MotionLatching: u32 = 0x0002;
    /** Specifies the relevant unit and range for this dimension (mm, degrees etc.) */
    pub const Unit: u32 = 0x0004;
    /** Supports limitation of the operating range */
    pub const Limitation: u32 = 0x0008;
    /** Supports speed motion throttling. */
    pub const Speed: u32 = 0x0010;
    /** Drives a translation motion */
    pub const Translation: u32 = 0x0020;
    /** Drives a rotation motion */
    pub const Rotation: u32 = 0x0040;
    /** Modulates a particular flow level (light, air, privacy ...) */
    pub const Modulation: u32 = 0x0080;
}
/** Attributes and commands for configuring the Refrigerator alarm. */
pub mod RefrigeratorAlarm {
    /** Supports the ability to reset alarms */
    pub const Reset: u32 = 0x0001;
}
/** This cluster provides an interface for controlling the Input Selector on a media device such as a TV. */
pub mod MediaInput {
    /** Supports updates to the input names */
    pub const NameUpdates: u32 = 0x0001;
}
/** The server cluster provides an interface to occupancy sensing functionality based on one or more sensing modalities, including configuration and provision of notifications of occupancy status. */
pub mod OccupancySensing {
    /** Supports sensing using a modality not listed in the other bits */
    pub const Other: u32 = 0x0001;
    /** Supports sensing using PIR (Passive InfraRed) */
    pub const PassiveInfrared: u32 = 0x0002;
    /** Supports sensing using UltraSound */
    pub const Ultrasonic: u32 = 0x0004;
    /** Supports sensing using a physical contact */
    pub const PhysicalContact: u32 = 0x0008;
    /** Supports sensing using Active InfraRed measurement (e.g. time-of-flight or transflective/reflective IR sensing) */
    pub const ActiveInfrared: u32 = 0x0010;
    /** Supports sensing using radar waves (microwave) */
    pub const Radar: u32 = 0x0020;
    /** Supports sensing using analysis of radio signals, e.g.: RSSI, CSI and/or any other metric from the signal */
    pub const RFSensing: u32 = 0x0040;
    /** Supports sensing based on analyzing images */
    pub const Vision: u32 = 0x0080;
}
/** The CommodityTariffCluster provides the mechanism for communicating Commodity Tariff information within the premises. */
pub mod CommodityTariff {
    /** Supports information about commodity pricing */
    pub const Pricing: u32 = 0x0001;
    /** Supports information about when friendly credit periods begin and end */
    pub const FriendlyCredit: u32 = 0x0002;
    /** Supports information about when auxiliary loads should be enabled or disabled */
    pub const AuxiliaryLoad: u32 = 0x0004;
    /** Supports information about peak periods */
    pub const PeakPeriod: u32 = 0x0008;
    /** Supports information about power threshold */
    pub const PowerThreshold: u32 = 0x0010;
    /** Supports information about randomization of calendar day entries */
    pub const Randomization: u32 = 0x0020;
}
/** Attributes and commands for configuring the measurement of pressure, and reporting pressure measurements. */
pub mod PressureMeasurement {
    /** Extended range and resolution */
    pub const Extended: u32 = 0x0001;
}
/** An interface for configuring and controlling the functionality of a thermostat. */
pub mod Thermostat {
    /** Thermostat is capable of managing a heating device */
    pub const Heating: u32 = 0x0001;
    /** Thermostat is capable of managing a cooling device */
    pub const Cooling: u32 = 0x0002;
    /** Supports Occupied and Unoccupied setpoints */
    pub const Occupancy: u32 = 0x0004;
    pub const Setback: u32 = 0x0010;
    /** Supports a System Mode of Auto */
    pub const AutoMode: u32 = 0x0020;
    /** Thermostat does not expose the LocalTemperature Value in the LocalTemperature attribute */
    pub const LocalTemperatureNotExposed: u32 = 0x0040;
    /** Supports enhanced schedules */
    pub const MatterScheduleConfiguration: u32 = 0x0080;
    /** Thermostat supports setpoint presets */
    pub const Presets: u32 = 0x0100;
}
/** This cluster provides an interface for controlling the current Channel on a device. */
pub mod Channel {
    /** Provides list of available channels. */
    pub const ChannelList: u32 = 0x0001;
    /** Provides lineup info, which is a reference to an external source of lineup information. */
    pub const LineupInfo: u32 = 0x0002;
    /** Provides electronic program guide information. */
    pub const ElectronicGuide: u32 = 0x0004;
    /** Provides ability to record program. */
    pub const RecordProgram: u32 = 0x0008;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod OvenMode {
    /** Dependency with the OnOff cluster */
    pub const OnOff: u32 = 0x0001;
}
/** This cluster allows a client to manage the power draw of a device. An example of such a client could be an Energy Management System (EMS) which controls an Energy Smart Appliance (ESA). */
pub mod DeviceEnergyManagement {
    /** Allows an EMS to make a temporary power adjustment (within the limits offered by the ESA). */
    pub const PowerAdjustment: u32 = 0x0001;
    /** Allows an ESA to advertise its indicative future power consumption vs time. */
    pub const PowerForecastReporting: u32 = 0x0002;
    /** Allows an ESA to advertise its indicative future state vs time. */
    pub const StateForecastReporting: u32 = 0x0004;
    /** Allows an EMS to delay an ESA's planned operation. */
    pub const StartTimeAdjustment: u32 = 0x0008;
    /** Allows an EMS to pause an ESA's planned operation. */
    pub const Pausable: u32 = 0x0010;
    /** Allows an EMS to adjust an ESA's planned operation. */
    pub const ForecastAdjustment: u32 = 0x0020;
    /** Allows an EMS to request constraints to an ESA's planned operation. */
    pub const ConstraintBasedAdjustment: u32 = 0x0040;
}
/** Attributes and commands for configuring the temperature control, and reporting temperature. */
pub mod TemperatureControl {
    /** Use actual temperature numbers */
    pub const TemperatureNumber: u32 = 0x0001;
    /** Use temperature levels */
    pub const TemperatureLevel: u32 = 0x0002;
    /** Use step control with temperature numbers */
    pub const TemperatureStep: u32 = 0x0004;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod DeviceEnergyManagementMode {
    /** Dependency with the OnOff cluster */
    pub const OnOff: u32 = 0x0001;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod LaundryWasherMode {
    /** Dependency with the OnOff cluster */
    pub const OnOff: u32 = 0x0001;
}
/** This cluster is used to configure a valve. */
pub mod ValveConfigurationandControl {
    /** UTC time is used for time indications */
    pub const TimeSync: u32 = 0x0001;
    /** Device supports setting the specific position of the valve */
    pub const Level: u32 = 0x0002;
}
