libertas_matter_macros::matter_attributes! {
/** This cluster is used for managing the content control (including "parental control") settings on a media device such as a TV, or Set-top Box. */
pub mod ContentControl {
    pub const Enabled: u32 = 0x0000;
    pub const OnDemandRatings: u32 = 0x0001;
    pub const OnDemandRatingThreshold: u32 = 0x0002;
    pub const ScheduledContentRatings: u32 = 0x0003;
    pub const ScheduledContentRatingThreshold: u32 = 0x0004;
    pub const ScreenDailyTime: u32 = 0x0005;
    pub const RemainingScreenTime: u32 = 0x0006;
    pub const BlockUnrated: u32 = 0x0007;
    pub const BlockChannelList: u32 = 0x0008;
    pub const BlockApplicationList: u32 = 0x0009;
    pub const BlockContentTimeWindow: u32 = 0x000A;
}
/** Attributes and commands for configuring the microwave oven control, and reporting cooking stats. */
pub mod MicrowaveOvenControl {
    pub const CookTime: u32 = 0x0000;
    pub const MaxCookTime: u32 = 0x0001;
    pub const PowerSetting: u32 = 0x0002;
    pub const MinPower: u32 = 0x0003;
    pub const MaxPower: u32 = 0x0004;
    pub const PowerStep: u32 = 0x0005;
    pub const SupportedWatts: u32 = 0x0006;
    pub const SelectedWattIndex: u32 = 0x0007;
    pub const WattRating: u32 = 0x0008;
}
/** This cluster exposes interactions with a switch device, for the purpose of using those interactions by other devices.
 * Two types of switch devices are supported: latching switch (e.g. rocker switch) and momentary switch (e.g. push button), distinguished with their feature flags.
 * Interactions with the switch device are exposed as attributes (for the latching switch) and as events (for both types of switches). An interested party MAY subscribe to these attributes/events and thus be informed of the interactions, and can perform actions based on this, for example by sending commands to perform an action such as controlling a light or a window shade. */
pub mod Switch {
    pub const NumberOfPositions: u32 = 0x0000;
    pub const CurrentPosition: u32 = 0x0001;
    pub const MultiPressMax: u32 = 0x0002;
}
/** The User Label Cluster provides a feature to tag an endpoint with zero or more labels. */
pub mod UserLabel {
    pub const LabelList: u32 = 0x0000;
}
/** This cluster is used to allow clients to control the operation of a hot water heating appliance so that it can be used with energy management. */
pub mod WaterHeaterManagement {
    pub const HeaterTypes: u32 = 0x0000;
    pub const HeatDemand: u32 = 0x0001;
    pub const TankVolume: u32 = 0x0002;
    pub const EstimatedHeatRequired: u32 = 0x0003;
    pub const TankPercentage: u32 = 0x0004;
    pub const BoostState: u32 = 0x0005;
}
/** The Ethernet Network Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub mod EthernetNetworkDiagnostics {
    pub const PHYRate: u32 = 0x0000;
    pub const FullDuplex: u32 = 0x0001;
    pub const PacketRxCount: u32 = 0x0002;
    pub const PacketTxCount: u32 = 0x0003;
    pub const TxErrCount: u32 = 0x0004;
    pub const CollisionCount: u32 = 0x0005;
    pub const OverrunCount: u32 = 0x0006;
    pub const CarrierDetect: u32 = 0x0007;
    pub const TimeSinceReset: u32 = 0x0008;
}
/** This cluster provides an interface for launching content on a media player device such as a TV or Speaker. */
pub mod ContentLauncher {
    pub const AcceptHeader: u32 = 0x0000;
    pub const SupportedStreamingProtocols: u32 = 0x0001;
}
/** The General Diagnostics Cluster, along with other diagnostics clusters, provide a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub mod GeneralDiagnostics {
    pub const NetworkInterfaces: u32 = 0x0000;
    pub const RebootCount: u32 = 0x0001;
    pub const UpTime: u32 = 0x0002;
    pub const TotalOperationalHours: u32 = 0x0003;
    pub const BootReason: u32 = 0x0004;
    pub const ActiveHardwareFaults: u32 = 0x0005;
    pub const ActiveRadioFaults: u32 = 0x0006;
    pub const ActiveNetworkFaults: u32 = 0x0007;
    pub const TestEventTriggersEnabled: u32 = 0x0008;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod FormaldehydeConcentrationMeasurement {
    pub const MeasuredValue: u32 = 0x0000;
    pub const MinMeasuredValue: u32 = 0x0001;
    pub const MaxMeasuredValue: u32 = 0x0002;
    pub const PeakMeasuredValue: u32 = 0x0003;
    pub const PeakMeasuredValueWindow: u32 = 0x0004;
    pub const AverageMeasuredValue: u32 = 0x0005;
    pub const AverageMeasuredValueWindow: u32 = 0x0006;
    pub const Uncertainty: u32 = 0x0007;
    pub const MeasurementUnit: u32 = 0x0008;
    pub const MeasurementMedium: u32 = 0x0009;
    pub const LevelValue: u32 = 0x000A;
}
/** Allows servers to ensure that listed clients are notified when a server is available for communication. */
pub mod ICDManagement {
    pub const IdleModeDuration: u32 = 0x0000;
    pub const ActiveModeDuration: u32 = 0x0001;
    pub const ActiveModeThreshold: u32 = 0x0002;
    pub const RegisteredClients: u32 = 0x0003;
    pub const ICDCounter: u32 = 0x0004;
    pub const ClientsSupportedPerFabric: u32 = 0x0005;
    pub const UserActiveModeTriggerHint: u32 = 0x0006;
    pub const UserActiveModeTriggerInstruction: u32 = 0x0007;
    pub const OperatingMode: u32 = 0x0008;
    pub const MaximumCheckInBackoff: u32 = 0x0009;
}
/** Functionality to configure, enable, disable network credentials and access on a Matter device. */
pub mod NetworkCommissioning {
    pub const MaxNetworks: u32 = 0x0000;
    pub const Networks: u32 = 0x0001;
    pub const ScanMaxTimeSeconds: u32 = 0x0002;
    pub const ConnectMaxTimeSeconds: u32 = 0x0003;
    pub const InterfaceEnabled: u32 = 0x0004;
    pub const LastNetworkingStatus: u32 = 0x0005;
    pub const LastNetworkID: u32 = 0x0006;
    pub const LastConnectErrorValue: u32 = 0x0007;
    pub const SupportedWiFiBands: u32 = 0x0008;
    pub const SupportedThreadFeatures: u32 = 0x0009;
    pub const ThreadVersion: u32 = 0x000A;
}
/** Accurate time is required for a number of reasons, including scheduling, display and validating security materials. */
pub mod TimeSynchronization {
    pub const UTCTime: u32 = 0x0000;
    pub const Granularity: u32 = 0x0001;
    pub const TimeSource: u32 = 0x0002;
    pub const TrustedTimeSource: u32 = 0x0003;
    pub const DefaultNTP: u32 = 0x0004;
    pub const TimeZone: u32 = 0x0005;
    pub const DSTOffset: u32 = 0x0006;
    pub const LocalTime: u32 = 0x0007;
    pub const TimeZoneDatabase: u32 = 0x0008;
    pub const NTPServerAvailable: u32 = 0x0009;
    pub const TimeZoneListMaxSize: u32 = 0x000A;
    pub const DSTOffsetListMaxSize: u32 = 0x000B;
    pub const SupportsDNSResolve: u32 = 0x000C;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod RVCRunMode {
    pub const SupportedModes: u32 = 0x0000;
    pub const CurrentMode: u32 = 0x0001;
    pub const StartUpMode: u32 = 0x0002;
    pub const OnMode: u32 = 0x0003;
}
/** This cluster provides an interface to a boolean state called StateValue. */
pub mod BooleanState {
    pub const StateValue: u32 = 0x0000;
}
/** The Commodity Price Cluster provides the mechanism for communicating Gas, Energy, or Water pricing information within the premises. */
pub mod CommodityPrice {
    pub const TariffUnit: u32 = 0x0000;
    pub const Currency: u32 = 0x0001;
    pub const CurrentPrice: u32 = 0x0002;
    pub const PriceForecast: u32 = 0x0003;
}
/** This cluster provides an interface for launching content on a media player device such as a TV or Speaker. */
pub mod ApplicationLauncher {
    pub const CatalogList: u32 = 0x0000;
    pub const CurrentApp: u32 = 0x0001;
}
/** The Thread Network Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems */
pub mod ThreadNetworkDiagnostics {
    pub const Channel: u32 = 0x0000;
    pub const RoutingRole: u32 = 0x0001;
    pub const NetworkName: u32 = 0x0002;
    pub const PanId: u32 = 0x0003;
    pub const ExtendedPanId: u32 = 0x0004;
    pub const MeshLocalPrefix: u32 = 0x0005;
    pub const OverrunCount: u32 = 0x0006;
    pub const NeighborTable: u32 = 0x0007;
    pub const RouteTable: u32 = 0x0008;
    pub const PartitionId: u32 = 0x0009;
    pub const Weighting: u32 = 0x000A;
    pub const DataVersion: u32 = 0x000B;
    pub const StableDataVersion: u32 = 0x000C;
    pub const LeaderRouterId: u32 = 0x000D;
    pub const DetachedRoleCount: u32 = 0x000E;
    pub const ChildRoleCount: u32 = 0x000F;
    pub const RouterRoleCount: u32 = 0x0010;
    pub const LeaderRoleCount: u32 = 0x0011;
    pub const AttachAttemptCount: u32 = 0x0012;
    pub const PartitionIdChangeCount: u32 = 0x0013;
    pub const BetterPartitionAttachAttemptCount: u32 = 0x0014;
    pub const ParentChangeCount: u32 = 0x0015;
    pub const TxTotalCount: u32 = 0x0016;
    pub const TxUnicastCount: u32 = 0x0017;
    pub const TxBroadcastCount: u32 = 0x0018;
    pub const TxAckRequestedCount: u32 = 0x0019;
    pub const TxAckedCount: u32 = 0x001A;
    pub const TxNoAckRequestedCount: u32 = 0x001B;
    pub const TxDataCount: u32 = 0x001C;
    pub const TxDataPollCount: u32 = 0x001D;
    pub const TxBeaconCount: u32 = 0x001E;
    pub const TxBeaconRequestCount: u32 = 0x001F;
    pub const TxOtherCount: u32 = 0x0020;
    pub const TxRetryCount: u32 = 0x0021;
    pub const TxDirectMaxRetryExpiryCount: u32 = 0x0022;
    pub const TxIndirectMaxRetryExpiryCount: u32 = 0x0023;
    pub const TxErrCcaCount: u32 = 0x0024;
    pub const TxErrAbortCount: u32 = 0x0025;
    pub const TxErrBusyChannelCount: u32 = 0x0026;
    pub const RxTotalCount: u32 = 0x0027;
    pub const RxUnicastCount: u32 = 0x0028;
    pub const RxBroadcastCount: u32 = 0x0029;
    pub const RxDataCount: u32 = 0x002A;
    pub const RxDataPollCount: u32 = 0x002B;
    pub const RxBeaconCount: u32 = 0x002C;
    pub const RxBeaconRequestCount: u32 = 0x002D;
    pub const RxOtherCount: u32 = 0x002E;
    pub const RxAddressFilteredCount: u32 = 0x002F;
    pub const RxDestAddrFilteredCount: u32 = 0x0030;
    pub const RxDuplicatedCount: u32 = 0x0031;
    pub const RxErrNoFrameCount: u32 = 0x0032;
    pub const RxErrUnknownNeighborCount: u32 = 0x0033;
    pub const RxErrInvalidSrcAddrCount: u32 = 0x0034;
    pub const RxErrSecCount: u32 = 0x0035;
    pub const RxErrFcsCount: u32 = 0x0036;
    pub const RxErrOtherCount: u32 = 0x0037;
    pub const ActiveTimestamp: u32 = 0x0038;
    pub const PendingTimestamp: u32 = 0x0039;
    pub const Delay: u32 = 0x003A;
    pub const SecurityPolicy: u32 = 0x003B;
    pub const ChannelPage0Mask: u32 = 0x003C;
    pub const OperationalDatasetComponents: u32 = 0x003D;
    pub const ActiveNetworkFaultsList: u32 = 0x003E;
    pub const ExtAddress: u32 = 0x003F;
    pub const Rloc16: u32 = 0x0040;
}
/** This cluster provides a standardized way for a Node (typically a Bridge, but could be any Node) to expose action information. */
pub mod Actions {
    pub const ActionList: u32 = 0x0000;
    pub const EndpointLists: u32 = 0x0001;
    pub const SetupURL: u32 = 0x0002;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod PM25ConcentrationMeasurement {
    pub const MeasuredValue: u32 = 0x0000;
    pub const MinMeasuredValue: u32 = 0x0001;
    pub const MaxMeasuredValue: u32 = 0x0002;
    pub const PeakMeasuredValue: u32 = 0x0003;
    pub const PeakMeasuredValueWindow: u32 = 0x0004;
    pub const AverageMeasuredValue: u32 = 0x0005;
    pub const AverageMeasuredValueWindow: u32 = 0x0006;
    pub const Uncertainty: u32 = 0x0007;
    pub const MeasurementUnit: u32 = 0x0008;
    pub const MeasurementMedium: u32 = 0x0009;
    pub const LevelValue: u32 = 0x000A;
}
/** The Group Key Management Cluster is the mechanism by which group keys are managed. */
pub mod GroupKeyManagement {
    pub const GroupKeyMap: u32 = 0x0000;
    pub const GroupTable: u32 = 0x0001;
    pub const MaxGroupsPerFabric: u32 = 0x0002;
    pub const MaxGroupKeysPerFabric: u32 = 0x0003;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod CarbonMonoxideConcentrationMeasurement {
    pub const MeasuredValue: u32 = 0x0000;
    pub const MinMeasuredValue: u32 = 0x0001;
    pub const MaxMeasuredValue: u32 = 0x0002;
    pub const PeakMeasuredValue: u32 = 0x0003;
    pub const PeakMeasuredValueWindow: u32 = 0x0004;
    pub const AverageMeasuredValue: u32 = 0x0005;
    pub const AverageMeasuredValueWindow: u32 = 0x0006;
    pub const Uncertainty: u32 = 0x0007;
    pub const MeasurementUnit: u32 = 0x0008;
    pub const MeasurementMedium: u32 = 0x0009;
    pub const LevelValue: u32 = 0x000A;
}
/** This cluster provides information about an application running on a TV or media player device which is represented as an endpoint. */
pub mod ApplicationBasic {
    pub const VendorName: u32 = 0x0000;
    pub const VendorID: u32 = 0x0001;
    pub const ApplicationName: u32 = 0x0002;
    pub const ProductID: u32 = 0x0003;
    pub const Application: u32 = 0x0004;
    pub const Status: u32 = 0x0005;
    pub const ApplicationVersion: u32 = 0x0006;
    pub const AllowedVendorList: u32 = 0x0007;
}
/** Attributes and commands for controlling devices that can be set to a level between fully 'On' and fully 'Off.' */
pub mod LevelControl {
    pub const CurrentLevel: u32 = 0x0000;
    pub const RemainingTime: u32 = 0x0001;
    pub const MinLevel: u32 = 0x0002;
    pub const MaxLevel: u32 = 0x0003;
    pub const CurrentFrequency: u32 = 0x0004;
    pub const MinFrequency: u32 = 0x0005;
    pub const MaxFrequency: u32 = 0x0006;
    pub const Options: u32 = 0x000F;
    pub const OnOffTransitionTime: u32 = 0x0010;
    pub const OnLevel: u32 = 0x0011;
    pub const OnTransitionTime: u32 = 0x0012;
    pub const OffTransitionTime: u32 = 0x0013;
    pub const DefaultMoveRate: u32 = 0x0014;
    pub const StartUpCurrentLevel: u32 = 0x4000;
}
/** Electric Vehicle Supply Equipment (EVSE) is equipment used to charge an Electric Vehicle (EV) or Plug-In Hybrid Electric Vehicle. This cluster provides an interface to the functionality of Electric Vehicle Supply Equipment (EVSE) management. */
pub mod EnergyEVSE {
    pub const State: u32 = 0x0000;
    pub const SupplyState: u32 = 0x0001;
    pub const FaultState: u32 = 0x0002;
    pub const ChargingEnabledUntil: u32 = 0x0003;
    pub const DischargingEnabledUntil: u32 = 0x0004;
    pub const CircuitCapacity: u32 = 0x0005;
    pub const MinimumChargeCurrent: u32 = 0x0006;
    pub const MaximumChargeCurrent: u32 = 0x0007;
    pub const MaximumDischargeCurrent: u32 = 0x0008;
    pub const UserMaximumChargeCurrent: u32 = 0x0009;
    pub const RandomizationDelayWindow: u32 = 0x000A;
    pub const NextChargeStartTime: u32 = 0x0023;
    pub const NextChargeTargetTime: u32 = 0x0024;
    pub const NextChargeRequiredEnergy: u32 = 0x0025;
    pub const NextChargeTargetSoC: u32 = 0x0026;
    pub const ApproximateEVEfficiency: u32 = 0x0027;
    pub const StateOfCharge: u32 = 0x0030;
    pub const BatteryCapacity: u32 = 0x0031;
    pub const VehicleID: u32 = 0x0032;
    pub const SessionID: u32 = 0x0040;
    pub const SessionDuration: u32 = 0x0041;
    pub const SessionEnergyCharged: u32 = 0x0042;
    pub const SessionEnergyDischarged: u32 = 0x0043;
}
/** This Cluster serves two purposes towards a Node communicating with a Bridge: indicate that the functionality on
 * the Endpoint where it is placed (and its Parts) is bridged from a non-CHIP technology; and provide a centralized
 * collection of attributes that the Node MAY collect to aid in conveying information regarding the Bridged Device to a user,
 * such as the vendor name, the model name, or user-assigned name. */
pub mod BridgedDeviceBasicInformation {
    pub const DataModelRevision: u32 = 0x0000;
    pub const VendorName: u32 = 0x0001;
    pub const VendorID: u32 = 0x0002;
    pub const ProductName: u32 = 0x0003;
    pub const ProductID: u32 = 0x0004;
    pub const NodeLabel: u32 = 0x0005;
    pub const Location: u32 = 0x0006;
    pub const HardwareVersion: u32 = 0x0007;
    pub const HardwareVersionString: u32 = 0x0008;
    pub const SoftwareVersion: u32 = 0x0009;
    pub const SoftwareVersionString: u32 = 0x000A;
    pub const ManufacturingDate: u32 = 0x000B;
    pub const PartNumber: u32 = 0x000C;
    pub const ProductURL: u32 = 0x000D;
    pub const ProductLabel: u32 = 0x000E;
    pub const SerialNumber: u32 = 0x000F;
    pub const LocalConfigDisabled: u32 = 0x0010;
    pub const Reachable: u32 = 0x0011;
    pub const UniqueID: u32 = 0x0012;
    pub const CapabilityMinima: u32 = 0x0013;
    pub const ProductAppearance: u32 = 0x0014;
    pub const SpecificationVersion: u32 = 0x0015;
    pub const MaxPathsPerInvoke: u32 = 0x0016;
    pub const ConfigurationVersion: u32 = 0x0018;
}
/** The Software Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub mod SoftwareDiagnostics {
    pub const ThreadMetrics: u32 = 0x0000;
    pub const CurrentHeapFree: u32 = 0x0001;
    pub const CurrentHeapUsed: u32 = 0x0002;
    pub const CurrentHeapHighWatermark: u32 = 0x0003;
}
/** This cluster is used to describe the configuration and capabilities of a Device's power system. */
pub mod PowerSourceConfiguration {
    pub const Sources: u32 = 0x0000;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod DishwasherMode {
    pub const SupportedModes: u32 = 0x0000;
    pub const CurrentMode: u32 = 0x0001;
    pub const StartUpMode: u32 = 0x0002;
    pub const OnMode: u32 = 0x0003;
}
/** Commands to trigger a Node to allow a new Administrator to commission it. */
pub mod AdministratorCommissioning {
    pub const WindowStatus: u32 = 0x0000;
    pub const AdminFabricIndex: u32 = 0x0001;
    pub const AdminVendorId: u32 = 0x0002;
}
/** This cluster provides an interface to manage regions of interest, or Zones, which can be either manufacturer or user defined. */
pub mod ZoneManagement {
    pub const MaxUserDefinedZones: u32 = 0x0000;
    pub const MaxZones: u32 = 0x0001;
    pub const Zones: u32 = 0x0002;
    pub const Triggers: u32 = 0x0003;
    pub const SensitivityMax: u32 = 0x0004;
    pub const Sensitivity: u32 = 0x0005;
    pub const TwoDCartesianMax: u32 = 0x0006;
}
/** The Joint Fabric Datastore Cluster is a cluster that provides a mechanism for the Joint Fabric Administrators to manage the set of Nodes, Groups, and Group membership among Nodes in the Joint Fabric. */
pub mod JointFabricDatastore {
    pub const AnchorRootCA: u32 = 0x0000;
    pub const AnchorNodeID: u32 = 0x0001;
    pub const AnchorVendorID: u32 = 0x0002;
    pub const FriendlyName: u32 = 0x0003;
    pub const GroupKeySetList: u32 = 0x0004;
    pub const GroupList: u32 = 0x0005;
    pub const NodeList: u32 = 0x0006;
    pub const AdminList: u32 = 0x0007;
    pub const Status: u32 = 0x0008;
    pub const EndpointGroupIDList: u32 = 0x0009;
    pub const EndpointBindingList: u32 = 0x000A;
    pub const NodeKeySetList: u32 = 0x000B;
    pub const NodeACLList: u32 = 0x000C;
    pub const NodeEndpointList: u32 = 0x000D;
}
/** This cluster supports remotely monitoring and, where supported, changing the operational state of any device where a state machine is a part of the operation. */
pub mod OperationalState {
    pub const PhaseList: u32 = 0x0000;
    pub const CurrentPhase: u32 = 0x0001;
    pub const CountdownTime: u32 = 0x0002;
    pub const OperationalStateList: u32 = 0x0003;
    pub const OperationalState: u32 = 0x0004;
    pub const OperationalError: u32 = 0x0005;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod MicrowaveOvenMode {
    pub const SupportedModes: u32 = 0x0000;
    pub const CurrentMode: u32 = 0x0001;
    pub const StartUpMode: u32 = 0x0002;
    pub const OnMode: u32 = 0x0003;
}
/** This cluster provides a way to access options associated with the operation of
 * a laundry dryer device type. */
pub mod LaundryDryerControls {
    pub const SupportedDrynessLevels: u32 = 0x0000;
    pub const SelectedDrynessLevel: u32 = 0x0001;
}
/** Supports the ability for clients to request the commissioning of themselves or other nodes onto a fabric which the cluster server can commission onto. */
pub mod CommissionerControl {
    pub const SupportedDeviceCategories: u32 = 0x0000;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod ModeSelect {
    pub const Description: u32 = 0x0000;
    pub const StandardNamespace: u32 = 0x0001;
    pub const SupportedModes: u32 = 0x0002;
    pub const CurrentMode: u32 = 0x0003;
    pub const StartUpMode: u32 = 0x0004;
    pub const OnMode: u32 = 0x0005;
}
/** This cluster implements the upload of Audio and Video streams from the Push AV Stream Transport Cluster using suitable push-based transports. */
pub mod PushAVStreamTransport {
    pub const SupportedFormats: u32 = 0x0000;
    pub const CurrentConnections: u32 = 0x0001;
}
/** This cluster provides an interface to soil measurement functionality, including configuration and provision of notifications of soil measurements. */
pub mod SoilMeasurement {
    pub const SoilMoistureMeasurementLimits: u32 = 0x0000;
    pub const SoilMoistureMeasuredValue: u32 = 0x0001;
}
/** Nodes should be expected to be deployed to any and all regions of the world. These global regions
 * may have differing preferences for how dates and times are conveyed. As such, Nodes that visually
 * or audibly convey time information need a mechanism by which they can be configured to use a
 * user’s preferred format. */
pub mod TimeFormatLocalization {
    pub const HourFormat: u32 = 0x0000;
    pub const ActiveCalendarType: u32 = 0x0001;
    pub const SupportedCalendarTypes: u32 = 0x0002;
}
/** This cluster provides an interface for controlling the Output on a media device such as a TV. */
pub mod AudioOutput {
    pub const OutputList: u32 = 0x0000;
    pub const CurrentOutput: u32 = 0x0001;
}
/** Attributes and commands for switching devices between 'On' and 'Off' states. */
pub mod OnOff {
    pub const OnOff: u32 = 0x0000;
    pub const GlobalSceneControl: u32 = 0x4000;
    pub const OnTime: u32 = 0x4001;
    pub const OffWaitTime: u32 = 0x4002;
    pub const StartUpOnOff: u32 = 0x4003;
}
/** Attributes and commands for controlling the color properties of a color-capable light. */
pub mod ColorControl {
    pub const CurrentHue: u32 = 0x0000;
    pub const CurrentSaturation: u32 = 0x0001;
    pub const RemainingTime: u32 = 0x0002;
    pub const CurrentX: u32 = 0x0003;
    pub const CurrentY: u32 = 0x0004;
    pub const DriftCompensation: u32 = 0x0005;
    pub const CompensationText: u32 = 0x0006;
    pub const ColorTemperatureMireds: u32 = 0x0007;
    pub const ColorMode: u32 = 0x0008;
    pub const Options: u32 = 0x000F;
    pub const NumberOfPrimaries: u32 = 0x0010;
    pub const Primary1X: u32 = 0x0011;
    pub const Primary1Y: u32 = 0x0012;
    pub const Primary1Intensity: u32 = 0x0013;
    pub const Primary2X: u32 = 0x0015;
    pub const Primary2Y: u32 = 0x0016;
    pub const Primary2Intensity: u32 = 0x0017;
    pub const Primary3X: u32 = 0x0019;
    pub const Primary3Y: u32 = 0x001A;
    pub const Primary3Intensity: u32 = 0x001B;
    pub const Primary4X: u32 = 0x0020;
    pub const Primary4Y: u32 = 0x0021;
    pub const Primary4Intensity: u32 = 0x0022;
    pub const Primary5X: u32 = 0x0024;
    pub const Primary5Y: u32 = 0x0025;
    pub const Primary5Intensity: u32 = 0x0026;
    pub const Primary6X: u32 = 0x0028;
    pub const Primary6Y: u32 = 0x0029;
    pub const Primary6Intensity: u32 = 0x002A;
    pub const WhitePointX: u32 = 0x0030;
    pub const WhitePointY: u32 = 0x0031;
    pub const ColorPointRX: u32 = 0x0032;
    pub const ColorPointRY: u32 = 0x0033;
    pub const ColorPointRIntensity: u32 = 0x0034;
    pub const ColorPointGX: u32 = 0x0036;
    pub const ColorPointGY: u32 = 0x0037;
    pub const ColorPointGIntensity: u32 = 0x0038;
    pub const ColorPointBX: u32 = 0x003A;
    pub const ColorPointBY: u32 = 0x003B;
    pub const ColorPointBIntensity: u32 = 0x003C;
    pub const EnhancedCurrentHue: u32 = 0x4000;
    pub const EnhancedColorMode: u32 = 0x4001;
    pub const ColorLoopActive: u32 = 0x4002;
    pub const ColorLoopDirection: u32 = 0x4003;
    pub const ColorLoopTime: u32 = 0x4004;
    pub const ColorLoopStartEnhancedHue: u32 = 0x4005;
    pub const ColorLoopStoredEnhancedHue: u32 = 0x4006;
    pub const ColorCapabilities: u32 = 0x400A;
    pub const ColorTempPhysicalMinMireds: u32 = 0x400B;
    pub const ColorTempPhysicalMaxMireds: u32 = 0x400C;
    pub const CoupleColorTempToLevelMinMireds: u32 = 0x400D;
    pub const StartUpColorTemperatureMireds: u32 = 0x4010;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod PM10ConcentrationMeasurement {
    pub const MeasuredValue: u32 = 0x0000;
    pub const MinMeasuredValue: u32 = 0x0001;
    pub const MaxMeasuredValue: u32 = 0x0002;
    pub const PeakMeasuredValue: u32 = 0x0003;
    pub const PeakMeasuredValueWindow: u32 = 0x0004;
    pub const AverageMeasuredValue: u32 = 0x0005;
    pub const AverageMeasuredValueWindow: u32 = 0x0006;
    pub const Uncertainty: u32 = 0x0007;
    pub const MeasurementUnit: u32 = 0x0008;
    pub const MeasurementMedium: u32 = 0x0009;
    pub const LevelValue: u32 = 0x000A;
}
/** Attributes and commands for configuring the Dishwasher alarm. */
pub mod DishwasherAlarm {
    pub const Mask: u32 = 0x0000;
    pub const Latch: u32 = 0x0001;
    pub const State: u32 = 0x0002;
    pub const Supported: u32 = 0x0003;
}
/** This cluster provides an interface for observing and managing the state of smoke and CO alarms. */
pub mod SmokeCOAlarm {
    pub const ExpressedState: u32 = 0x0000;
    pub const SmokeState: u32 = 0x0001;
    pub const COState: u32 = 0x0002;
    pub const BatteryAlert: u32 = 0x0003;
    pub const DeviceMuted: u32 = 0x0004;
    pub const TestInProgress: u32 = 0x0005;
    pub const HardwareFaultAlert: u32 = 0x0006;
    pub const EndOfServiceAlert: u32 = 0x0007;
    pub const InterconnectSmokeAlarm: u32 = 0x0008;
    pub const InterconnectCOAlarm: u32 = 0x0009;
    pub const ContaminationState: u32 = 0x000A;
    pub const SmokeSensitivityLevel: u32 = 0x000B;
    pub const ExpiryDate: u32 = 0x000C;
}
/** Functionality to retrieve operational information about a managed Wi-Fi network. */
pub mod WiFiNetworkManagement {
    pub const SSID: u32 = 0x0000;
    pub const PassphraseSurrogate: u32 = 0x0001;
}
/** This cluster provides an interface into controls associated with the operation of a device that provides pan, tilt, and zoom functions, either mechanically, or against a digital image. */
pub mod CameraAVSettingsUserLevelManagement {
    pub const MPTZPosition: u32 = 0x0000;
    pub const MaxPresets: u32 = 0x0001;
    pub const MPTZPresets: u32 = 0x0002;
    pub const DPTZStreams: u32 = 0x0003;
    pub const ZoomMax: u32 = 0x0004;
    pub const TiltMin: u32 = 0x0005;
    pub const TiltMax: u32 = 0x0006;
    pub const PanMin: u32 = 0x0007;
    pub const PanMax: u32 = 0x0008;
    pub const MovementState: u32 = 0x0009;
}
/** This cluster provides an interface for passing messages to be presented by a device. */
pub mod Messages {
    pub const Messages: u32 = 0x0000;
    pub const ActiveMessageIDs: u32 = 0x0001;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod CarbonDioxideConcentrationMeasurement {
    pub const MeasuredValue: u32 = 0x0000;
    pub const MinMeasuredValue: u32 = 0x0001;
    pub const MaxMeasuredValue: u32 = 0x0002;
    pub const PeakMeasuredValue: u32 = 0x0003;
    pub const PeakMeasuredValueWindow: u32 = 0x0004;
    pub const AverageMeasuredValue: u32 = 0x0005;
    pub const AverageMeasuredValueWindow: u32 = 0x0006;
    pub const Uncertainty: u32 = 0x0007;
    pub const MeasurementUnit: u32 = 0x0008;
    pub const MeasurementMedium: u32 = 0x0009;
    pub const LevelValue: u32 = 0x000A;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod RVCCleanMode {
    pub const SupportedModes: u32 = 0x0000;
    pub const CurrentMode: u32 = 0x0001;
    pub const StartUpMode: u32 = 0x0002;
    pub const OnMode: u32 = 0x0003;
}
/** This cluster provides a mechanism for querying data about electrical power as measured by the server. */
pub mod ElectricalPowerMeasurement {
    pub const PowerMode: u32 = 0x0000;
    pub const NumberOfMeasurementTypes: u32 = 0x0001;
    pub const Accuracy: u32 = 0x0002;
    pub const Ranges: u32 = 0x0003;
    pub const Voltage: u32 = 0x0004;
    pub const ActiveCurrent: u32 = 0x0005;
    pub const ReactiveCurrent: u32 = 0x0006;
    pub const ApparentCurrent: u32 = 0x0007;
    pub const ActivePower: u32 = 0x0008;
    pub const ReactivePower: u32 = 0x0009;
    pub const ApparentPower: u32 = 0x000A;
    pub const RMSVoltage: u32 = 0x000B;
    pub const RMSCurrent: u32 = 0x000C;
    pub const RMSPower: u32 = 0x000D;
    pub const Frequency: u32 = 0x000E;
    pub const HarmonicCurrents: u32 = 0x000F;
    pub const HarmonicPhases: u32 = 0x0010;
    pub const PowerFactor: u32 = 0x0011;
    pub const NeutralCurrent: u32 = 0x0012;
}
/** The Fixed Label Cluster provides a feature for the device to tag an endpoint with zero or more read only
 * labels. */
pub mod FixedLabel {
    pub const LabelList: u32 = 0x0000;
}
/** Nodes should be expected to be deployed to any and all regions of the world. These global regions
 * may have differing preferences for the units in which values are conveyed in communication to a
 * user. As such, Nodes that visually or audibly convey measurable values to the user need a
 * mechanism by which they can be configured to use a user’s preferred unit. */
pub mod UnitLocalization {
    pub const TemperatureUnit: u32 = 0x0000;
    pub const SupportedTemperatureUnits: u32 = 0x0001;
}
/** This cluster is used to describe the configuration and capabilities of a physical power source that provides power to the Node. */
pub mod PowerSource {
    pub const Status: u32 = 0x0000;
    pub const Order: u32 = 0x0001;
    pub const Description: u32 = 0x0002;
    pub const WiredAssessedInputVoltage: u32 = 0x0003;
    pub const WiredAssessedInputFrequency: u32 = 0x0004;
    pub const WiredCurrentType: u32 = 0x0005;
    pub const WiredAssessedCurrent: u32 = 0x0006;
    pub const WiredNominalVoltage: u32 = 0x0007;
    pub const WiredMaximumCurrent: u32 = 0x0008;
    pub const WiredPresent: u32 = 0x0009;
    pub const ActiveWiredFaults: u32 = 0x000A;
    pub const BatVoltage: u32 = 0x000B;
    pub const BatPercentRemaining: u32 = 0x000C;
    pub const BatTimeRemaining: u32 = 0x000D;
    pub const BatChargeLevel: u32 = 0x000E;
    pub const BatReplacementNeeded: u32 = 0x000F;
    pub const BatReplaceability: u32 = 0x0010;
    pub const BatPresent: u32 = 0x0011;
    pub const ActiveBatFaults: u32 = 0x0012;
    pub const BatReplacementDescription: u32 = 0x0013;
    pub const BatCommonDesignation: u32 = 0x0014;
    pub const BatANSIDesignation: u32 = 0x0015;
    pub const BatIECDesignation: u32 = 0x0016;
    pub const BatApprovedChemistry: u32 = 0x0017;
    pub const BatCapacity: u32 = 0x0018;
    pub const BatQuantity: u32 = 0x0019;
    pub const BatChargeState: u32 = 0x001A;
    pub const BatTimeToFullCharge: u32 = 0x001B;
    pub const BatFunctionalWhileCharging: u32 = 0x001C;
    pub const BatChargingCurrent: u32 = 0x001D;
    pub const ActiveBatChargeFaults: u32 = 0x001E;
    pub const EndpointList: u32 = 0x001F;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod OzoneConcentrationMeasurement {
    pub const MeasuredValue: u32 = 0x0000;
    pub const MinMeasuredValue: u32 = 0x0001;
    pub const MaxMeasuredValue: u32 = 0x0002;
    pub const PeakMeasuredValue: u32 = 0x0003;
    pub const PeakMeasuredValueWindow: u32 = 0x0004;
    pub const AverageMeasuredValue: u32 = 0x0005;
    pub const AverageMeasuredValueWindow: u32 = 0x0006;
    pub const Uncertainty: u32 = 0x0007;
    pub const MeasurementUnit: u32 = 0x0008;
    pub const MeasurementMedium: u32 = 0x0009;
    pub const LevelValue: u32 = 0x000A;
}
/** The Power Topology Cluster provides a mechanism for expressing how power is flowing between endpoints. */
pub mod PowerTopology {
    pub const AvailableEndpoints: u32 = 0x0000;
    pub const ActiveEndpoints: u32 = 0x0001;
}
/** Attributes and commands for configuring the measurement of illuminance, and reporting illuminance measurements. */
pub mod IlluminanceMeasurement {
    pub const MeasuredValue: u32 = 0x0000;
    pub const MinMeasuredValue: u32 = 0x0001;
    pub const MaxMeasuredValue: u32 = 0x0002;
    pub const Tolerance: u32 = 0x0003;
    pub const LightSensorType: u32 = 0x0004;
}
/** The Commodity Metering Cluster provides the mechanism for communicating commodity consumption information within a premises. */
pub mod CommodityMetering {
    pub const MeteredQuantity: u32 = 0x0000;
    pub const MeteredQuantityTimestamp: u32 = 0x0001;
    pub const TariffUnit: u32 = 0x0002;
    pub const MaximumMeteredQuantities: u32 = 0x0003;
}
/** The Descriptor Cluster is meant to replace the support from the Zigbee Device Object (ZDO) for describing a node, its endpoints and clusters. */
pub mod Descriptor {
    pub const DeviceTypeList: u32 = 0x0000;
    pub const ServerList: u32 = 0x0001;
    pub const ClientList: u32 = 0x0002;
    pub const PartsList: u32 = 0x0003;
    pub const TagList: u32 = 0x0004;
    pub const EndpointUniqueID: u32 = 0x0005;
}
/** The Electrical Grid Conditions Cluster provides the mechanism for communicating electricity grid carbon intensity to devices within the premises in units of Grams of CO2e per kWh. */
pub mod ElectricalGridConditions {
    pub const LocalGenerationAvailable: u32 = 0x0000;
    pub const CurrentConditions: u32 = 0x0001;
    pub const ForecastConditions: u32 = 0x0002;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod NitrogenDioxideConcentrationMeasurement {
    pub const MeasuredValue: u32 = 0x0000;
    pub const MinMeasuredValue: u32 = 0x0001;
    pub const MaxMeasuredValue: u32 = 0x0002;
    pub const PeakMeasuredValue: u32 = 0x0003;
    pub const PeakMeasuredValueWindow: u32 = 0x0004;
    pub const AverageMeasuredValue: u32 = 0x0005;
    pub const AverageMeasuredValueWindow: u32 = 0x0006;
    pub const Uncertainty: u32 = 0x0007;
    pub const MeasurementUnit: u32 = 0x0008;
    pub const MeasurementMedium: u32 = 0x0009;
    pub const LevelValue: u32 = 0x000A;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod PM1ConcentrationMeasurement {
    pub const MeasuredValue: u32 = 0x0000;
    pub const MinMeasuredValue: u32 = 0x0001;
    pub const MaxMeasuredValue: u32 = 0x0002;
    pub const PeakMeasuredValue: u32 = 0x0003;
    pub const PeakMeasuredValueWindow: u32 = 0x0004;
    pub const AverageMeasuredValue: u32 = 0x0005;
    pub const AverageMeasuredValueWindow: u32 = 0x0006;
    pub const Uncertainty: u32 = 0x0007;
    pub const MeasurementUnit: u32 = 0x0008;
    pub const MeasurementMedium: u32 = 0x0009;
    pub const LevelValue: u32 = 0x000A;
}
/** This cluster provides attributes and events for determining basic information about Nodes, which supports both
 * Commissioning and operational determination of Node characteristics, such as Vendor ID, Product ID and serial number,
 * which apply to the whole Node. Also allows setting user device information such as location. */
pub mod BasicInformation {
    pub const DataModelRevision: u32 = 0x0000;
    pub const VendorName: u32 = 0x0001;
    pub const VendorID: u32 = 0x0002;
    pub const ProductName: u32 = 0x0003;
    pub const ProductID: u32 = 0x0004;
    pub const NodeLabel: u32 = 0x0005;
    pub const Location: u32 = 0x0006;
    pub const HardwareVersion: u32 = 0x0007;
    pub const HardwareVersionString: u32 = 0x0008;
    pub const SoftwareVersion: u32 = 0x0009;
    pub const SoftwareVersionString: u32 = 0x000A;
    pub const ManufacturingDate: u32 = 0x000B;
    pub const PartNumber: u32 = 0x000C;
    pub const ProductURL: u32 = 0x000D;
    pub const ProductLabel: u32 = 0x000E;
    pub const SerialNumber: u32 = 0x000F;
    pub const LocalConfigDisabled: u32 = 0x0010;
    pub const Reachable: u32 = 0x0011;
    pub const UniqueID: u32 = 0x0012;
    pub const CapabilityMinima: u32 = 0x0013;
    pub const ProductAppearance: u32 = 0x0014;
    pub const SpecificationVersion: u32 = 0x0015;
    pub const MaxPathsPerInvoke: u32 = 0x0016;
    pub const ConfigurationVersion: u32 = 0x0018;
}
/** Attributes and commands for configuring the measurement of relative humidity, and reporting relative humidity measurements. */
pub mod RelativeHumidityMeasurement {
    pub const MeasuredValue: u32 = 0x0000;
    pub const MinMeasuredValue: u32 = 0x0001;
    pub const MaxMeasuredValue: u32 = 0x0002;
    pub const Tolerance: u32 = 0x0003;
}
/** This cluster provides an interface for controlling Media Playback (PLAY, PAUSE, etc) on a media device such as a TV or Speaker. */
pub mod MediaPlayback {
    pub const CurrentState: u32 = 0x0000;
    pub const StartTime: u32 = 0x0001;
    pub const Duration: u32 = 0x0002;
    pub const SampledPosition: u32 = 0x0003;
    pub const PlaybackSpeed: u32 = 0x0004;
    pub const SeekRangeEnd: u32 = 0x0005;
    pub const SeekRangeStart: u32 = 0x0006;
    pub const ActiveAudioTrack: u32 = 0x0007;
    pub const AvailableAudioTracks: u32 = 0x0008;
    pub const ActiveTextTrack: u32 = 0x0009;
    pub const AvailableTextTracks: u32 = 0x000A;
}
/** Provides an interface for controlling and adjusting automatic window coverings. */
pub mod WindowCovering {
    pub const Type: u32 = 0x0000;
    pub const NumberOfActuationsLift: u32 = 0x0005;
    pub const NumberOfActuationsTilt: u32 = 0x0006;
    pub const ConfigStatus: u32 = 0x0007;
    pub const CurrentPositionLiftPercentage: u32 = 0x0008;
    pub const CurrentPositionTiltPercentage: u32 = 0x0009;
    pub const OperationalStatus: u32 = 0x000A;
    pub const TargetPositionLiftPercent100ths: u32 = 0x000B;
    pub const TargetPositionTiltPercent100ths: u32 = 0x000C;
    pub const EndProductType: u32 = 0x000D;
    pub const CurrentPositionLiftPercent100ths: u32 = 0x000E;
    pub const CurrentPositionTiltPercent100ths: u32 = 0x000F;
    pub const Mode: u32 = 0x0017;
    pub const SafetyStatus: u32 = 0x001A;
}
/** The Wi-Fi Network Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub mod WiFiNetworkDiagnostics {
    pub const BSSID: u32 = 0x0000;
    pub const SecurityType: u32 = 0x0001;
    pub const WiFiVersion: u32 = 0x0002;
    pub const ChannelNumber: u32 = 0x0003;
    pub const RSSI: u32 = 0x0004;
    pub const BeaconLostCount: u32 = 0x0005;
    pub const BeaconRxCount: u32 = 0x0006;
    pub const PacketMulticastRxCount: u32 = 0x0007;
    pub const PacketMulticastTxCount: u32 = 0x0008;
    pub const PacketUnicastRxCount: u32 = 0x0009;
    pub const PacketUnicastTxCount: u32 = 0x000A;
    pub const CurrentMaxRate: u32 = 0x000B;
    pub const OverrunCount: u32 = 0x000C;
}
/** Attributes for reporting air quality classification */
pub mod AirQuality {
    pub const AirQuality: u32 = 0x0000;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod TotalVolatileOrganicCompoundsConcentrationMeasurement {
    pub const MeasuredValue: u32 = 0x0000;
    pub const MinMeasuredValue: u32 = 0x0001;
    pub const MaxMeasuredValue: u32 = 0x0002;
    pub const PeakMeasuredValue: u32 = 0x0003;
    pub const PeakMeasuredValueWindow: u32 = 0x0004;
    pub const AverageMeasuredValue: u32 = 0x0005;
    pub const AverageMeasuredValueWindow: u32 = 0x0006;
    pub const Uncertainty: u32 = 0x0007;
    pub const MeasurementUnit: u32 = 0x0008;
    pub const MeasurementMedium: u32 = 0x0009;
    pub const LevelValue: u32 = 0x000A;
}
/** Provides an interface for downloading and applying OTA software updates */
pub mod OTASoftwareUpdateRequestor {
    pub const DefaultOTAProviders: u32 = 0x0000;
    pub const UpdatePossible: u32 = 0x0001;
    pub const UpdateState: u32 = 0x0002;
    pub const UpdateStateProgress: u32 = 0x0003;
}
/** The WebRTC transport requestor cluster provides a way for stream consumers (e.g. Matter Stream Viewer) to establish a WebRTC connection with a stream provider. */
pub mod WebRTCTransportRequestor {
    pub const CurrentSessions: u32 = 0x0000;
}
/** Manages the names and credentials of Thread networks visible to the user. */
pub mod ThreadNetworkDirectory {
    pub const PreferredExtendedPanID: u32 = 0x0000;
    pub const ThreadNetworks: u32 = 0x0001;
    pub const ThreadNetworkTableSize: u32 = 0x0002;
}
/** The Service Area cluster provides an interface for controlling the areas where a device should operate, and for querying the current area being serviced. */
pub mod ServiceArea {
    pub const SupportedAreas: u32 = 0x0000;
    pub const SupportedMaps: u32 = 0x0001;
    pub const SelectedAreas: u32 = 0x0002;
    pub const CurrentArea: u32 = 0x0003;
    pub const EstimatedEndTime: u32 = 0x0004;
    pub const Progress: u32 = 0x0005;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod RefrigeratorAndTemperatureControlledCabinetMode {
    pub const SupportedModes: u32 = 0x0000;
    pub const CurrentMode: u32 = 0x0001;
    pub const StartUpMode: u32 = 0x0002;
    pub const OnMode: u32 = 0x0003;
}
/** The Access Control Cluster exposes a data model view of a
 * Node's Access Control List (ACL), which codifies the rules used to manage
 * and enforce Access Control for the Node's endpoints and their associated
 * cluster instances. */
pub mod AccessControl {
    pub const ACL: u32 = 0x0000;
    pub const Extension: u32 = 0x0001;
    pub const SubjectsPerAccessControlEntry: u32 = 0x0002;
    pub const TargetsPerAccessControlEntry: u32 = 0x0003;
    pub const AccessControlEntriesPerFabric: u32 = 0x0004;
    pub const CommissioningARL: u32 = 0x0005;
    pub const ARL: u32 = 0x0006;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod WaterHeaterMode {
    pub const SupportedModes: u32 = 0x0000;
    pub const CurrentMode: u32 = 0x0001;
    pub const StartUpMode: u32 = 0x0002;
    pub const OnMode: u32 = 0x0003;
}
/** This Cluster is used to provision TLS Endpoints with enough information to facilitate subsequent connection. */
pub mod TLSClientManagement {
    pub const MaxProvisioned: u32 = 0x0000;
    pub const ProvisionedEndpoints: u32 = 0x0001;
}
/** This cluster provides a mechanism for querying data about the electrical energy imported or provided by the server. */
pub mod ElectricalEnergyMeasurement {
    pub const Accuracy: u32 = 0x0000;
    pub const CumulativeEnergyImported: u32 = 0x0001;
    pub const CumulativeEnergyExported: u32 = 0x0002;
    pub const PeriodicEnergyImported: u32 = 0x0003;
    pub const PeriodicEnergyExported: u32 = 0x0004;
    pub const CumulativeEnergyReset: u32 = 0x0005;
}
/** This cluster provides an interface for controlling a Closure. */
pub mod ClosureControl {
    pub const CountdownTime: u32 = 0x0000;
    pub const MainState: u32 = 0x0001;
    pub const CurrentErrorList: u32 = 0x0002;
    pub const OverallCurrentState: u32 = 0x0003;
    pub const OverallTargetState: u32 = 0x0004;
    pub const LatchControlModes: u32 = 0x0005;
}
/** Attributes and commands for putting a device into Identification mode (e.g. flashing a light). */
pub mod Identify {
    pub const IdentifyTime: u32 = 0x0000;
    pub const IdentifyType: u32 = 0x0001;
}
/** The Binding Cluster is meant to replace the support from the Zigbee Device Object (ZDO) for supporting the binding table. */
pub mod Binding {
    pub const Binding: u32 = 0x0000;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod EnergyEVSEMode {
    pub const SupportedModes: u32 = 0x0000;
    pub const CurrentMode: u32 = 0x0001;
    pub const StartUpMode: u32 = 0x0002;
    pub const OnMode: u32 = 0x0003;
}
/** This cluster is used to configure a boolean sensor. */
pub mod BooleanStateConfiguration {
    pub const CurrentSensitivityLevel: u32 = 0x0000;
    pub const SupportedSensitivityLevels: u32 = 0x0001;
    pub const DefaultSensitivityLevel: u32 = 0x0002;
    pub const AlarmsActive: u32 = 0x0003;
    pub const AlarmsSuppressed: u32 = 0x0004;
    pub const AlarmsEnabled: u32 = 0x0005;
    pub const AlarmsSupported: u32 = 0x0006;
    pub const SensorFault: u32 = 0x0007;
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod RadonConcentrationMeasurement {
    pub const MeasuredValue: u32 = 0x0000;
    pub const MinMeasuredValue: u32 = 0x0001;
    pub const MaxMeasuredValue: u32 = 0x0002;
    pub const PeakMeasuredValue: u32 = 0x0003;
    pub const PeakMeasuredValueWindow: u32 = 0x0004;
    pub const AverageMeasuredValue: u32 = 0x0005;
    pub const AverageMeasuredValueWindow: u32 = 0x0006;
    pub const Uncertainty: u32 = 0x0007;
    pub const MeasurementUnit: u32 = 0x0008;
    pub const MeasurementMedium: u32 = 0x0009;
    pub const LevelValue: u32 = 0x000A;
}
/** Nodes should be expected to be deployed to any and all regions of the world. These global regions
 * may have differing common languages, units of measurements, and numerical formatting
 * standards. As such, Nodes that visually or audibly convey information need a mechanism by which
 * they can be configured to use a user’s preferred language, units, etc */
pub mod LocalizationConfiguration {
    pub const ActiveLocale: u32 = 0x0000;
    pub const SupportedLocales: u32 = 0x0001;
}
/** This Meter Identification Cluster provides attributes for determining advanced information about utility metering device. */
pub mod MeterIdentification {
    pub const MeterType: u32 = 0x0000;
    pub const PointOfDelivery: u32 = 0x0001;
    pub const MeterSerialNumber: u32 = 0x0002;
    pub const ProtocolVersion: u32 = 0x0003;
    pub const PowerThreshold: u32 = 0x0004;
}
/** This cluster provides an interface to specify preferences for how devices should consume energy. */
pub mod EnergyPreference {
    pub const EnergyBalances: u32 = 0x0000;
    pub const CurrentEnergyBalance: u32 = 0x0001;
    pub const EnergyPriorities: u32 = 0x0002;
    pub const LowPowerModeSensitivities: u32 = 0x0003;
    pub const CurrentLowPowerModeSensitivity: u32 = 0x0004;
}
/** Attributes and commands for scene configuration and manipulation. */
pub mod ScenesManagement {
    pub const SceneTableSize: u32 = 0x0001;
    pub const FabricSceneInfo: u32 = 0x0002;
}
/** Attributes and commands for monitoring HEPA filters in a device */
pub mod HEPAFilterMonitoring {
    pub const Condition: u32 = 0x0000;
    pub const DegradationDirection: u32 = 0x0001;
    pub const ChangeIndication: u32 = 0x0002;
    pub const InPlaceIndicator: u32 = 0x0003;
    pub const LastChangedTime: u32 = 0x0004;
    pub const ReplacementProductList: u32 = 0x0005;
}
/** Attributes and commands for monitoring HEPA filters in a device */
pub mod ActivatedCarbonFilterMonitoring {
    pub const Condition: u32 = 0x0000;
    pub const DegradationDirection: u32 = 0x0001;
    pub const ChangeIndication: u32 = 0x0002;
    pub const InPlaceIndicator: u32 = 0x0003;
    pub const LastChangedTime: u32 = 0x0004;
    pub const ReplacementProductList: u32 = 0x0005;
}
/** Attributes and commands for monitoring HEPA filters in a device */
pub mod WaterTankLevelMonitoring {
    pub const Condition: u32 = 0x0000;
    pub const DegradationDirection: u32 = 0x0001;
    pub const ChangeIndication: u32 = 0x0002;
    pub const InPlaceIndicator: u32 = 0x0003;
    pub const LastChangedTime: u32 = 0x0004;
    pub const ReplacementProductList: u32 = 0x0005;
}
/** This cluster provides an interface for managing low power mode on a device that supports the Wake On LAN protocol. */
pub mod WakeOnLAN {
    pub const MACAddress: u32 = 0x0000;
    pub const LinkLocalAddress: u32 = 0x0001;
}
/** An interface for configuring and controlling pumps. */
pub mod PumpConfigurationandControl {
    pub const MaxPressure: u32 = 0x0000;
    pub const MaxSpeed: u32 = 0x0001;
    pub const MaxFlow: u32 = 0x0002;
    pub const MinConstPressure: u32 = 0x0003;
    pub const MaxConstPressure: u32 = 0x0004;
    pub const MinCompPressure: u32 = 0x0005;
    pub const MaxCompPressure: u32 = 0x0006;
    pub const MinConstSpeed: u32 = 0x0007;
    pub const MaxConstSpeed: u32 = 0x0008;
    pub const MinConstFlow: u32 = 0x0009;
    pub const MaxConstFlow: u32 = 0x000A;
    pub const MinConstTemp: u32 = 0x000B;
    pub const MaxConstTemp: u32 = 0x000C;
    pub const PumpStatus: u32 = 0x0010;
    pub const EffectiveOperationMode: u32 = 0x0011;
    pub const EffectiveControlMode: u32 = 0x0012;
    pub const Capacity: u32 = 0x0013;
    pub const Speed: u32 = 0x0014;
    pub const LifetimeRunningHours: u32 = 0x0015;
    pub const Power: u32 = 0x0016;
    pub const LifetimeEnergyConsumed: u32 = 0x0017;
    pub const OperationMode: u32 = 0x0020;
    pub const ControlMode: u32 = 0x0021;
}
/** Attributes and commands for configuring the measurement of temperature, and reporting temperature measurements. */
pub mod TemperatureMeasurement {
    pub const MeasuredValue: u32 = 0x0000;
    pub const MinMeasuredValue: u32 = 0x0001;
    pub const MaxMeasuredValue: u32 = 0x0002;
    pub const Tolerance: u32 = 0x0003;
}
/** This cluster is used to manage global aspects of the Commissioning flow. */
pub mod GeneralCommissioning {
    pub const Breadcrumb: u32 = 0x0000;
    pub const BasicCommissioningInfo: u32 = 0x0001;
    pub const RegulatoryConfig: u32 = 0x0002;
    pub const LocationCapability: u32 = 0x0003;
    pub const SupportsConcurrentConnection: u32 = 0x0004;
    pub const TCAcceptedVersion: u32 = 0x0005;
    pub const TCMinRequiredVersion: u32 = 0x0006;
    pub const TCAcknowledgements: u32 = 0x0007;
    pub const TCAcknowledgementsRequired: u32 = 0x0008;
    pub const TCUpdateDeadline: u32 = 0x0009;
    pub const RecoveryIdentifier: u32 = 0x000A;
    pub const NetworkRecoveryReason: u32 = 0x000B;
    pub const IsCommissioningWithoutPower: u32 = 0x000C;
}
/** This cluster is used to add or remove Operational Credentials on a Commissionee or Node, as well as manage the associated Fabrics. */
pub mod OperationalCredentials {
    pub const NOCs: u32 = 0x0000;
    pub const Fabrics: u32 = 0x0001;
    pub const SupportedFabrics: u32 = 0x0002;
    pub const CommissionedFabrics: u32 = 0x0003;
    pub const TrustedRootCertificates: u32 = 0x0004;
    pub const CurrentFabricIndex: u32 = 0x0005;
}
/** This cluster provides an interface for UX navigation within a set of targets on a device or endpoint. */
pub mod TargetNavigator {
    pub const TargetList: u32 = 0x0000;
    pub const CurrentTarget: u32 = 0x0001;
}
/** An interface for controlling a fan in a heating/cooling system. */
pub mod FanControl {
    pub const FanMode: u32 = 0x0000;
    pub const FanModeSequence: u32 = 0x0001;
    pub const PercentSetting: u32 = 0x0002;
    pub const PercentCurrent: u32 = 0x0003;
    pub const SpeedMax: u32 = 0x0004;
    pub const SpeedSetting: u32 = 0x0005;
    pub const SpeedCurrent: u32 = 0x0006;
    pub const RockSupport: u32 = 0x0007;
    pub const RockSetting: u32 = 0x0008;
    pub const WindSupport: u32 = 0x0009;
    pub const WindSetting: u32 = 0x000A;
    pub const AirflowDirection: u32 = 0x000B;
}
pub mod GlobalElements {
    pub const ClusterRevision: u32 = 0xFFFD;
    pub const FeatureMap: u32 = 0xFFFC;
    pub const AttributeList: u32 = 0xFFFB;
    pub const EventList: u32 = 0xFFFA;
    pub const AcceptedCommandList: u32 = 0xFFF9;
    pub const GeneratedCommandList: u32 = 0xFFF8;
}
/** An interface to a generic way to secure a door */
pub mod DoorLock {
    pub const LockState: u32 = 0x0000;
    pub const LockType: u32 = 0x0001;
    pub const ActuatorEnabled: u32 = 0x0002;
    pub const DoorState: u32 = 0x0003;
    pub const DoorOpenEvents: u32 = 0x0004;
    pub const DoorClosedEvents: u32 = 0x0005;
    pub const OpenPeriod: u32 = 0x0006;
    pub const NumberOfTotalUsersSupported: u32 = 0x0011;
    pub const NumberOfPINUsersSupported: u32 = 0x0012;
    pub const NumberOfRFIDUsersSupported: u32 = 0x0013;
    pub const NumberOfWeekDaySchedulesSupportedPerUser: u32 = 0x0014;
    pub const NumberOfYearDaySchedulesSupportedPerUser: u32 = 0x0015;
    pub const NumberOfHolidaySchedulesSupported: u32 = 0x0016;
    pub const MaxPINCodeLength: u32 = 0x0017;
    pub const MinPINCodeLength: u32 = 0x0018;
    pub const MaxRFIDCodeLength: u32 = 0x0019;
    pub const MinRFIDCodeLength: u32 = 0x001A;
    pub const CredentialRulesSupport: u32 = 0x001B;
    pub const NumberOfCredentialsSupportedPerUser: u32 = 0x001C;
    pub const Language: u32 = 0x0021;
    pub const LEDSettings: u32 = 0x0022;
    pub const AutoRelockTime: u32 = 0x0023;
    pub const SoundVolume: u32 = 0x0024;
    pub const OperatingMode: u32 = 0x0025;
    pub const SupportedOperatingModes: u32 = 0x0026;
    pub const DefaultConfigurationRegister: u32 = 0x0027;
    pub const EnableLocalProgramming: u32 = 0x0028;
    pub const EnableOneTouchLocking: u32 = 0x0029;
    pub const EnableInsideStatusLED: u32 = 0x002A;
    pub const EnablePrivacyModeButton: u32 = 0x002B;
    pub const LocalProgrammingFeatures: u32 = 0x002C;
    pub const WrongCodeEntryLimit: u32 = 0x0030;
    pub const UserCodeTemporaryDisableTime: u32 = 0x0031;
    pub const SendPINOverTheAir: u32 = 0x0032;
    pub const RequirePINforRemoteOperation: u32 = 0x0033;
    pub const ExpiringUserTimeout: u32 = 0x0035;
    pub const AliroReaderVerificationKey: u32 = 0x0080;
    pub const AliroReaderGroupIdentifier: u32 = 0x0081;
    pub const AliroReaderGroupSubIdentifier: u32 = 0x0082;
    pub const AliroExpeditedTransactionSupportedProtocolVersions: u32 = 0x0083;
    pub const AliroGroupResolvingKey: u32 = 0x0084;
    pub const AliroSupportedBLEUWBProtocolVersions: u32 = 0x0085;
    pub const AliroBLEAdvertisingVersion: u32 = 0x0086;
    pub const NumberOfAliroCredentialIssuerKeysSupported: u32 = 0x0087;
    pub const NumberOfAliroEndpointKeysSupported: u32 = 0x0088;
}
/** Attributes and commands for configuring the measurement of flow, and reporting flow measurements. */
pub mod FlowMeasurement {
    pub const MeasuredValue: u32 = 0x0000;
    pub const MinMeasuredValue: u32 = 0x0001;
    pub const MaxMeasuredValue: u32 = 0x0002;
    pub const Tolerance: u32 = 0x0003;
}
/** The WebRTC transport provider cluster provides a way for stream providers (e.g. Cameras) to stream or receive their data through WebRTC. */
pub mod WebRTCTransportProvider {
    pub const CurrentSessions: u32 = 0x0000;
}
/** Manage the Thread network of Thread Border Router */
pub mod ThreadBorderRouterManagement {
    pub const BorderRouterName: u32 = 0x0000;
    pub const BorderAgentID: u32 = 0x0001;
    pub const ThreadVersion: u32 = 0x0002;
    pub const InterfaceEnabled: u32 = 0x0003;
    pub const ActiveDatasetTimestamp: u32 = 0x0004;
    pub const PendingDatasetTimestamp: u32 = 0x0005;
}
/** The Camera AV Stream Management cluster is used to allow clients to manage, control, and configure various audio, video, and snapshot streams on a camera. */
pub mod CameraAVStreamManagement {
    pub const MaxConcurrentEncoders: u32 = 0x0000;
    pub const MaxEncodedPixelRate: u32 = 0x0001;
    pub const VideoSensorParams: u32 = 0x0002;
    pub const NightVisionUsesInfrared: u32 = 0x0003;
    pub const MinViewportResolution: u32 = 0x0004;
    pub const RateDistortionTradeOffPoints: u32 = 0x0005;
    pub const MaxContentBufferSize: u32 = 0x0006;
    pub const MicrophoneCapabilities: u32 = 0x0007;
    pub const SpeakerCapabilities: u32 = 0x0008;
    pub const TwoWayTalkSupport: u32 = 0x0009;
    pub const SnapshotCapabilities: u32 = 0x000A;
    pub const MaxNetworkBandwidth: u32 = 0x000B;
    pub const CurrentFrameRate: u32 = 0x000C;
    pub const HDRModeEnabled: u32 = 0x000D;
    pub const SupportedStreamUsages: u32 = 0x000E;
    pub const AllocatedVideoStreams: u32 = 0x000F;
    pub const AllocatedAudioStreams: u32 = 0x0010;
    pub const AllocatedSnapshotStreams: u32 = 0x0011;
    pub const StreamUsagePriorities: u32 = 0x0012;
    pub const SoftRecordingPrivacyModeEnabled: u32 = 0x0013;
    pub const SoftLivestreamPrivacyModeEnabled: u32 = 0x0014;
    pub const HardPrivacyModeOn: u32 = 0x0015;
    pub const NightVision: u32 = 0x0016;
    pub const NightVisionIllum: u32 = 0x0017;
    pub const Viewport: u32 = 0x0018;
    pub const SpeakerMuted: u32 = 0x0019;
    pub const SpeakerVolumeLevel: u32 = 0x001A;
    pub const SpeakerMaxLevel: u32 = 0x001B;
    pub const SpeakerMinLevel: u32 = 0x001C;
    pub const MicrophoneMuted: u32 = 0x001D;
    pub const MicrophoneVolumeLevel: u32 = 0x001E;
    pub const MicrophoneMaxLevel: u32 = 0x001F;
    pub const MicrophoneMinLevel: u32 = 0x0020;
    pub const MicrophoneAGCEnabled: u32 = 0x0021;
    pub const ImageRotation: u32 = 0x0022;
    pub const ImageFlipHorizontal: u32 = 0x0023;
    pub const ImageFlipVertical: u32 = 0x0024;
    pub const LocalVideoRecordingEnabled: u32 = 0x0025;
    pub const LocalSnapshotRecordingEnabled: u32 = 0x0026;
    pub const StatusLightEnabled: u32 = 0x0027;
    pub const StatusLightBrightness: u32 = 0x0028;
}
/** An instance of the Joint Fabric Administrator Cluster only applies to Joint Fabric Administrator nodes fulfilling the role of Anchor CA. */
pub mod JointFabricAdministrator {
    pub const AdministratorFabricIndex: u32 = 0x0000;
}
/** This cluster supports remotely monitoring and, where supported, changing the operational state of a Robotic Vacuum. */
pub mod RVCOperationalState {
    pub const PhaseList: u32 = 0x0000;
    pub const CurrentPhase: u32 = 0x0001;
    pub const CountdownTime: u32 = 0x0002;
    pub const OperationalStateList: u32 = 0x0003;
    pub const OperationalState: u32 = 0x0004;
    pub const OperationalError: u32 = 0x0005;
}
/** This cluster supports remotely monitoring and controlling the different types of functionality available to a washing device, such as a washing machine. */
pub mod LaundryWasherControls {
    pub const SpinSpeeds: u32 = 0x0000;
    pub const SpinSpeedCurrent: u32 = 0x0001;
    pub const NumberOfRinses: u32 = 0x0002;
    pub const SupportedRinses: u32 = 0x0003;
}
/** Attributes and commands for group configuration and manipulation. */
pub mod Groups {
    pub const NameSupport: u32 = 0x0000;
}
/** This cluster provides an interface to reflect and control a closure's range of movement, usually involving a panel, by using 6-axis framework. */
pub mod ClosureDimension {
    pub const CurrentState: u32 = 0x0000;
    pub const TargetState: u32 = 0x0001;
    pub const Resolution: u32 = 0x0002;
    pub const StepValue: u32 = 0x0003;
    pub const Unit: u32 = 0x0004;
    pub const UnitRange: u32 = 0x0005;
    pub const LimitRange: u32 = 0x0006;
    pub const TranslationDirection: u32 = 0x0007;
    pub const RotationAxis: u32 = 0x0008;
    pub const Overflow: u32 = 0x0009;
    pub const ModulationType: u32 = 0x000A;
    pub const LatchControlModes: u32 = 0x000B;
}
/** Attributes and commands for configuring the Refrigerator alarm. */
pub mod RefrigeratorAlarm {
    pub const Mask: u32 = 0x0000;
    pub const Latch: u32 = 0x0001;
    pub const State: u32 = 0x0002;
    pub const Supported: u32 = 0x0003;
}
/** An interface for configuring the user interface of a thermostat (which may be remote from the thermostat). */
pub mod ThermostatUserInterfaceConfiguration {
    pub const TemperatureDisplayMode: u32 = 0x0000;
    pub const KeypadLockout: u32 = 0x0001;
    pub const ScheduleProgrammingVisibility: u32 = 0x0002;
}
/** This cluster provides an interface for controlling the Input Selector on a media device such as a TV. */
pub mod MediaInput {
    pub const InputList: u32 = 0x0000;
    pub const CurrentInput: u32 = 0x0001;
}
/** The server cluster provides an interface to occupancy sensing functionality based on one or more sensing modalities, including configuration and provision of notifications of occupancy status. */
pub mod OccupancySensing {
    pub const Occupancy: u32 = 0x0000;
    pub const OccupancySensorType: u32 = 0x0001;
    pub const OccupancySensorTypeBitmap: u32 = 0x0002;
    pub const HoldTime: u32 = 0x0003;
    pub const HoldTimeLimits: u32 = 0x0004;
    pub const PIROccupiedToUnoccupiedDelay: u32 = 0x0010;
    pub const PIRUnoccupiedToOccupiedDelay: u32 = 0x0011;
    pub const PIRUnoccupiedToOccupiedThreshold: u32 = 0x0012;
    pub const UltrasonicOccupiedToUnoccupiedDelay: u32 = 0x0020;
    pub const UltrasonicUnoccupiedToOccupiedDelay: u32 = 0x0021;
    pub const UltrasonicUnoccupiedToOccupiedThreshold: u32 = 0x0022;
    pub const PhysicalContactOccupiedToUnoccupiedDelay: u32 = 0x0030;
    pub const PhysicalContactUnoccupiedToOccupiedDelay: u32 = 0x0031;
    pub const PhysicalContactUnoccupiedToOccupiedThreshold: u32 = 0x0032;
}
/** This Cluster is used to manage TLS Client Certificates and to provision
 * TLS endpoints with enough information to facilitate subsequent connection. */
pub mod TLSCertificateManagement {
    pub const MaxRootCertificates: u32 = 0x0000;
    pub const ProvisionedRootCertificates: u32 = 0x0001;
    pub const MaxClientCertificates: u32 = 0x0002;
    pub const ProvisionedClientCertificates: u32 = 0x0003;
}
/** The CommodityTariffCluster provides the mechanism for communicating Commodity Tariff information within the premises. */
pub mod CommodityTariff {
    pub const TariffInfo: u32 = 0x0000;
    pub const TariffUnit: u32 = 0x0001;
    pub const StartDate: u32 = 0x0002;
    pub const DayEntries: u32 = 0x0003;
    pub const DayPatterns: u32 = 0x0004;
    pub const CalendarPeriods: u32 = 0x0005;
    pub const IndividualDays: u32 = 0x0006;
    pub const CurrentDay: u32 = 0x0007;
    pub const NextDay: u32 = 0x0008;
    pub const CurrentDayEntry: u32 = 0x0009;
    pub const CurrentDayEntryDate: u32 = 0x000A;
    pub const NextDayEntry: u32 = 0x000B;
    pub const NextDayEntryDate: u32 = 0x000C;
    pub const TariffComponents: u32 = 0x000D;
    pub const TariffPeriods: u32 = 0x000E;
    pub const CurrentTariffComponents: u32 = 0x000F;
    pub const NextTariffComponents: u32 = 0x0010;
    pub const DefaultRandomizationOffset: u32 = 0x0011;
    pub const DefaultRandomizationType: u32 = 0x0012;
}
/** Attributes and commands for configuring the measurement of pressure, and reporting pressure measurements. */
pub mod PressureMeasurement {
    pub const MeasuredValue: u32 = 0x0000;
    pub const MinMeasuredValue: u32 = 0x0001;
    pub const MaxMeasuredValue: u32 = 0x0002;
    pub const Tolerance: u32 = 0x0003;
    pub const ScaledValue: u32 = 0x0010;
    pub const MinScaledValue: u32 = 0x0011;
    pub const MaxScaledValue: u32 = 0x0012;
    pub const ScaledTolerance: u32 = 0x0013;
    pub const Scale: u32 = 0x0014;
}
/** An interface for configuring and controlling the functionality of a thermostat. */
pub mod Thermostat {
    pub const LocalTemperature: u32 = 0x0000;
    pub const OutdoorTemperature: u32 = 0x0001;
    pub const Occupancy: u32 = 0x0002;
    pub const AbsMinHeatSetpointLimit: u32 = 0x0003;
    pub const AbsMaxHeatSetpointLimit: u32 = 0x0004;
    pub const AbsMinCoolSetpointLimit: u32 = 0x0005;
    pub const AbsMaxCoolSetpointLimit: u32 = 0x0006;
    pub const LocalTemperatureCalibration: u32 = 0x0010;
    pub const OccupiedCoolingSetpoint: u32 = 0x0011;
    pub const OccupiedHeatingSetpoint: u32 = 0x0012;
    pub const UnoccupiedCoolingSetpoint: u32 = 0x0013;
    pub const UnoccupiedHeatingSetpoint: u32 = 0x0014;
    pub const MinHeatSetpointLimit: u32 = 0x0015;
    pub const MaxHeatSetpointLimit: u32 = 0x0016;
    pub const MinCoolSetpointLimit: u32 = 0x0017;
    pub const MaxCoolSetpointLimit: u32 = 0x0018;
    pub const MinSetpointDeadBand: u32 = 0x0019;
    pub const RemoteSensing: u32 = 0x001A;
    pub const ControlSequenceOfOperation: u32 = 0x001B;
    pub const SystemMode: u32 = 0x001C;
    pub const ThermostatRunningMode: u32 = 0x001E;
    pub const TemperatureSetpointHold: u32 = 0x0023;
    pub const TemperatureSetpointHoldDuration: u32 = 0x0024;
    pub const ThermostatProgrammingOperationMode: u32 = 0x0025;
    pub const ThermostatRunningState: u32 = 0x0029;
    pub const SetpointChangeSource: u32 = 0x0030;
    pub const SetpointChangeAmount: u32 = 0x0031;
    pub const SetpointChangeSourceTimestamp: u32 = 0x0032;
    pub const EmergencyHeatDelta: u32 = 0x003A;
    pub const ACType: u32 = 0x0040;
    pub const ACCapacity: u32 = 0x0041;
    pub const ACRefrigerantType: u32 = 0x0042;
    pub const ACCompressorType: u32 = 0x0043;
    pub const ACErrorCode: u32 = 0x0044;
    pub const ACLouverPosition: u32 = 0x0045;
    pub const ACCoilTemperature: u32 = 0x0046;
    pub const ACCapacityFormat: u32 = 0x0047;
    pub const PresetTypes: u32 = 0x0048;
    pub const ScheduleTypes: u32 = 0x0049;
    pub const NumberOfPresets: u32 = 0x004A;
    pub const NumberOfSchedules: u32 = 0x004B;
    pub const NumberOfScheduleTransitions: u32 = 0x004C;
    pub const NumberOfScheduleTransitionPerDay: u32 = 0x004D;
    pub const ActivePresetHandle: u32 = 0x004E;
    pub const ActiveScheduleHandle: u32 = 0x004F;
    pub const Presets: u32 = 0x0050;
    pub const Schedules: u32 = 0x0051;
    pub const SetpointHoldExpiryTimestamp: u32 = 0x0052;
}
/** This cluster provides an interface for controlling the current Channel on a device. */
pub mod Channel {
    pub const ChannelList: u32 = 0x0000;
    pub const Lineup: u32 = 0x0001;
    pub const CurrentChannel: u32 = 0x0002;
}
/** Provides extended device information for all the logical devices represented by a Bridged Node. */
pub mod EcosystemInformation {
    pub const DeviceDirectory: u32 = 0x0000;
    pub const LocationDirectory: u32 = 0x0001;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod OvenMode {
    pub const SupportedModes: u32 = 0x0000;
    pub const CurrentMode: u32 = 0x0001;
    pub const StartUpMode: u32 = 0x0002;
    pub const OnMode: u32 = 0x0003;
}
/** This cluster allows a client to manage the power draw of a device. An example of such a client could be an Energy Management System (EMS) which controls an Energy Smart Appliance (ESA). */
pub mod DeviceEnergyManagement {
    pub const ESAType: u32 = 0x0000;
    pub const ESACanGenerate: u32 = 0x0001;
    pub const ESAState: u32 = 0x0002;
    pub const AbsMinPower: u32 = 0x0003;
    pub const AbsMaxPower: u32 = 0x0004;
    pub const PowerAdjustmentCapability: u32 = 0x0005;
    pub const Forecast: u32 = 0x0006;
    pub const OptOutState: u32 = 0x0007;
}
/** Attributes and commands for configuring the temperature control, and reporting temperature. */
pub mod TemperatureControl {
    pub const TemperatureSetpoint: u32 = 0x0000;
    pub const MinTemperature: u32 = 0x0001;
    pub const MaxTemperature: u32 = 0x0002;
    pub const Step: u32 = 0x0003;
    pub const SelectedTemperatureLevel: u32 = 0x0004;
    pub const SupportedTemperatureLevels: u32 = 0x0005;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod DeviceEnergyManagementMode {
    pub const SupportedModes: u32 = 0x0000;
    pub const CurrentMode: u32 = 0x0001;
    pub const StartUpMode: u32 = 0x0002;
    pub const OnMode: u32 = 0x0003;
}
/** This cluster provides facilities to configure and play Chime sounds, such as those used in a doorbell. */
pub mod Chime {
    pub const InstalledChimeSounds: u32 = 0x0000;
    pub const SelectedChime: u32 = 0x0001;
    pub const Enabled: u32 = 0x0002;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod LaundryWasherMode {
    pub const SupportedModes: u32 = 0x0000;
    pub const CurrentMode: u32 = 0x0001;
    pub const StartUpMode: u32 = 0x0002;
    pub const OnMode: u32 = 0x0003;
}
/** This cluster is used to configure a valve. */
pub mod ValveConfigurationandControl {
    pub const OpenDuration: u32 = 0x0000;
    pub const DefaultOpenDuration: u32 = 0x0001;
    pub const AutoCloseTime: u32 = 0x0002;
    pub const RemainingDuration: u32 = 0x0003;
    pub const CurrentState: u32 = 0x0004;
    pub const TargetState: u32 = 0x0005;
    pub const CurrentLevel: u32 = 0x0006;
    pub const TargetLevel: u32 = 0x0007;
    pub const DefaultOpenLevel: u32 = 0x0008;
    pub const ValveFault: u32 = 0x0009;
    pub const LevelStep: u32 = 0x000A;
}
/** This cluster supports remotely monitoring and, where supported, changing the operational state of an Oven. */
pub mod OvenCavityOperationalState {
    pub const PhaseList: u32 = 0x0000;
    pub const CurrentPhase: u32 = 0x0001;
    pub const CountdownTime: u32 = 0x0002;
    pub const OperationalStateList: u32 = 0x0003;
    pub const OperationalState: u32 = 0x0004;
    pub const OperationalError: u32 = 0x0005;
}
}
