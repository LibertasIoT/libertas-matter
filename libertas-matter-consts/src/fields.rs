pub mod ContentControl {
    pub mod AppInfoStruct {
        pub const CatalogVendorID: u32 = 0;
        pub const ApplicationID: u32 = 1;
    }
    pub mod BlockChannelStruct {
        pub const BlockChannelIndex: u32 = 0;
        pub const MajorNumber: u32 = 1;
        pub const MinorNumber: u32 = 2;
        pub const Identifier: u32 = 3;
    }
    pub mod RatingNameStruct {
        pub const RatingName: u32 = 0;
        pub const RatingNameDesc: u32 = 1;
    }
    pub mod TimePeriodStruct {
        pub const StartHour: u32 = 0;
        pub const StartMinute: u32 = 1;
        pub const EndHour: u32 = 2;
        pub const EndMinute: u32 = 3;
    }
    pub mod TimeWindowStruct {
        pub const TimeWindowIndex: u32 = 0;
        pub const DayOfWeek: u32 = 1;
        pub const TimePeriod: u32 = 2;
    }
/** The purpose of this command is to update the PIN used for protecting configuration of the content control settings. */
    pub mod UpdatePIN {
        pub const OldPIN: u32 = 0;
        pub const NewPIN: u32 = 1;
    }
/** This command SHALL be generated in response to a ResetPIN command. */
    pub mod ResetPINResponse {
        pub const PINCode: u32 = 0;
    }
/** The purpose of this command is to add the extra screen time for the user. */
    pub mod AddBonusTime {
        pub const PINCode: u32 = 0;
        pub const BonusTime: u32 = 1;
    }
/** The purpose of this command is to set the ScreenDailyTime attribute. */
    pub mod SetScreenDailyTime {
        pub const ScreenTime: u32 = 0;
    }
/** The purpose of this command is to set the OnDemandRatingThreshold attribute. */
    pub mod SetOnDemandRatingThreshold {
        pub const Rating: u32 = 0;
    }
/** The purpose of this command is to set ScheduledContentRatingThreshold attribute. */
    pub mod SetScheduledContentRatingThreshold {
        pub const Rating: u32 = 0;
    }
/** The purpose of this command is to set BlockChannelList attribute. */
    pub mod AddBlockChannels {
        pub const Channels: u32 = 0;
    }
/** The purpose of this command is to remove channels from the BlockChannelList attribute. */
    pub mod RemoveBlockChannels {
        pub const ChannelIndexes: u32 = 0;
    }
/** The purpose of this command is to set applications to the BlockApplicationList attribute. */
    pub mod AddBlockApplications {
        pub const Applications: u32 = 0;
    }
/** The purpose of this command is to remove applications from the BlockApplicationList attribute. */
    pub mod RemoveBlockApplications {
        pub const Applications: u32 = 0;
    }
/** The purpose of this command is to set the BlockContentTimeWindow attribute. */
    pub mod SetBlockContentTimeWindow {
        pub const TimeWindow: u32 = 0;
    }
/** The purpose of this command is to remove the selected time windows from the BlockContentTimeWindow attribute. */
    pub mod RemoveBlockContentTimeWindow {
        pub const TimeWindowIndexes: u32 = 0;
    }
}
pub mod MicrowaveOvenControl {
/** This command is used to set the cooking parameters associated with the operation of the device. */
    pub mod SetCookingParameters {
        pub const CookMode: u32 = 0;
        pub const CookTime: u32 = 1;
        pub const PowerSetting: u32 = 2;
        pub const WattSettingIndex: u32 = 3;
        pub const StartAfterSetting: u32 = 4;
    }
/** This command is used to add more time to the CookTime attribute of the server. */
    pub mod AddMoreTime {
        pub const TimeToAdd: u32 = 0;
    }
}
pub mod Switch {
/** This event SHALL be generated, when the latching switch is moved to a new position. */
    pub mod SwitchLatched {
        pub const NewPosition: u32 = 0;
    }
/** This event SHALL be generated, when the momentary switch starts to be pressed (after debouncing). */
    pub mod InitialPress {
        pub const NewPosition: u32 = 0;
    }
/** This event SHALL be generated when the momentary switch has been pressed for a "long" time. */
    pub mod LongPress {
        pub const NewPosition: u32 = 0;
    }
/** If the server has the Action Switch (AS) feature flag set, this event SHALL NOT be generated at all, since setting the Action Switch feature flag forbids the Momentary Switch ShortRelease (MSR) feature flag from being set. */
    pub mod ShortRelease {
        pub const PreviousPosition: u32 = 0;
    }
/** This event SHALL be generated, when the momentary switch has been released (after debouncing) and after having been pressed for a long time, i.e. this event SHALL be generated when the switch is released if a LongPress event has been generated since the previous InitialPress event. */
    pub mod LongRelease {
        pub const PreviousPosition: u32 = 0;
    }
/** If the server has the Action Switch (AS) feature flag set, this event SHALL NOT be generated at all. */
    pub mod MultiPressOngoing {
        pub const NewPosition: u32 = 0;
        pub const CurrentNumberOfPressesCounted: u32 = 1;
    }
/** This event SHALL be generated to indicate how many times the momentary switch has been pressed in a multi-press sequence, after it has been detected that the sequence has ended. */
    pub mod MultiPressComplete {
        pub const PreviousPosition: u32 = 0;
        pub const TotalNumberOfPressesCounted: u32 = 1;
    }
}
pub mod UserLabel {
    pub mod LabelStruct {
        pub const Label: u32 = 0;
        pub const Value: u32 = 1;
    }
}
pub mod WaterHeaterManagement {
    pub mod WaterHeaterBoostInfoStruct {
        pub const Duration: u32 = 0;
        pub const OneShot: u32 = 1;
        pub const EmergencyBoost: u32 = 2;
        pub const TemporarySetpoint: u32 = 3;
        pub const TargetPercentage: u32 = 4;
        pub const TargetReheat: u32 = 5;
    }
/** Allows a client to request that the water heater is put into a Boost state. */
    pub mod Boost {
        pub const BoostInfo: u32 = 0;
    }
/** This event SHALL be generated whenever a Boost command is accepted. */
    pub mod BoostStarted {
        pub const BoostInfo: u32 = 0;
    }
}
pub mod ContentLauncher {
    pub mod AdditionalInfoStruct {
        pub const Name: u32 = 0;
        pub const Value: u32 = 1;
    }
    pub mod BrandingInformationStruct {
        pub const ProviderName: u32 = 0;
        pub const Background: u32 = 1;
        pub const Logo: u32 = 2;
        pub const ProgressBar: u32 = 3;
        pub const Splash: u32 = 4;
        pub const WaterMark: u32 = 5;
    }
    pub mod ContentSearchStruct {
        pub const ParameterList: u32 = 0;
    }
    pub mod DimensionStruct {
        pub const Width: u32 = 0;
        pub const Height: u32 = 1;
        pub const Metric: u32 = 2;
    }
    pub mod ParameterStruct {
        pub const Type: u32 = 0;
        pub const Value: u32 = 1;
        pub const ExternalIDList: u32 = 2;
    }
    pub mod PlaybackPreferencesStruct {
        pub const PlaybackPosition: u32 = 0;
        pub const TextTrack: u32 = 1;
        pub const AudioTracks: u32 = 2;
    }
    pub mod StyleInformationStruct {
        pub const ImageURL: u32 = 0;
        pub const Color: u32 = 1;
        pub const Size: u32 = 2;
    }
    pub mod TrackPreferenceStruct {
        pub const LanguageCode: u32 = 0;
        pub const Characteristics: u32 = 1;
        pub const AudioOutputIndex: u32 = 2;
    }
/** Upon receipt, this SHALL launch the specified content with optional search criteria. */
    pub mod LaunchContent {
        pub const Search: u32 = 0;
        pub const AutoPlay: u32 = 1;
        pub const Data: u32 = 2;
        pub const PlaybackPreferences: u32 = 3;
        pub const UseCurrentContext: u32 = 4;
    }
/** Upon receipt, this SHALL launch content from the specified URL. */
    pub mod LaunchURL {
        pub const ContentURL: u32 = 0;
        pub const DisplayString: u32 = 1;
        pub const BrandingInformation: u32 = 2;
        pub const PlaybackPreferences: u32 = 3;
    }
/** This command SHALL be generated in response to LaunchContent command. */
    pub mod LauncherResponse {
        pub const Status: u32 = 0;
        pub const Data: u32 = 1;
    }
}
pub mod GeneralDiagnostics {
    pub mod NetworkInterface {
        pub const Name: u32 = 0;
        pub const IsOperational: u32 = 1;
        pub const OffPremiseServicesReachableIPv4: u32 = 2;
        pub const OffPremiseServicesReachableIPv6: u32 = 3;
        pub const HardwareAddress: u32 = 4;
        pub const IPv4Addresses: u32 = 5;
        pub const IPv6Addresses: u32 = 6;
        pub const Type: u32 = 7;
    }
/** Provide a means for certification tests to trigger some test-plan-specific events */
    pub mod TestEventTrigger {
        pub const EnableKey: u32 = 0;
        pub const EventTrigger: u32 = 1;
    }
/** Response for the TimeSnapshot command. */
    pub mod TimeSnapshotResponse {
        pub const SystemTimeMs: u32 = 0;
        pub const PosixTimeMs: u32 = 1;
    }
/** Request a variable length payload response. */
    pub mod PayloadTestRequest {
        pub const EnableKey: u32 = 0;
        pub const Value: u32 = 1;
        pub const Count: u32 = 2;
    }
/** Response for the PayloadTestRequest command. */
    pub mod PayloadTestResponse {
        pub const Payload: u32 = 0;
    }
/** Indicate a change in the set of hardware faults currently detected by the Node. */
    pub mod HardwareFaultChange {
        pub const Current: u32 = 0;
        pub const Previous: u32 = 1;
    }
/** Indicate a change in the set of radio faults currently detected by the Node. */
    pub mod RadioFaultChange {
        pub const Current: u32 = 0;
        pub const Previous: u32 = 1;
    }
/** Indicate a change in the set of network faults currently detected by the Node. */
    pub mod NetworkFaultChange {
        pub const Current: u32 = 0;
        pub const Previous: u32 = 1;
    }
/** Indicate the reason that caused the device to start-up. */
    pub mod BootReason {
        pub const BootReason: u32 = 0;
    }
}
pub mod ICDManagement {
    pub mod MonitoringRegistrationStruct {
        pub const CheckInNodeID: u32 = 1;
        pub const MonitoredSubject: u32 = 2;
        pub const ClientType: u32 = 4;
    }
/** This command allows a client to register itself with the ICD to be notified when the device is available for communication. */
    pub mod RegisterClient {
        pub const CheckInNodeID: u32 = 0;
        pub const MonitoredSubject: u32 = 1;
        pub const Key: u32 = 2;
        pub const VerificationKey: u32 = 3;
        pub const ClientType: u32 = 4;
    }
/** This command SHALL be sent by the ICD Management Cluster server in response to a successful RegisterClient command. */
    pub mod RegisterClientResponse {
        pub const ICDCounter: u32 = 0;
    }
/** This command allows a client to unregister itself with the ICD. */
    pub mod UnregisterClient {
        pub const CheckInNodeID: u32 = 0;
        pub const VerificationKey: u32 = 1;
    }
/** This command allows a client to request that the server stays in active mode for at least a given time duration (in milliseconds) from when this command is received. */
    pub mod StayActiveRequest {
        pub const StayActiveDuration: u32 = 0;
    }
/** This message SHALL be sent by the ICD in response to the StayActiveRequest command and SHALL contain the computed duration (in milliseconds) that the ICD intends to stay active for. */
    pub mod StayActiveResponse {
        pub const PromisedActiveDuration: u32 = 0;
    }
}
pub mod NetworkCommissioning {
    pub mod NetworkInfoStruct {
        pub const NetworkID: u32 = 0;
        pub const Connected: u32 = 1;
    }
    pub mod ThreadInterfaceScanResultStruct {
        pub const PanId: u32 = 0;
        pub const ExtendedPanId: u32 = 1;
        pub const NetworkName: u32 = 2;
        pub const Channel: u32 = 3;
        pub const Version: u32 = 4;
        pub const ExtendedAddress: u32 = 5;
        pub const RSSI: u32 = 6;
        pub const LQI: u32 = 7;
    }
    pub mod WiFiInterfaceScanResultStruct {
        pub const Security: u32 = 0;
        pub const SSID: u32 = 1;
        pub const BSSID: u32 = 2;
        pub const Channel: u32 = 3;
        pub const WiFiBand: u32 = 4;
        pub const RSSI: u32 = 5;
    }
/** Detemine the set of networks the device sees as available. */
    pub mod ScanNetworks {
        pub const SSID: u32 = 0;
        pub const Breadcrumb: u32 = 1;
    }
/** Relay the set of networks the device sees as available back to the client. */
    pub mod ScanNetworksResponse {
        pub const NetworkingStatus: u32 = 0;
        pub const DebugText: u32 = 1;
        pub const WiFiScanResults: u32 = 2;
        pub const ThreadScanResults: u32 = 3;
    }
/** Add or update the credentials for a given Wi-Fi network. */
    pub mod AddOrUpdateWiFiNetwork {
        pub const SSID: u32 = 0;
        pub const Credentials: u32 = 1;
        pub const Breadcrumb: u32 = 2;
    }
/** Add or update the credentials for a given Thread network. */
    pub mod AddOrUpdateThreadNetwork {
        pub const OperationalDataset: u32 = 0;
        pub const Breadcrumb: u32 = 1;
    }
/** Remove the definition of a given network (including its credentials). */
    pub mod RemoveNetwork {
        pub const NetworkID: u32 = 0;
        pub const Breadcrumb: u32 = 1;
    }
/** Response command for various commands that add/remove/modify network credentials. */
    pub mod NetworkConfigResponse {
        pub const NetworkingStatus: u32 = 0;
        pub const DebugText: u32 = 1;
        pub const NetworkIndex: u32 = 2;
    }
/** Connect to the specified network, using previously-defined credentials. */
    pub mod ConnectNetwork {
        pub const NetworkID: u32 = 0;
        pub const Breadcrumb: u32 = 1;
    }
/** Command that indicates whether we have succcessfully connected to a network. */
    pub mod ConnectNetworkResponse {
        pub const NetworkingStatus: u32 = 0;
        pub const DebugText: u32 = 1;
        pub const ErrorValue: u32 = 2;
    }
/** Modify the order in which networks will be presented in the Networks attribute. */
    pub mod ReorderNetwork {
        pub const NetworkID: u32 = 0;
        pub const NetworkIndex: u32 = 1;
        pub const Breadcrumb: u32 = 2;
    }
}
pub mod TimeSynchronization {
    pub mod DSTOffsetStruct {
        pub const Offset: u32 = 0;
        pub const ValidStarting: u32 = 1;
        pub const ValidUntil: u32 = 2;
    }
    pub mod FabricScopedTrustedTimeSourceStruct {
        pub const NodeID: u32 = 0;
        pub const Endpoint: u32 = 1;
    }
    pub mod TimeZoneStruct {
        pub const Offset: u32 = 0;
        pub const ValidAt: u32 = 1;
        pub const Name: u32 = 2;
    }
    pub mod TrustedTimeSourceStruct {
        pub const FabricIndex: u32 = 0;
        pub const NodeID: u32 = 1;
        pub const Endpoint: u32 = 2;
    }
/** This command is used to set the UTC time of the node. */
    pub mod SetUTCTime {
        pub const UTCTime: u32 = 0;
        pub const Granularity: u32 = 1;
        pub const TimeSource: u32 = 2;
    }
/** This command is used to set the TrustedTimeSource attribute. */
    pub mod SetTrustedTimeSource {
        pub const TrustedTimeSource: u32 = 0;
    }
/** This command is used to set the time zone of the node. */
    pub mod SetTimeZone {
        pub const TimeZone: u32 = 0;
    }
/** THis command is used to report the result of a SetTimeZone command. */
    pub mod SetTimeZoneResponse {
        pub const DSTOffsetRequired: u32 = 0;
    }
/** This command is used to set the DST offsets for a node. */
    pub mod SetDSTOffset {
        pub const DSTOffset: u32 = 0;
    }
/** This command is used to set the DefaultNTP attribute. */
    pub mod SetDefaultNTP {
        pub const DefaultNTP: u32 = 0;
    }
/** This event SHALL be generated when the node starts or stops applying a DST offset. */
    pub mod DSTStatus {
        pub const DSTOffsetActive: u32 = 0;
    }
/** This event SHALL be generated when the node changes its time zone offset or name. */
    pub mod TimeZoneStatus {
        pub const Offset: u32 = 0;
        pub const Name: u32 = 1;
    }
}
pub mod RVCRunMode {
    pub mod ModeOptionStruct {
        pub const Label: u32 = 0;
        pub const Mode: u32 = 1;
        pub const ModeTags: u32 = 2;
    }
    pub mod ModeTagStruct {
        pub const MfgCode: u32 = 0;
        pub const Value: u32 = 1;
    }
/** This command is used to change device modes.
 * On receipt of this command the device SHALL respond with a ChangeToModeResponse command. */
    pub mod ChangeToMode {
        pub const NewMode: u32 = 0;
    }
/** This command is sent by the device on receipt of the ChangeToModeWithStatus command. */
    pub mod ChangeToModeResponse {
        pub const Status: u32 = 0;
        pub const StatusText: u32 = 1;
    }
}
pub mod BooleanState {
/** If this event is supported, it SHALL be generated when the StateValue attribute changes. */
    pub mod StateChange {
        pub const StateValue: u32 = 0;
    }
}
pub mod CommodityPrice {
    pub mod CommodityPriceComponentStruct {
        pub const Price: u32 = 0;
        pub const Source: u32 = 1;
        pub const Description: u32 = 2;
        pub const TariffComponentID: u32 = 3;
    }
    pub mod CommodityPriceStruct {
        pub const PeriodStart: u32 = 0;
        pub const PeriodEnd: u32 = 1;
        pub const Price: u32 = 2;
        pub const PriceLevel: u32 = 3;
        pub const Description: u32 = 4;
        pub const Components: u32 = 5;
    }
/** Upon receipt, this SHALL generate a GetDetailedPrice Response command. */
    pub mod GetDetailedPriceRequest {
        pub const Details: u32 = 0;
    }
/** This command SHALL be generated in response to a GetDetailedPrice Request command. */
    pub mod GetDetailedPriceResponse {
        pub const CurrentPrice: u32 = 0;
    }
/** Upon receipt, this SHALL generate a GetDetailedForecast Response command. */
    pub mod GetDetailedForecastRequest {
        pub const Details: u32 = 0;
    }
/** This command SHALL be generated in response to a GetDetailedForecast Request command. */
    pub mod GetDetailedForecastResponse {
        pub const PriceForecast: u32 = 0;
    }
/** This event SHALL be generated when the value of the CurrentPrice attribute changes. */
    pub mod PriceChange {
        pub const CurrentPrice: u32 = 0;
    }
}
pub mod ApplicationLauncher {
    pub mod ApplicationEPStruct {
        pub const Application: u32 = 0;
        pub const Endpoint: u32 = 1;
    }
    pub mod ApplicationStruct {
        pub const CatalogVendorID: u32 = 0;
        pub const ApplicationID: u32 = 1;
    }
/** Upon receipt of this command, the server SHALL launch the application with optional data. */
    pub mod LaunchApp {
        pub const Application: u32 = 0;
        pub const Data: u32 = 1;
    }
/** Upon receipt of this command, the server SHALL stop the application if it is running. */
    pub mod StopApp {
        pub const Application: u32 = 0;
    }
/** Upon receipt of this command, the server SHALL hide the application. */
    pub mod HideApp {
        pub const Application: u32 = 0;
    }
/** This command SHALL be generated in response to LaunchApp/StopApp/HideApp commands. */
    pub mod LauncherResponse {
        pub const Status: u32 = 0;
        pub const Data: u32 = 1;
    }
}
pub mod ThreadNetworkDiagnostics {
    pub mod NeighborTableStruct {
        pub const ExtAddress: u32 = 0;
        pub const Age: u32 = 1;
        pub const Rloc16: u32 = 2;
        pub const LinkFrameCounter: u32 = 3;
        pub const MleFrameCounter: u32 = 4;
        pub const LQI: u32 = 5;
        pub const AverageRssi: u32 = 6;
        pub const LastRssi: u32 = 7;
        pub const FrameErrorRate: u32 = 8;
        pub const MessageErrorRate: u32 = 9;
        pub const RxOnWhenIdle: u32 = 10;
        pub const FullThreadDevice: u32 = 11;
        pub const FullNetworkData: u32 = 12;
        pub const IsChild: u32 = 13;
    }
    pub mod OperationalDatasetComponents {
        pub const ActiveTimestampPresent: u32 = 0;
        pub const PendingTimestampPresent: u32 = 1;
        pub const MasterKeyPresent: u32 = 2;
        pub const NetworkNamePresent: u32 = 3;
        pub const ExtendedPanIdPresent: u32 = 4;
        pub const MeshLocalPrefixPresent: u32 = 5;
        pub const DelayPresent: u32 = 6;
        pub const PanIdPresent: u32 = 7;
        pub const ChannelPresent: u32 = 8;
        pub const PskcPresent: u32 = 9;
        pub const SecurityPolicyPresent: u32 = 10;
        pub const ChannelMaskPresent: u32 = 11;
    }
    pub mod RouteTableStruct {
        pub const ExtAddress: u32 = 0;
        pub const Rloc16: u32 = 1;
        pub const RouterId: u32 = 2;
        pub const NextHop: u32 = 3;
        pub const PathCost: u32 = 4;
        pub const LQIIn: u32 = 5;
        pub const LQIOut: u32 = 6;
        pub const Age: u32 = 7;
        pub const Allocated: u32 = 8;
        pub const LinkEstablished: u32 = 9;
    }
    pub mod SecurityPolicy {
        pub const RotationTime: u32 = 0;
        pub const Flags: u32 = 1;
    }
/** The ConnectionStatus Event SHALL indicate that a Node's connection status to a Thread network has changed. */
    pub mod ConnectionStatus {
        pub const ConnectionStatus: u32 = 0;
    }
/** The NetworkFaultChange Event SHALL indicate a change in the set of network faults currently detected by the Node. */
    pub mod NetworkFaultChange {
        pub const Current: u32 = 0;
        pub const Previous: u32 = 1;
    }
}
pub mod Actions {
    pub mod ActionStruct {
        pub const ActionID: u32 = 0;
        pub const Name: u32 = 1;
        pub const Type: u32 = 2;
        pub const EndpointListID: u32 = 3;
        pub const SupportedCommands: u32 = 4;
        pub const State: u32 = 5;
    }
    pub mod EndpointListStruct {
        pub const EndpointListID: u32 = 0;
        pub const Name: u32 = 1;
        pub const Type: u32 = 2;
        pub const Endpoints: u32 = 3;
    }
/** This command is used to trigger an instantaneous action. */
    pub mod InstantAction {
        pub const ActionID: u32 = 0;
        pub const InvokeID: u32 = 1;
    }
/** This command is used to trigger an instantaneous action with a transition over a given time. */
    pub mod InstantActionWithTransition {
        pub const ActionID: u32 = 0;
        pub const InvokeID: u32 = 1;
        pub const TransitionTime: u32 = 2;
    }
/** This command is used to trigger the commencement of an action. */
    pub mod StartAction {
        pub const ActionID: u32 = 0;
        pub const InvokeID: u32 = 1;
    }
/** This command is used to trigger the commencement of an action with a duration. */
    pub mod StartActionWithDuration {
        pub const ActionID: u32 = 0;
        pub const InvokeID: u32 = 1;
        pub const Duration: u32 = 2;
    }
/** This command is used to stop an action. */
    pub mod StopAction {
        pub const ActionID: u32 = 0;
        pub const InvokeID: u32 = 1;
    }
/** This command is used to pause an action. */
    pub mod PauseAction {
        pub const ActionID: u32 = 0;
        pub const InvokeID: u32 = 1;
    }
/** This command is used to pause an action with a duration. */
    pub mod PauseActionWithDuration {
        pub const ActionID: u32 = 0;
        pub const InvokeID: u32 = 1;
        pub const Duration: u32 = 2;
    }
/** This command is used to resume an action. */
    pub mod ResumeAction {
        pub const ActionID: u32 = 0;
        pub const InvokeID: u32 = 1;
    }
/** This command is used to enable an action. */
    pub mod EnableAction {
        pub const ActionID: u32 = 0;
        pub const InvokeID: u32 = 1;
    }
/** This command is used to enable an action with a duration. */
    pub mod EnableActionWithDuration {
        pub const ActionID: u32 = 0;
        pub const InvokeID: u32 = 1;
        pub const Duration: u32 = 2;
    }
/** This command is used to disable an action. */
    pub mod DisableAction {
        pub const ActionID: u32 = 0;
        pub const InvokeID: u32 = 1;
    }
/** This command is used to disable an action with a duration. */
    pub mod DisableActionWithDuration {
        pub const ActionID: u32 = 0;
        pub const InvokeID: u32 = 1;
        pub const Duration: u32 = 2;
    }
/** This event SHALL be generated when there is a change in the State of an ActionID during the execution of an action and the most recent command using that ActionID used an InvokeID data field. */
    pub mod StateChanged {
        pub const ActionID: u32 = 0;
        pub const InvokeID: u32 = 1;
        pub const NewState: u32 = 2;
    }
/** This event SHALL be generated when there is some error which prevents the action from its normal planned execution and the most recent command using that ActionID used an InvokeID data field. */
    pub mod ActionFailed {
        pub const ActionID: u32 = 0;
        pub const InvokeID: u32 = 1;
        pub const NewState: u32 = 2;
        pub const Error: u32 = 3;
    }
}
pub mod DiagnosticLogs {
/** Reception of this command starts the process of retrieving diagnostic logs from a Node. */
    pub mod RetrieveLogsRequest {
        pub const Intent: u32 = 0;
        pub const RequestedProtocol: u32 = 1;
        pub const TransferFileDesignator: u32 = 2;
    }
/** This SHALL be generated as a response to the RetrieveLogsRequest. */
    pub mod RetrieveLogsResponse {
        pub const Status: u32 = 0;
        pub const LogContent: u32 = 1;
        pub const UTCTimeStamp: u32 = 2;
        pub const TimeSinceBoot: u32 = 3;
    }
}
pub mod GroupKeyManagement {
    pub mod GroupInfoMapStruct {
        pub const GroupId: u32 = 1;
        pub const Endpoints: u32 = 2;
        pub const GroupName: u32 = 3;
    }
    pub mod GroupKeyMapStruct {
        pub const GroupId: u32 = 1;
        pub const GroupKeySetID: u32 = 2;
    }
    pub mod GroupKeySetStruct {
        pub const GroupKeySetID: u32 = 0;
        pub const GroupKeySecurityPolicy: u32 = 1;
        pub const EpochKey0: u32 = 2;
        pub const EpochStartTime0: u32 = 3;
        pub const EpochKey1: u32 = 4;
        pub const EpochStartTime1: u32 = 5;
        pub const EpochKey2: u32 = 6;
        pub const EpochStartTime2: u32 = 7;
        pub const GroupKeyMulticastPolicy: u32 = 8;
    }
/** Write a new set of keys for the given key set id. */
    pub mod KeySetWrite {
        pub const GroupKeySet: u32 = 0;
    }
/** Read the keys for a given key set id. */
    pub mod KeySetRead {
        pub const GroupKeySetID: u32 = 0;
    }
/** Response to KeySetRead */
    pub mod KeySetReadResponse {
        pub const GroupKeySet: u32 = 0;
    }
/** Revoke a Root Key from a Group */
    pub mod KeySetRemove {
        pub const GroupKeySetID: u32 = 0;
    }
/** Reseponse to KeySetReadAllIndices */
    pub mod KeySetReadAllIndicesResponse {
        pub const GroupKeySetIDs: u32 = 0;
    }
}
pub mod ApplicationBasic {
    pub mod ApplicationStruct {
        pub const CatalogVendorID: u32 = 0;
        pub const ApplicationID: u32 = 1;
    }
}
pub mod LevelControl {
/** This command will move the device to the specified level. */
    pub mod MoveToLevel {
        pub const Level: u32 = 0;
        pub const TransitionTime: u32 = 1;
        pub const OptionsMask: u32 = 2;
        pub const OptionsOverride: u32 = 3;
    }
/** This command will move the device using the specified values. */
    pub mod Move {
        pub const MoveMode: u32 = 0;
        pub const Rate: u32 = 1;
        pub const OptionsMask: u32 = 2;
        pub const OptionsOverride: u32 = 3;
    }
/** This command will do a relative step change of the device using the specified values. */
    pub mod Step {
        pub const StepMode: u32 = 0;
        pub const StepSize: u32 = 1;
        pub const TransitionTime: u32 = 2;
        pub const OptionsMask: u32 = 3;
        pub const OptionsOverride: u32 = 4;
    }
/** This command will stop the actions of various other commands that are still in progress. */
    pub mod Stop {
        pub const OptionsMask: u32 = 0;
        pub const OptionsOverride: u32 = 1;
    }
/** This command will move the device to the specified level. */
    pub mod MoveToLevelWithOnOff {
        pub const Level: u32 = 0;
        pub const TransitionTime: u32 = 1;
        pub const OptionsMask: u32 = 2;
        pub const OptionsOverride: u32 = 3;
    }
/** This command will move the device using the specified values. */
    pub mod MoveWithOnOff {
        pub const MoveMode: u32 = 0;
        pub const Rate: u32 = 1;
        pub const OptionsMask: u32 = 2;
        pub const OptionsOverride: u32 = 3;
    }
/** This command will do a relative step change of the device using the specified values. */
    pub mod StepWithOnOff {
        pub const StepMode: u32 = 0;
        pub const StepSize: u32 = 1;
        pub const TransitionTime: u32 = 2;
        pub const OptionsMask: u32 = 3;
        pub const OptionsOverride: u32 = 4;
    }
/** This command will stop the actions of various other commands that are still in progress. */
    pub mod StopWithOnOff {
        pub const OptionsMask: u32 = 0;
        pub const OptionsOverride: u32 = 1;
    }
/** This command will cause the device to change the current frequency to the requested value. */
    pub mod MoveToClosestFrequency {
        pub const Frequency: u32 = 0;
    }
}
pub mod EnergyEVSE {
    pub mod ChargingTargetScheduleStruct {
        pub const DayOfWeekForSequence: u32 = 0;
        pub const ChargingTargets: u32 = 1;
    }
    pub mod ChargingTargetStruct {
        pub const TargetTimeMinutesPastMidnight: u32 = 0;
        pub const TargetSoC: u32 = 1;
        pub const AddedEnergy: u32 = 2;
    }
/** The GetTargetsResponse is sent in response to the GetTargets Command. */
    pub mod GetTargetsResponse {
        pub const ChargingTargetSchedules: u32 = 0;
    }
/** This command allows a client to enable the EVSE to charge an EV, and to provide or update the maximum and minimum charge current. */
    pub mod EnableCharging {
        pub const ChargingEnabledUntil: u32 = 0;
        pub const MinimumChargeCurrent: u32 = 1;
        pub const MaximumChargeCurrent: u32 = 2;
    }
/** Upon receipt, this SHALL allow a client to enable the discharge of an EV, and to provide or update the maximum discharge current. */
    pub mod EnableDischarging {
        pub const DischargingEnabledUntil: u32 = 0;
        pub const MaximumDischargeCurrent: u32 = 1;
    }
/** Allows a client to set the user specified charging targets. */
    pub mod SetTargets {
        pub const ChargingTargetSchedules: u32 = 0;
    }
/** This event SHALL be generated when the EV is plugged in. */
    pub mod EVConnected {
        pub const SessionID: u32 = 0;
    }
/** This event SHALL be generated when the EV is unplugged or not detected (having been previously plugged in). */
    pub mod EVNotDetected {
        pub const SessionID: u32 = 0;
        pub const State: u32 = 1;
        pub const SessionDuration: u32 = 2;
        pub const SessionEnergyCharged: u32 = 3;
        pub const SessionEnergyDischarged: u32 = 4;
    }
/** This event SHALL be generated whenever the EV starts charging or discharging, except when an EV has switched between charging and discharging under the control of the PowerAdjustment feature of the Device Energy Management cluster of the associated Device Energy Management device. */
    pub mod EnergyTransferStarted {
        pub const SessionID: u32 = 0;
        pub const State: u32 = 1;
        pub const MaximumCurrent: u32 = 2;
        pub const MaximumDischargeCurrent: u32 = 3;
    }
/** This event SHALL be generated whenever the EV stops charging or discharging, except when an EV has switched between charging and discharging under the control of the PowerAdjustment feature of the Device Energy Management cluster of the associated Device Energy Management device. */
    pub mod EnergyTransferStopped {
        pub const SessionID: u32 = 0;
        pub const State: u32 = 1;
        pub const Reason: u32 = 2;
        pub const EnergyTransferred: u32 = 4;
        pub const EnergyDischarged: u32 = 5;
    }
/** If the EVSE detects a fault it SHALL generate a Fault Event. */
    pub mod Fault {
        pub const SessionID: u32 = 0;
        pub const State: u32 = 1;
        pub const FaultStatePreviousState: u32 = 2;
        pub const FaultStateCurrentState: u32 = 4;
    }
/** This event SHALL be generated when a RFID card has been read. */
    pub mod RFID {
        pub const UID: u32 = 0;
    }
}
pub mod ContentAppObserver {
/** Upon receipt, the data field MAY be parsed and interpreted. Message encoding is specific to the Content App. A Content App MAY when possible read attributes from the Basic Information Cluster on the Observer and use this to determine the Message encoding. */
    pub mod ContentAppMessage {
        pub const Data: u32 = 0;
        pub const EncodingHint: u32 = 1;
    }
/** This command SHALL be generated in response to ContentAppMessage command. */
    pub mod ContentAppMessageResponse {
        pub const Status: u32 = 0;
        pub const Data: u32 = 1;
        pub const EncodingHint: u32 = 2;
    }
}
pub mod BridgedDeviceBasicInformation {
    pub mod CapabilityMinimaStruct {
        pub const CaseSessionsPerFabric: u32 = 0;
        pub const SubscriptionsPerFabric: u32 = 1;
    }
    pub mod ProductAppearanceStruct {
        pub const Finish: u32 = 0;
        pub const PrimaryColor: u32 = 1;
    }
/** Upon receipt, the server SHALL attempt to keep the bridged device active for the duration specified by the command, when the device is next active. */
    pub mod KeepActive {
        pub const StayActiveDuration: u32 = 0;
        pub const TimeoutMs: u32 = 1;
    }
/** The StartUp event SHALL be generated by a Node as soon as reasonable after completing a boot or reboot process. */
    pub mod StartUp {
        pub const SoftwareVersion: u32 = 0;
    }
/** The Leave event SHOULD be generated by the bridge when it detects that the associated device has left the non-Matter network. */
    pub mod Leave {
        pub const FabricIndex: u32 = 0;
    }
/** This event SHALL be generated when there is a change in the Reachable attribute. */
    pub mod ReachableChanged {
        pub const ReachableNewValue: u32 = 0;
    }
/** This event (when supported) SHALL be generated the next time a bridged device becomes active after a KeepActive command is received. */
    pub mod ActiveChanged {
        pub const PromisedActiveDuration: u32 = 0;
    }
}
pub mod SoftwareDiagnostics {
    pub mod ThreadMetricsStruct {
        pub const ID: u32 = 0;
        pub const Name: u32 = 1;
        pub const StackFreeCurrent: u32 = 2;
        pub const StackFreeMinimum: u32 = 3;
        pub const StackSize: u32 = 4;
    }
/** This Event SHALL be generated when a software fault occurs on the Node. */
    pub mod SoftwareFault {
        pub const ID: u32 = 0;
        pub const Name: u32 = 1;
        pub const FaultRecording: u32 = 2;
    }
}
pub mod DishwasherMode {
    pub mod ModeOptionStruct {
        pub const Label: u32 = 0;
        pub const Mode: u32 = 1;
        pub const ModeTags: u32 = 2;
    }
    pub mod ModeTagStruct {
        pub const MfgCode: u32 = 0;
        pub const Value: u32 = 1;
    }
/** This command is used to change device modes.
 * On receipt of this command the device SHALL respond with a ChangeToModeResponse command. */
    pub mod ChangeToMode {
        pub const NewMode: u32 = 0;
    }
/** This command is sent by the device on receipt of the ChangeToModeWithStatus command. */
    pub mod ChangeToModeResponse {
        pub const Status: u32 = 0;
        pub const StatusText: u32 = 1;
    }
}
pub mod AdministratorCommissioning {
/** This command is used by a current Administrator to instruct a Node to go into commissioning mode. */
    pub mod OpenCommissioningWindow {
        pub const CommissioningTimeout: u32 = 0;
        pub const PAKEPasscodeVerifier: u32 = 1;
        pub const Discriminator: u32 = 2;
        pub const Iterations: u32 = 3;
        pub const Salt: u32 = 4;
    }
/** This command MAY be used by a current Administrator to instruct a Node to go into commissioning mode, if the node supports the Basic Commissioning Method. */
    pub mod OpenBasicCommissioningWindow {
        pub const CommissioningTimeout: u32 = 0;
    }
}
pub mod ZoneManagement {
    pub mod TwoDCartesianVertexStruct {
        pub const X: u32 = 0;
        pub const Y: u32 = 1;
    }
    pub mod TwoDCartesianZoneStruct {
        pub const Name: u32 = 0;
        pub const Use: u32 = 1;
        pub const Vertices: u32 = 2;
        pub const Color: u32 = 3;
    }
    pub mod ZoneInformationStruct {
        pub const ZoneID: u32 = 0;
        pub const ZoneType: u32 = 1;
        pub const ZoneSource: u32 = 2;
        pub const TwoDCartesianZone: u32 = 3;
    }
    pub mod ZoneTriggerControlStruct {
        pub const ZoneID: u32 = 0;
        pub const InitialDuration: u32 = 1;
        pub const AugmentationDuration: u32 = 2;
        pub const MaxDuration: u32 = 3;
        pub const BlindDuration: u32 = 4;
        pub const Sensitivity: u32 = 5;
    }
/** This command SHALL create and store a TwoD Cartesian Zone. */
    pub mod CreateTwoDCartesianZone {
        pub const Zone: u32 = 0;
    }
/** This command SHALL be generated in response to a CreateTwoDCartesianZone command. */
    pub mod CreateTwoDCartesianZoneResponse {
        pub const ZoneID: u32 = 0;
    }
/** The UpdateTwoDCartesianZone SHALL update a stored TwoD Cartesian Zone. */
    pub mod UpdateTwoDCartesianZone {
        pub const ZoneID: u32 = 0;
        pub const Zone: u32 = 1;
    }
/** This command SHALL remove the user-defined Zone indicated by ZoneID. */
    pub mod RemoveZone {
        pub const ZoneID: u32 = 0;
    }
/** This command is used to create or update a Trigger for the specified motion Zone. */
    pub mod CreateOrUpdateTrigger {
        pub const Trigger: u32 = 0;
    }
/** This command SHALL remove the Trigger for the provided ZoneID. */
    pub mod RemoveTrigger {
        pub const ZoneID: u32 = 0;
    }
/** This event SHALL be generated when a Zone is first triggered. */
    pub mod ZoneTriggered {
        pub const Zone: u32 = 0;
        pub const Reason: u32 = 1;
    }
/** This event SHALL be generated when either the TriggerDetectedDuration value is exceeded by the TimeSinceInitialTrigger value or the MaxDuration value is exceeded by the TimeSinceInitialTrigger value, as described in xrefstyle=full. */
    pub mod ZoneStopped {
        pub const Zone: u32 = 0;
        pub const Reason: u32 = 1;
    }
}
pub mod JointFabricDatastore {
    pub mod DatastoreACLEntryStruct {
        pub const NodeID: u32 = 0;
        pub const ListID: u32 = 1;
        pub const ACLEntry: u32 = 2;
        pub const StatusEntry: u32 = 3;
    }
    pub mod DatastoreAccessControlEntryStruct {
        pub const Privilege: u32 = 1;
        pub const AuthMode: u32 = 2;
        pub const Subjects: u32 = 3;
        pub const Targets: u32 = 4;
    }
    pub mod DatastoreAccessControlTargetStruct {
        pub const Cluster: u32 = 0;
        pub const Endpoint: u32 = 1;
        pub const DeviceType: u32 = 2;
    }
    pub mod DatastoreAdministratorInformationEntryStruct {
        pub const NodeID: u32 = 1;
        pub const FriendlyName: u32 = 2;
        pub const VendorID: u32 = 3;
        pub const ICAC: u32 = 4;
    }
    pub mod DatastoreBindingTargetStruct {
        pub const Node: u32 = 1;
        pub const Group: u32 = 2;
        pub const Endpoint: u32 = 3;
        pub const Cluster: u32 = 4;
    }
    pub mod DatastoreEndpointBindingEntryStruct {
        pub const NodeID: u32 = 0;
        pub const EndpointID: u32 = 1;
        pub const ListID: u32 = 2;
        pub const Binding: u32 = 3;
        pub const StatusEntry: u32 = 4;
    }
    pub mod DatastoreEndpointEntryStruct {
        pub const EndpointID: u32 = 0;
        pub const NodeID: u32 = 1;
        pub const FriendlyName: u32 = 2;
        pub const StatusEntry: u32 = 3;
    }
    pub mod DatastoreEndpointGroupIDEntryStruct {
        pub const NodeID: u32 = 0;
        pub const EndpointID: u32 = 1;
        pub const GroupID: u32 = 2;
        pub const StatusEntry: u32 = 3;
    }
    pub mod DatastoreGroupInformationEntryStruct {
        pub const GroupID: u32 = 0;
        pub const FriendlyName: u32 = 1;
        pub const GroupKeySetID: u32 = 2;
        pub const GroupCAT: u32 = 3;
        pub const GroupCATVersion: u32 = 4;
        pub const GroupPermission: u32 = 5;
    }
    pub mod DatastoreGroupKeySetStruct {
        pub const GroupKeySetID: u32 = 0;
        pub const GroupKeySecurityPolicy: u32 = 1;
        pub const EpochKey0: u32 = 2;
        pub const EpochStartTime0: u32 = 3;
        pub const EpochKey1: u32 = 4;
        pub const EpochStartTime1: u32 = 5;
        pub const EpochKey2: u32 = 6;
        pub const EpochStartTime2: u32 = 7;
        pub const GroupKeyMulticastPolicy: u32 = 8;
    }
    pub mod DatastoreNodeInformationEntryStruct {
        pub const NodeID: u32 = 1;
        pub const FriendlyName: u32 = 2;
        pub const CommissioningStatusEntry: u32 = 3;
    }
    pub mod DatastoreNodeKeySetEntryStruct {
        pub const NodeID: u32 = 0;
        pub const GroupKeySetID: u32 = 1;
        pub const StatusEntry: u32 = 2;
    }
    pub mod DatastoreStatusEntryStruct {
        pub const State: u32 = 0;
        pub const UpdateTimestamp: u32 = 1;
        pub const FailureCode: u32 = 2;
    }
/** This command SHALL be used to add a KeySet to the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod AddKeySet {
        pub const GroupKeySet: u32 = 0;
    }
/** This command SHALL be used to update a KeySet in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod UpdateKeySet {
        pub const GroupKeySet: u32 = 0;
    }
/** This command SHALL be used to remove a KeySet from the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod RemoveKeySet {
        pub const GroupKeySetID: u32 = 0;
    }
/** This command SHALL be used to add a group to the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod AddGroup {
        pub const GroupID: u32 = 0;
        pub const FriendlyName: u32 = 1;
        pub const GroupKeySetID: u32 = 2;
        pub const GroupCAT: u32 = 3;
        pub const GroupCATVersion: u32 = 4;
        pub const GroupPermission: u32 = 5;
    }
/** This command SHALL be used to update a group in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod UpdateGroup {
        pub const GroupID: u32 = 0;
        pub const FriendlyName: u32 = 1;
        pub const GroupKeySetID: u32 = 2;
        pub const GroupCAT: u32 = 3;
        pub const GroupCATVersion: u32 = 4;
        pub const GroupPermission: u32 = 5;
    }
/** This command SHALL be used to remove a group from the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod RemoveGroup {
        pub const GroupID: u32 = 0;
    }
/** This command SHALL be used to add an admin to the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod AddAdmin {
        pub const NodeID: u32 = 1;
        pub const FriendlyName: u32 = 2;
        pub const VendorID: u32 = 3;
        pub const ICAC: u32 = 4;
    }
/** This command SHALL be used to update an admin in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod UpdateAdmin {
        pub const NodeID: u32 = 0;
        pub const FriendlyName: u32 = 1;
        pub const ICAC: u32 = 2;
    }
/** This command SHALL be used to remove an admin from the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod RemoveAdmin {
        pub const NodeID: u32 = 0;
    }
/** The command SHALL be used to add a node to the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod AddPendingNode {
        pub const NodeID: u32 = 0;
        pub const FriendlyName: u32 = 1;
    }
/** The command SHALL be used to request that Datastore information relating to a Node of the accessing fabric is refreshed. */
    pub mod RefreshNode {
        pub const NodeID: u32 = 0;
    }
/** The command SHALL be used to update the friendly name for a node in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod UpdateNode {
        pub const NodeID: u32 = 0;
        pub const FriendlyName: u32 = 1;
    }
/** This command SHALL be used to remove a node from the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod RemoveNode {
        pub const NodeID: u32 = 0;
    }
/** This command SHALL be used to update the state of an endpoint for a node in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod UpdateEndpointForNode {
        pub const EndpointID: u32 = 0;
        pub const NodeID: u32 = 1;
        pub const FriendlyName: u32 = 2;
    }
/** This command SHALL be used to add a Group ID to an endpoint for a node in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod AddGroupIDToEndpointForNode {
        pub const NodeID: u32 = 0;
        pub const EndpointID: u32 = 1;
        pub const GroupID: u32 = 2;
    }
/** This command SHALL be used to remove a Group ID from an endpoint for a node in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod RemoveGroupIDFromEndpointForNode {
        pub const NodeID: u32 = 0;
        pub const EndpointID: u32 = 1;
        pub const GroupID: u32 = 2;
    }
/** This command SHALL be used to add a binding to an endpoint for a node in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod AddBindingToEndpointForNode {
        pub const NodeID: u32 = 0;
        pub const EndpointID: u32 = 1;
        pub const Binding: u32 = 2;
    }
/** This command SHALL be used to remove a binding from an endpoint for a node in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod RemoveBindingFromEndpointForNode {
        pub const ListID: u32 = 0;
        pub const EndpointID: u32 = 1;
        pub const NodeID: u32 = 2;
    }
/** This command SHALL be used to add an ACL to a node in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod AddACLToNode {
        pub const NodeID: u32 = 0;
        pub const ACLEntry: u32 = 1;
    }
/** This command SHALL be used to remove an ACL from a node in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub mod RemoveACLFromNode {
        pub const ListID: u32 = 0;
        pub const NodeID: u32 = 1;
    }
}
pub mod OperationalState {
    pub mod ErrorStateStruct {
        pub const ErrorStateID: u32 = 0;
        pub const ErrorStateLabel: u32 = 1;
        pub const ErrorStateDetails: u32 = 2;
    }
    pub mod OperationalStateStruct {
        pub const OperationalStateID: u32 = 0;
        pub const OperationalStateLabel: u32 = 1;
    }
/** This command SHALL be generated in response to any of the Start, Stop, Pause, or Resume commands. */
    pub mod OperationalCommandResponse {
        pub const CommandResponseState: u32 = 0;
    }
/** OperationalError */
    pub mod OperationalError {
        pub const ErrorState: u32 = 0;
    }
/** OperationCompletion */
    pub mod OperationCompletion {
        pub const CompletionErrorCode: u32 = 0;
        pub const TotalOperationalTime: u32 = 1;
        pub const PausedTime: u32 = 2;
    }
}
pub mod MicrowaveOvenMode {
    pub mod ModeOptionStruct {
        pub const Label: u32 = 0;
        pub const Mode: u32 = 1;
        pub const ModeTags: u32 = 2;
    }
    pub mod ModeTagStruct {
        pub const MfgCode: u32 = 0;
        pub const Value: u32 = 1;
    }
    pub mod ChangeToMode {
        pub const NewMode: u32 = 0;
    }
    pub mod ChangeToModeResponse {
        pub const Status: u32 = 0;
        pub const StatusText: u32 = 1;
    }
}
pub mod CommissionerControl {
/** This command is sent by a client to request approval for a future CommissionNode call. */
    pub mod RequestCommissioningApproval {
        pub const RequestID: u32 = 0;
        pub const VendorID: u32 = 1;
        pub const ProductID: u32 = 2;
        pub const Label: u32 = 3;
    }
/** This command is sent by a client to request that the server begins commissioning a previously approved request. */
    pub mod CommissionNode {
        pub const RequestID: u32 = 0;
        pub const ResponseTimeoutSeconds: u32 = 1;
    }
/** When received within the timeout specified by ResponseTimeoutSeconds in the CommissionNode command, the client SHALL open a commissioning window on a node which matches the VendorID and ProductID provided in the associated RequestCommissioningApproval command. */
    pub mod ReverseOpenCommissioningWindow {
        pub const CommissioningTimeout: u32 = 0;
        pub const PAKEPasscodeVerifier: u32 = 1;
        pub const Discriminator: u32 = 2;
        pub const Iterations: u32 = 3;
        pub const Salt: u32 = 4;
    }
/** This event SHALL be generated by the server following a RequestCommissioningApproval command which the server responded to with SUCCESS. */
    pub mod CommissioningRequestResult {
        pub const RequestID: u32 = 0;
        pub const ClientNodeID: u32 = 1;
        pub const StatusCode: u32 = 2;
    }
}
pub mod ModeSelect {
    pub mod ModeOptionStruct {
        pub const Label: u32 = 0;
        pub const Mode: u32 = 1;
        pub const SemanticTags: u32 = 2;
    }
    pub mod SemanticTagStruct {
        pub const MfgCode: u32 = 0;
        pub const Value: u32 = 1;
    }
/** On receipt of this command, if the NewMode field indicates a valid mode transition within the supported list, the server SHALL set the CurrentMode attribute to the NewMode value, otherwise, the server SHALL respond with an INVALID_COMMAND status response. */
    pub mod ChangeToMode {
        pub const NewMode: u32 = 0;
    }
}
pub mod PushAVStreamTransport {
    pub mod AudioStreamStruct {
        pub const AudioStreamName: u32 = 0;
        pub const AudioStreamID: u32 = 1;
    }
    pub mod CMAFContainerOptionsStruct {
        pub const CMAFInterface: u32 = 0;
        pub const SegmentDuration: u32 = 1;
        pub const ChunkDuration: u32 = 2;
        pub const SessionGroup: u32 = 3;
        pub const TrackName: u32 = 4;
        pub const CENCKey: u32 = 5;
        pub const CENCKeyID: u32 = 6;
        pub const MetadataEnabled: u32 = 7;
    }
    pub mod ContainerOptionsStruct {
        pub const ContainerType: u32 = 0;
        pub const CMAFContainerOptions: u32 = 1;
    }
    pub mod SupportedFormatStruct {
        pub const ContainerFormat: u32 = 0;
        pub const IngestMethod: u32 = 1;
    }
    pub mod TransportConfigurationStruct {
        pub const ConnectionID: u32 = 0;
        pub const TransportStatus: u32 = 1;
        pub const TransportOptions: u32 = 2;
    }
    pub mod TransportMotionTriggerTimeControlStruct {
        pub const InitialDuration: u32 = 0;
        pub const AugmentationDuration: u32 = 1;
        pub const MaxDuration: u32 = 2;
        pub const BlindDuration: u32 = 3;
    }
    pub mod TransportOptionsStruct {
        pub const StreamUsage: u32 = 0;
        pub const VideoStreamID: u32 = 1;
        pub const AudioStreamID: u32 = 2;
        pub const TLSEndpointID: u32 = 3;
        pub const URL: u32 = 4;
        pub const TriggerOptions: u32 = 5;
        pub const IngestMethod: u32 = 6;
        pub const ContainerOptions: u32 = 7;
        pub const ExpiryTime: u32 = 8;
        pub const VideoStreams: u32 = 9;
        pub const AudioStreams: u32 = 10;
    }
    pub mod TransportTriggerOptionsStruct {
        pub const TriggerType: u32 = 0;
        pub const MotionZones: u32 = 1;
        pub const MotionSensitivity: u32 = 2;
        pub const MotionTimeControl: u32 = 3;
        pub const MaxPreRollLen: u32 = 4;
    }
    pub mod TransportZoneOptionsStruct {
        pub const Zone: u32 = 0;
        pub const Sensitivity: u32 = 1;
    }
    pub mod VideoStreamStruct {
        pub const VideoStreamName: u32 = 0;
        pub const VideoStreamID: u32 = 1;
    }
/** This command SHALL allocate a transport and return a PushTransportConnectionID. */
    pub mod AllocatePushTransport {
        pub const TransportOptions: u32 = 0;
    }
/** This command SHALL be generated in response to a successful AllocatePushTransport command. */
    pub mod AllocatePushTransportResponse {
        pub const TransportConfiguration: u32 = 0;
    }
/** This command SHALL be generated to request the Node deallocates the specified transport. */
    pub mod DeallocatePushTransport {
        pub const ConnectionID: u32 = 0;
    }
/** This command is used to request the Node modifies the configuration of the specified push transport. */
    pub mod ModifyPushTransport {
        pub const ConnectionID: u32 = 0;
        pub const TransportOptions: u32 = 1;
    }
/** This command SHALL be generated to request the Node modifies the Transport Status of a specified transport or all transports. */
    pub mod SetTransportStatus {
        pub const ConnectionID: u32 = 0;
        pub const TransportStatus: u32 = 1;
    }
/** This command SHALL be generated to request the Node to manually start the specified push transport. */
    pub mod ManuallyTriggerTransport {
        pub const ConnectionID: u32 = 0;
        pub const ActivationReason: u32 = 1;
        pub const TimeControl: u32 = 2;
        pub const UserDefined: u32 = 3;
    }
/** This command SHALL return the Transport Configuration for the specified push transport or all allocated transports for the fabric if null. */
    pub mod FindTransport {
        pub const ConnectionID: u32 = 0;
    }
/** This command SHALL be generated in response to a successful FindTransport command. */
    pub mod FindTransportResponse {
        pub const TransportConfigurations: u32 = 0;
    }
/** This event SHALL indicate a push transport transmission has begun. */
    pub mod PushTransportBegin {
        pub const ConnectionID: u32 = 0;
        pub const TriggerType: u32 = 1;
        pub const ActivationReason: u32 = 2;
        pub const ContainerType: u32 = 3;
        pub const CMAFSessionNumber: u32 = 4;
        pub const VendorSpecificContext: u32 = 5;
    }
/** This event SHALL indicate a push transport upload of the indicated recording has completed. */
    pub mod PushTransportEnd {
        pub const ConnectionID: u32 = 0;
        pub const ContainerType: u32 = 1;
        pub const CMAFSessionNumber: u32 = 2;
    }
}
pub mod AudioOutput {
    pub mod OutputInfoStruct {
        pub const Index: u32 = 0;
        pub const OutputType: u32 = 1;
        pub const Name: u32 = 2;
    }
/** Upon receipt, this SHALL change the output on the device to the output at a specific index in the Output List. */
    pub mod SelectOutput {
        pub const Index: u32 = 0;
    }
/** Upon receipt, this SHALL rename the output at a specific index in the Output List. */
    pub mod RenameOutput {
        pub const Index: u32 = 0;
        pub const Name: u32 = 1;
    }
}
pub mod OnOff {
/** The OffWithEffect command allows devices to be turned off using enhanced ways of fading. */
    pub mod OffWithEffect {
        pub const EffectIdentifier: u32 = 0;
        pub const EffectVariant: u32 = 1;
    }
/** This command allows devices to be turned on for a specific duration with a guarded off duration so that SHOULD the device be subsequently turned off, further OnWithTimedOff commands, received during this time, are prevented from turning the devices back on. */
    pub mod OnWithTimedOff {
        pub const OnOffControl: u32 = 0;
        pub const OnTime: u32 = 1;
        pub const OffWaitTime: u32 = 2;
    }
}
pub mod ColorControl {
/** Move to specified hue. */
    pub mod MoveToHue {
        pub const Hue: u32 = 0;
        pub const Direction: u32 = 1;
        pub const TransitionTime: u32 = 2;
        pub const OptionsMask: u32 = 3;
        pub const OptionsOverride: u32 = 4;
    }
/** Move hue up or down at specified rate. */
    pub mod MoveHue {
        pub const MoveMode: u32 = 0;
        pub const Rate: u32 = 1;
        pub const OptionsMask: u32 = 2;
        pub const OptionsOverride: u32 = 3;
    }
/** Step hue up or down by specified size at specified rate. */
    pub mod StepHue {
        pub const StepMode: u32 = 0;
        pub const StepSize: u32 = 1;
        pub const TransitionTime: u32 = 2;
        pub const OptionsMask: u32 = 3;
        pub const OptionsOverride: u32 = 4;
    }
/** Move to specified saturation. */
    pub mod MoveToSaturation {
        pub const Saturation: u32 = 0;
        pub const TransitionTime: u32 = 1;
        pub const OptionsMask: u32 = 2;
        pub const OptionsOverride: u32 = 3;
    }
/** Move saturation up or down at specified rate. */
    pub mod MoveSaturation {
        pub const MoveMode: u32 = 0;
        pub const Rate: u32 = 1;
        pub const OptionsMask: u32 = 2;
        pub const OptionsOverride: u32 = 3;
    }
/** Step saturation up or down by specified size at specified rate. */
    pub mod StepSaturation {
        pub const StepMode: u32 = 0;
        pub const StepSize: u32 = 1;
        pub const TransitionTime: u32 = 2;
        pub const OptionsMask: u32 = 3;
        pub const OptionsOverride: u32 = 4;
    }
/** Move to hue and saturation. */
    pub mod MoveToHueAndSaturation {
        pub const Hue: u32 = 0;
        pub const Saturation: u32 = 1;
        pub const TransitionTime: u32 = 2;
        pub const OptionsMask: u32 = 3;
        pub const OptionsOverride: u32 = 4;
    }
/** Move to specified color. */
    pub mod MoveToColor {
        pub const ColorX: u32 = 0;
        pub const ColorY: u32 = 1;
        pub const TransitionTime: u32 = 2;
        pub const OptionsMask: u32 = 3;
        pub const OptionsOverride: u32 = 4;
    }
/** Moves the color. */
    pub mod MoveColor {
        pub const RateX: u32 = 0;
        pub const RateY: u32 = 1;
        pub const OptionsMask: u32 = 2;
        pub const OptionsOverride: u32 = 3;
    }
/** Steps the lighting to a specific color. */
    pub mod StepColor {
        pub const StepX: u32 = 0;
        pub const StepY: u32 = 1;
        pub const TransitionTime: u32 = 2;
        pub const OptionsMask: u32 = 3;
        pub const OptionsOverride: u32 = 4;
    }
/** Move to a specific color temperature. */
    pub mod MoveToColorTemperature {
        pub const ColorTemperatureMireds: u32 = 0;
        pub const TransitionTime: u32 = 1;
        pub const OptionsMask: u32 = 2;
        pub const OptionsOverride: u32 = 3;
    }
/** Command description for EnhancedMoveToHue */
    pub mod EnhancedMoveToHue {
        pub const EnhancedHue: u32 = 0;
        pub const Direction: u32 = 1;
        pub const TransitionTime: u32 = 2;
        pub const OptionsMask: u32 = 3;
        pub const OptionsOverride: u32 = 4;
    }
/** Command description for EnhancedMoveHue */
    pub mod EnhancedMoveHue {
        pub const MoveMode: u32 = 0;
        pub const Rate: u32 = 1;
        pub const OptionsMask: u32 = 2;
        pub const OptionsOverride: u32 = 3;
    }
/** Command description for EnhancedStepHue */
    pub mod EnhancedStepHue {
        pub const StepMode: u32 = 0;
        pub const StepSize: u32 = 1;
        pub const TransitionTime: u32 = 2;
        pub const OptionsMask: u32 = 3;
        pub const OptionsOverride: u32 = 4;
    }
/** Command description for EnhancedMoveToHueAndSaturation */
    pub mod EnhancedMoveToHueAndSaturation {
        pub const EnhancedHue: u32 = 0;
        pub const Saturation: u32 = 1;
        pub const TransitionTime: u32 = 2;
        pub const OptionsMask: u32 = 3;
        pub const OptionsOverride: u32 = 4;
    }
/** Command description for ColorLoopSet */
    pub mod ColorLoopSet {
        pub const UpdateFlags: u32 = 0;
        pub const Action: u32 = 1;
        pub const Direction: u32 = 2;
        pub const Time: u32 = 3;
        pub const StartHue: u32 = 4;
        pub const OptionsMask: u32 = 5;
        pub const OptionsOverride: u32 = 6;
    }
/** Command description for StopMoveStep */
    pub mod StopMoveStep {
        pub const OptionsMask: u32 = 0;
        pub const OptionsOverride: u32 = 1;
    }
/** Command description for MoveColorTemperature */
    pub mod MoveColorTemperature {
        pub const MoveMode: u32 = 0;
        pub const Rate: u32 = 1;
        pub const ColorTemperatureMinimumMireds: u32 = 2;
        pub const ColorTemperatureMaximumMireds: u32 = 3;
        pub const OptionsMask: u32 = 4;
        pub const OptionsOverride: u32 = 5;
    }
/** Command description for StepColorTemperature */
    pub mod StepColorTemperature {
        pub const StepMode: u32 = 0;
        pub const StepSize: u32 = 1;
        pub const TransitionTime: u32 = 2;
        pub const ColorTemperatureMinimumMireds: u32 = 3;
        pub const ColorTemperatureMaximumMireds: u32 = 4;
        pub const OptionsMask: u32 = 5;
        pub const OptionsOverride: u32 = 6;
    }
}
pub mod OTASoftwareUpdateProvider {
/** Determine availability of a new Software Image */
    pub mod QueryImage {
        pub const VendorID: u32 = 0;
        pub const ProductID: u32 = 1;
        pub const SoftwareVersion: u32 = 2;
        pub const ProtocolsSupported: u32 = 3;
        pub const HardwareVersion: u32 = 4;
        pub const Location: u32 = 5;
        pub const RequestorCanConsent: u32 = 6;
        pub const MetadataForProvider: u32 = 7;
    }
/** Response to QueryImage command */
    pub mod QueryImageResponse {
        pub const Status: u32 = 0;
        pub const DelayedActionTime: u32 = 1;
        pub const ImageURI: u32 = 2;
        pub const SoftwareVersion: u32 = 3;
        pub const SoftwareVersionString: u32 = 4;
        pub const UpdateToken: u32 = 5;
        pub const UserConsentNeeded: u32 = 6;
        pub const MetadataForRequestor: u32 = 7;
    }
/** Determine next action to take for a downloaded Software Image */
    pub mod ApplyUpdateRequest {
        pub const UpdateToken: u32 = 0;
        pub const NewVersion: u32 = 1;
    }
/** Reponse to ApplyUpdateRequest command */
    pub mod ApplyUpdateResponse {
        pub const Action: u32 = 0;
        pub const DelayedActionTime: u32 = 1;
    }
/** Notify OTA Provider that an update was applied */
    pub mod NotifyUpdateApplied {
        pub const UpdateToken: u32 = 0;
        pub const SoftwareVersion: u32 = 1;
    }
}
pub mod DishwasherAlarm {
/** This command resets active and latched alarms (if possible). */
    pub mod Reset {
        pub const Alarms: u32 = 0;
    }
/** This command allows a client to request that an alarm be enabled or suppressed at the server. */
    pub mod ModifyEnabledAlarms {
        pub const Mask: u32 = 0;
    }
/** This event SHALL be generated when one or more alarms change state, and SHALL have these fields: */
    pub mod Notify {
        pub const Active: u32 = 0;
        pub const Inactive: u32 = 1;
        pub const State: u32 = 2;
        pub const Mask: u32 = 3;
    }
}
pub mod SmokeCOAlarm {
/** This event SHALL be generated when SmokeState attribute changes to either Warning or Critical state. */
    pub mod SmokeAlarm {
        pub const AlarmSeverityLevel: u32 = 0;
    }
/** This event SHALL be generated when COState attribute changes to either Warning or Critical state. */
    pub mod COAlarm {
        pub const AlarmSeverityLevel: u32 = 0;
    }
/** This event SHALL be generated when BatteryAlert attribute changes to either Warning or Critical state. */
    pub mod LowBattery {
        pub const AlarmSeverityLevel: u32 = 0;
    }
/** This event SHALL be generated when the device hosting the server receives a smoke alarm from an interconnected sensor. */
    pub mod InterconnectSmokeAlarm {
        pub const AlarmSeverityLevel: u32 = 0;
    }
/** This event SHALL be generated when the device hosting the server receives a smoke alarm from an interconnected sensor. */
    pub mod InterconnectCOAlarm {
        pub const AlarmSeverityLevel: u32 = 0;
    }
}
pub mod WiFiNetworkManagement {
/** This command SHALL be generated in response to a NetworkPassphraseRequest command. */
    pub mod NetworkPassphraseResponse {
        pub const Passphrase: u32 = 0;
    }
}
pub mod CameraAVSettingsUserLevelManagement {
    pub mod DPTZStruct {
        pub const VideoStreamID: u32 = 0;
        pub const Viewport: u32 = 1;
    }
    pub mod MPTZPresetStruct {
        pub const PresetID: u32 = 0;
        pub const Name: u32 = 1;
        pub const Settings: u32 = 2;
    }
    pub mod MPTZStruct {
        pub const Pan: u32 = 0;
        pub const Tilt: u32 = 1;
        pub const Zoom: u32 = 2;
    }
/** This command SHALL move the camera to the provided values for pan, tilt, and zoom in the mechanical PTZ. */
    pub mod MPTZSetPosition {
        pub const Pan: u32 = 0;
        pub const Tilt: u32 = 1;
        pub const Zoom: u32 = 2;
    }
/** This command SHALL move the camera by the delta values relative to the currently defined position. */
    pub mod MPTZRelativeMove {
        pub const PanDelta: u32 = 0;
        pub const TiltDelta: u32 = 1;
        pub const ZoomDelta: u32 = 2;
    }
/** This command SHALL move the camera to the positions specified by the Preset passed. */
    pub mod MPTZMoveToPreset {
        pub const PresetID: u32 = 0;
    }
/** This command allows creating a new preset or updating the values of an existing one. */
    pub mod MPTZSavePreset {
        pub const PresetID: u32 = 0;
        pub const Name: u32 = 1;
    }
/** This command SHALL remove a preset entry from the PresetMptzTable. */
    pub mod MPTZRemovePreset {
        pub const PresetID: u32 = 0;
    }
/** This command allows for setting the digital viewport for a specific Video Stream. */
    pub mod DPTZSetViewport {
        pub const VideoStreamID: u32 = 0;
        pub const Viewport: u32 = 1;
    }
/** This command SHALL change the per stream viewport by the amount specified in a relative fashion. */
    pub mod DPTZRelativeMove {
        pub const VideoStreamID: u32 = 0;
        pub const DeltaX: u32 = 1;
        pub const DeltaY: u32 = 2;
        pub const ZoomDelta: u32 = 3;
    }
}
pub mod Messages {
    pub mod MessageResponseOptionStruct {
        pub const MessageResponseID: u32 = 0;
        pub const Label: u32 = 1;
    }
    pub mod MessageStruct {
        pub const MessageID: u32 = 0;
        pub const Priority: u32 = 1;
        pub const MessageControl: u32 = 2;
        pub const StartTime: u32 = 3;
        pub const Duration: u32 = 4;
        pub const MessageText: u32 = 5;
        pub const Responses: u32 = 6;
    }
/** Command for requesting messages be presented */
    pub mod PresentMessagesRequest {
        pub const MessageID: u32 = 0;
        pub const Priority: u32 = 1;
        pub const MessageControl: u32 = 2;
        pub const StartTime: u32 = 3;
        pub const Duration: u32 = 4;
        pub const MessageText: u32 = 5;
        pub const Responses: u32 = 6;
    }
/** Command for cancelling message present requests */
    pub mod CancelMessagesRequest {
        pub const MessageIDs: u32 = 0;
    }
/** This event SHALL be generated when the message is confirmed by the user, or when the expiration date of the message is reached. */
    pub mod MessageQueued {
        pub const MessageID: u32 = 0;
    }
/** This event SHALL be generated when the message is presented to the user. */
    pub mod MessagePresented {
        pub const MessageID: u32 = 0;
    }
/** This event SHALL be generated when the message is confirmed by the user, or when the expiration date of the message is reached. */
    pub mod MessageComplete {
        pub const MessageID: u32 = 0;
        pub const ResponseID: u32 = 1;
        pub const Reply: u32 = 2;
        pub const FutureMessagesPreference: u32 = 3;
    }
}
pub mod AccountLogin {
/** The purpose of this command is to determine if the active user account of the given Content App matches the active user account of a given Commissionee, and when it does, return a Setup PIN which can be used for password-authenticated session establishment (PASE) with the Commissionee. */
    pub mod GetSetupPIN {
        pub const TempAccountIdentifier: u32 = 0;
    }
/** This message is sent in response to the GetSetupPIN command, and contains the Setup PIN, or null when the account identified in the request does not match the active account of the running Content App. */
    pub mod GetSetupPINResponse {
        pub const SetupPIN: u32 = 0;
    }
/** The purpose of this command is to allow the Content App to assume the user account of a given Commissionee by leveraging the Setup PIN input by the user during the commissioning process. */
    pub mod Login {
        pub const TempAccountIdentifier: u32 = 0;
        pub const SetupPIN: u32 = 1;
        pub const Node: u32 = 2;
    }
/** The purpose of this command is to instruct the Content App to clear the current user account. */
    pub mod Logout {
        pub const Node: u32 = 0;
    }
/** This event can be used by the Content App to indicate that the current user has logged out. */
    pub mod LoggedOut {
        pub const Node: u32 = 0;
    }
}
pub mod RVCCleanMode {
    pub mod ModeOptionStruct {
        pub const Label: u32 = 0;
        pub const Mode: u32 = 1;
        pub const ModeTags: u32 = 2;
    }
    pub mod ModeTagStruct {
        pub const MfgCode: u32 = 0;
        pub const Value: u32 = 1;
    }
/** This command is used to change device modes.
 * On receipt of this command the device SHALL respond with a ChangeToModeResponse command. */
    pub mod ChangeToMode {
        pub const NewMode: u32 = 0;
    }
/** This command is sent by the device on receipt of the ChangeToModeWithStatus command. */
    pub mod ChangeToModeResponse {
        pub const Status: u32 = 0;
        pub const StatusText: u32 = 1;
    }
}
pub mod ElectricalPowerMeasurement {
    pub mod HarmonicMeasurementStruct {
        pub const Order: u32 = 0;
        pub const Measurement: u32 = 1;
    }
    pub mod MeasurementAccuracyRangeStruct {
        pub const RangeMin: u32 = 0;
        pub const RangeMax: u32 = 1;
        pub const PercentMax: u32 = 2;
        pub const PercentMin: u32 = 3;
        pub const PercentTypical: u32 = 4;
        pub const FixedMax: u32 = 5;
        pub const FixedMin: u32 = 6;
        pub const FixedTypical: u32 = 7;
    }
    pub mod MeasurementAccuracyStruct {
        pub const MeasurementType: u32 = 0;
        pub const Measured: u32 = 1;
        pub const MinMeasuredValue: u32 = 2;
        pub const MaxMeasuredValue: u32 = 3;
        pub const AccuracyRanges: u32 = 4;
    }
    pub mod MeasurementRangeStruct {
        pub const MeasurementType: u32 = 0;
        pub const Min: u32 = 1;
        pub const Max: u32 = 2;
        pub const StartTimestamp: u32 = 3;
        pub const EndTimestamp: u32 = 4;
        pub const MinTimestamp: u32 = 5;
        pub const MaxTimestamp: u32 = 6;
        pub const StartSystime: u32 = 7;
        pub const EndSystime: u32 = 8;
        pub const MinSystime: u32 = 9;
        pub const MaxSystime: u32 = 10;
    }
/** If supported, this event SHALL be generated at the end of a measurement period. */
    pub mod MeasurementPeriodRanges {
        pub const Ranges: u32 = 0;
    }
}
pub mod FixedLabel {
    pub mod LabelStruct {
        pub const Label: u32 = 0;
        pub const Value: u32 = 1;
    }
}
pub mod PowerSource {
/** The WiredFaultChange Event SHALL be generated when the set of wired faults currently detected by the Node on this wired power source changes. */
    pub mod WiredFaultChange {
        pub const Current: u32 = 0;
        pub const Previous: u32 = 1;
    }
/** The BatFaultChange Event SHALL be generated when the set of battery faults currently detected by the Node on this battery power source changes. */
    pub mod BatFaultChange {
        pub const Current: u32 = 0;
        pub const Previous: u32 = 1;
    }
/** The BatChargeFaultChange Event SHALL be generated when the set of charge faults currently detected by the Node on this battery power source changes. */
    pub mod BatChargeFaultChange {
        pub const Current: u32 = 0;
        pub const Previous: u32 = 1;
    }
}
pub mod PowerTopology {
    pub mod CircuitNodeStruct {
        pub const Node: u32 = 1;
        pub const Endpoint: u32 = 2;
        pub const Label: u32 = 3;
    }
}
pub mod CommodityMetering {
    pub mod MeteredQuantityStruct {
        pub const TariffComponentIDs: u32 = 0;
        pub const Quantity: u32 = 1;
    }
}
pub mod Descriptor {
    pub mod DeviceTypeStruct {
        pub const DeviceType: u32 = 0;
        pub const Revision: u32 = 1;
    }
}
pub mod ElectricalGridConditions {
    pub mod ElectricalGridConditionsStruct {
        pub const PeriodStart: u32 = 0;
        pub const PeriodEnd: u32 = 1;
        pub const GridCarbonIntensity: u32 = 2;
        pub const GridCarbonLevel: u32 = 3;
        pub const LocalCarbonIntensity: u32 = 4;
        pub const LocalCarbonLevel: u32 = 5;
    }
/** This event SHALL be generated when the value of the CurrentConditions attribute changes. */
    pub mod CurrentConditionsChanged {
        pub const CurrentConditions: u32 = 0;
    }
}
pub mod BasicInformation {
    pub mod CapabilityMinimaStruct {
        pub const CaseSessionsPerFabric: u32 = 0;
        pub const SubscriptionsPerFabric: u32 = 1;
    }
    pub mod ProductAppearanceStruct {
        pub const Finish: u32 = 0;
        pub const PrimaryColor: u32 = 1;
    }
/** The StartUp event SHALL be generated by a Node as soon as reasonable after completing a boot or reboot process. */
    pub mod StartUp {
        pub const SoftwareVersion: u32 = 0;
    }
/** The Leave event SHOULD be generated by a Node prior to permanently leaving a given Fabric, such as when the RemoveFabric command is invoked for a given fabric, or triggered by factory reset or some other manufacturer specific action to disable or reset the operational data in the Node. */
    pub mod Leave {
        pub const FabricIndex: u32 = 0;
    }
/** This event (when supported) SHALL be generated when there is a change in the Reachable attribute. */
    pub mod ReachableChanged {
        pub const ReachableNewValue: u32 = 0;
    }
}
pub mod MediaPlayback {
    pub mod PlaybackPositionStruct {
        pub const UpdatedAt: u32 = 0;
        pub const Position: u32 = 1;
    }
    pub mod TrackAttributesStruct {
        pub const LanguageCode: u32 = 0;
        pub const Characteristics: u32 = 1;
        pub const DisplayName: u32 = 2;
    }
    pub mod TrackStruct {
        pub const ID: u32 = 0;
        pub const TrackAttributes: u32 = 1;
    }
/** Upon receipt, this SHALL Rewind through media. Different Rewind speeds can be used on the TV based upon the number of sequential calls to this function. This is to avoid needing to define every speed now (multiple fast, slow motion, etc). */
    pub mod Rewind {
        pub const AudioAdvanceUnmuted: u32 = 0;
    }
/** Upon receipt, this SHALL Advance through media. Different FF speeds can be used on the TV based upon the number of sequential calls to this function. This is to avoid needing to define every speed now (multiple fast, slow motion, etc). */
    pub mod FastForward {
        pub const AudioAdvanceUnmuted: u32 = 0;
    }
/** Upon receipt, this SHALL Skip forward in the media by the given number of seconds, using the data as follows: */
    pub mod SkipForward {
        pub const DeltaPositionMilliseconds: u32 = 0;
    }
/** Upon receipt, this SHALL Skip backward in the media by the given number of seconds, using the data as follows: */
    pub mod SkipBackward {
        pub const DeltaPositionMilliseconds: u32 = 0;
    }
/** This command SHALL be generated in response to various Playback Request commands. */
    pub mod PlaybackResponse {
        pub const Status: u32 = 0;
        pub const Data: u32 = 1;
    }
/** Upon receipt, this SHALL Skip backward in the media by the given number of seconds, using the data as follows: */
    pub mod Seek {
        pub const Position: u32 = 0;
    }
/** Upon receipt, the server SHALL set the active Audio Track to the one identified by the TrackID in the Track catalog for the streaming media. If the TrackID does not exist in the Track catalog, OR does not correspond to the streaming media OR no media is being streamed at the time of receipt of this command, the server will return an error status of INVALID_ARGUMENT. */
    pub mod ActivateAudioTrack {
        pub const TrackID: u32 = 0;
        pub const AudioOutputIndex: u32 = 1;
    }
/** Upon receipt, the server SHALL set the active Text Track to the one identified by the TrackID in the Track catalog for the streaming media. If the TrackID does not exist in the Track catalog, OR does not correspond to the streaming media OR no media is being streamed at the time of receipt of this command, the server SHALL return an error status of INVALID_ARGUMENT. */
    pub mod ActivateTextTrack {
        pub const TrackID: u32 = 0;
    }
/** If supported, this event SHALL be generated when there is a change in any of the supported attributes of the Media Playback cluster. */
    pub mod StateChanged {
        pub const CurrentState: u32 = 0;
        pub const StartTime: u32 = 1;
        pub const Duration: u32 = 2;
        pub const SampledPosition: u32 = 3;
        pub const PlaybackSpeed: u32 = 4;
        pub const SeekRangeEnd: u32 = 5;
        pub const SeekRangeStart: u32 = 6;
        pub const Data: u32 = 7;
        pub const AudioAdvanceUnmuted: u32 = 8;
    }
}
pub mod WindowCovering {
/** Go to lift percentage specified */
    pub mod GoToLiftPercentage {
        pub const LiftPercent100thsValue: u32 = 0;
    }
/** Go to tilt percentage specified */
    pub mod GoToTiltPercentage {
        pub const TiltPercent100thsValue: u32 = 0;
    }
}
pub mod WiFiNetworkDiagnostics {
/** The Disconnection Event SHALL indicate that a Node's Wi-Fi connection has been disconnected as a result of de-authenticated or dis-association and indicates the reason. */
    pub mod Disconnection {
        pub const ReasonCode: u32 = 0;
    }
/** The AssociationFailure event SHALL indicate that a Node has attempted to connect, or reconnect, to a Wi-Fi access point, but is unable to successfully associate or authenticate, after exhausting all internal retries of its supplicant. */
    pub mod AssociationFailure {
        pub const AssociationFailureCause: u32 = 0;
        pub const Status: u32 = 1;
    }
/** The ConnectionStatus Event SHALL indicate that a Node's connection status to a Wi-Fi network has changed. */
    pub mod ConnectionStatus {
        pub const ConnectionStatus: u32 = 0;
    }
}
pub mod OTASoftwareUpdateRequestor {
    pub mod ProviderLocation {
        pub const ProviderNodeID: u32 = 1;
        pub const Endpoint: u32 = 2;
    }
/** Announce the presence of an OTA Provider */
    pub mod AnnounceOTAProvider {
        pub const ProviderNodeID: u32 = 0;
        pub const VendorID: u32 = 1;
        pub const AnnouncementReason: u32 = 2;
        pub const MetadataForNode: u32 = 3;
        pub const Endpoint: u32 = 4;
    }
/** This event SHALL be generated when a change of the UpdateState attribute occurs due to an OTA Requestor moving through the states necessary to query for updates. */
    pub mod StateTransition {
        pub const PreviousState: u32 = 0;
        pub const NewState: u32 = 1;
        pub const Reason: u32 = 2;
        pub const TargetSoftwareVersion: u32 = 3;
    }
/** This event SHALL be generated whenever a new version starts executing after being applied due to a software update. */
    pub mod VersionApplied {
        pub const SoftwareVersion: u32 = 0;
        pub const ProductID: u32 = 1;
    }
/** This event SHALL be generated whenever an error occurs during OTA Requestor download operation. */
    pub mod DownloadError {
        pub const SoftwareVersion: u32 = 0;
        pub const BytesDownloaded: u32 = 1;
        pub const ProgressPercent: u32 = 2;
        pub const PlatformCode: u32 = 3;
    }
}
pub mod WebRTCTransportRequestor {
/** This command provides the stream requestor with WebRTC session details. */
    pub mod Offer {
        pub const WebRTCSessionID: u32 = 0;
        pub const SDP: u32 = 1;
        pub const ICEServers: u32 = 2;
        pub const ICETransportPolicy: u32 = 3;
    }
/** This command provides the stream requestor with the WebRTC session details (i.e. Session ID and SDP answer), It is the next command in the Offer/Answer flow to the ProvideOffer command. */
    pub mod Answer {
        pub const WebRTCSessionID: u32 = 0;
        pub const SDP: u32 = 1;
    }
/** This command allows for the object based ICE candidates generated after the initial Offer / Answer exchange, via a JSEP onicecandidate event, a DOM rtcpeerconnectioniceevent event, or other WebRTC compliant implementations, to be added to a session during the gathering phase. */
    pub mod ICECandidates {
        pub const WebRTCSessionID: u32 = 0;
        pub const ICECandidates: u32 = 1;
    }
/** This command notifies the stream requestor that the provider has ended the WebRTC session. */
    pub mod End {
        pub const WebRTCSessionID: u32 = 0;
        pub const Reason: u32 = 1;
    }
}
pub mod ThreadNetworkDirectory {
    pub mod ThreadNetworkStruct {
        pub const ExtendedPanID: u32 = 0;
        pub const NetworkName: u32 = 1;
        pub const Channel: u32 = 2;
        pub const ActiveTimestamp: u32 = 3;
    }
/** Adds an entry to the ThreadNetworks attribute with the specified Thread Operational Dataset. */
    pub mod AddNetwork {
        pub const OperationalDataset: u32 = 0;
    }
/** Removes the network with the given Extended PAN ID from the ThreadNetworks attribute. */
    pub mod RemoveNetwork {
        pub const ExtendedPanID: u32 = 0;
    }
/** Retrieves the Thread Operational Dataset with the given Extended PAN ID. */
    pub mod GetOperationalDataset {
        pub const ExtendedPanID: u32 = 0;
    }
/** Contains the Thread Operational Dataset for the Extended PAN specified in GetOperationalDataset. */
    pub mod OperationalDatasetResponse {
        pub const OperationalDataset: u32 = 0;
    }
}
pub mod ServiceArea {
    pub mod AreaInfoStruct {
        pub const LocationInfo: u32 = 0;
        pub const LandmarkInfo: u32 = 1;
    }
    pub mod AreaStruct {
        pub const AreaID: u32 = 0;
        pub const MapID: u32 = 1;
        pub const AreaInfo: u32 = 2;
    }
    pub mod LandmarkInfoStruct {
        pub const LandmarkTag: u32 = 0;
        pub const RelativePositionTag: u32 = 1;
    }
    pub mod MapStruct {
        pub const MapID: u32 = 0;
        pub const Name: u32 = 1;
    }
    pub mod ProgressStruct {
        pub const AreaID: u32 = 0;
        pub const Status: u32 = 1;
        pub const TotalOperationalTime: u32 = 2;
        pub const EstimatedTime: u32 = 3;
    }
/** This command is used to select a set of device areas, where the device is to operate. */
    pub mod SelectAreas {
        pub const NewAreas: u32 = 0;
    }
/** This command is sent by the device on receipt of the SelectAreas command. */
    pub mod SelectAreasResponse {
        pub const Status: u32 = 0;
        pub const StatusText: u32 = 1;
    }
/** This command is used to skip the given area, and to attempt operating at other areas on the SupportedAreas attribute list. */
    pub mod SkipArea {
        pub const SkippedArea: u32 = 0;
    }
/** This command is sent by the device on receipt of the SkipArea command. */
    pub mod SkipAreaResponse {
        pub const Status: u32 = 0;
        pub const StatusText: u32 = 1;
    }
}
pub mod RefrigeratorAndTemperatureControlledCabinetMode {
    pub mod ModeOptionStruct {
        pub const Label: u32 = 0;
        pub const Mode: u32 = 1;
        pub const ModeTags: u32 = 2;
    }
    pub mod ModeTagStruct {
        pub const MfgCode: u32 = 0;
        pub const Value: u32 = 1;
    }
/** This command is used to change device modes.
 * On receipt of this command the device SHALL respond with a ChangeToModeResponse command. */
    pub mod ChangeToMode {
        pub const NewMode: u32 = 0;
    }
/** This command is sent by the device on receipt of the ChangeToModeWithStatus command. */
    pub mod ChangeToModeResponse {
        pub const Status: u32 = 0;
        pub const StatusText: u32 = 1;
    }
}
pub mod AccessControl {
    pub mod AccessControlEntryStruct {
        pub const Privilege: u32 = 1;
        pub const AuthMode: u32 = 2;
        pub const Subjects: u32 = 3;
        pub const Targets: u32 = 4;
    }
    pub mod AccessControlExtensionStruct {
        pub const Data: u32 = 1;
    }
    pub mod AccessControlTargetStruct {
        pub const Cluster: u32 = 0;
        pub const Endpoint: u32 = 1;
        pub const DeviceType: u32 = 2;
    }
    pub mod AccessRestrictionEntryStruct {
        pub const Endpoint: u32 = 0;
        pub const Cluster: u32 = 1;
        pub const Restrictions: u32 = 2;
    }
    pub mod AccessRestrictionStruct {
        pub const Type: u32 = 0;
        pub const ID: u32 = 1;
    }
    pub mod CommissioningAccessRestrictionEntryStruct {
        pub const Endpoint: u32 = 0;
        pub const Cluster: u32 = 1;
        pub const Restrictions: u32 = 2;
    }
/** This command signals to the service associated with the device vendor that the fabric administrator would like a review of the current restrictions on the accessing fabric. */
    pub mod ReviewFabricRestrictions {
        pub const ARL: u32 = 0;
    }
/** Returns the review token for the request, which can be used to correlate with a FabricRestrictionReviewUpdate event. */
    pub mod ReviewFabricRestrictionsResponse {
        pub const Token: u32 = 0;
    }
/** The server SHALL generate AccessControlEntryChanged events whenever its ACL attribute data is changed by an Administrator. */
    pub mod AccessControlEntryChanged {
        pub const AdminNodeID: u32 = 1;
        pub const AdminPasscodeID: u32 = 2;
        pub const ChangeType: u32 = 3;
        pub const LatestValue: u32 = 4;
    }
/** The server SHALL generate AccessControlExtensionChanged events whenever its extension attribute data is changed by an Administrator. */
    pub mod AccessControlExtensionChanged {
        pub const AdminNodeID: u32 = 1;
        pub const AdminPasscodeID: u32 = 2;
        pub const ChangeType: u32 = 3;
        pub const LatestValue: u32 = 4;
    }
/** The server SHALL generate a FabricRestrictionReviewUpdate event to indicate completion of a fabric restriction review. */
    pub mod FabricRestrictionReviewUpdate {
        pub const Token: u32 = 0;
        pub const Instruction: u32 = 1;
        pub const ARLRequestFlowUrl: u32 = 2;
    }
}
pub mod WaterHeaterMode {
    pub mod ModeOptionStruct {
        pub const Label: u32 = 0;
        pub const Mode: u32 = 1;
        pub const ModeTags: u32 = 2;
    }
    pub mod ModeTagStruct {
        pub const MfgCode: u32 = 0;
        pub const Value: u32 = 1;
    }
/** This command is used to change device modes. */
    pub mod ChangeToMode {
        pub const NewMode: u32 = 0;
    }
/** This command is sent by the device on receipt of the ChangeToMode command. */
    pub mod ChangeToModeResponse {
        pub const Status: u32 = 0;
        pub const StatusText: u32 = 1;
    }
}
pub mod TLSClientManagement {
    pub mod TLSEndpointStruct {
        pub const EndpointID: u32 = 0;
        pub const Hostname: u32 = 1;
        pub const Port: u32 = 2;
        pub const CAID: u32 = 3;
        pub const CCDID: u32 = 4;
        pub const ReferenceCount: u32 = 5;
    }
/** This command is used to provision a TLS Endpoint for the provided Hostname / Port combination. */
    pub mod ProvisionEndpoint {
        pub const Hostname: u32 = 0;
        pub const Port: u32 = 1;
        pub const CAID: u32 = 2;
        pub const CCDID: u32 = 3;
        pub const EndpointID: u32 = 4;
    }
/** This command is used to report the result of the ProvisionEndpoint command. */
    pub mod ProvisionEndpointResponse {
        pub const EndpointID: u32 = 0;
    }
/** This command is used to find a TLS Endpoint by its ID. */
    pub mod FindEndpoint {
        pub const EndpointID: u32 = 0;
    }
/** This command is used to report the result of the FindEndpoint command. */
    pub mod FindEndpointResponse {
        pub const Endpoint: u32 = 0;
    }
/** This command is used to remove a TLS Endpoint by its ID. */
    pub mod RemoveEndpoint {
        pub const EndpointID: u32 = 0;
    }
}
pub mod ElectricalEnergyMeasurement {
    pub mod CumulativeEnergyResetStruct {
        pub const ImportedResetTimestamp: u32 = 0;
        pub const ExportedResetTimestamp: u32 = 1;
        pub const ImportedResetSystime: u32 = 2;
        pub const ExportedResetSystime: u32 = 3;
    }
    pub mod EnergyMeasurementStruct {
        pub const Energy: u32 = 0;
        pub const StartTimestamp: u32 = 1;
        pub const EndTimestamp: u32 = 2;
        pub const StartSystime: u32 = 3;
        pub const EndSystime: u32 = 4;
        pub const ApparentEnergy: u32 = 5;
        pub const ReactiveEnergy: u32 = 6;
    }
    pub mod MeasurementAccuracyRangeStruct {
        pub const RangeMin: u32 = 0;
        pub const RangeMax: u32 = 1;
        pub const PercentMax: u32 = 2;
        pub const PercentMin: u32 = 3;
        pub const PercentTypical: u32 = 4;
        pub const FixedMax: u32 = 5;
        pub const FixedMin: u32 = 6;
        pub const FixedTypical: u32 = 7;
    }
    pub mod MeasurementAccuracyStruct {
        pub const MeasurementType: u32 = 0;
        pub const Measured: u32 = 1;
        pub const MinMeasuredValue: u32 = 2;
        pub const MaxMeasuredValue: u32 = 3;
        pub const AccuracyRanges: u32 = 4;
    }
/** This event SHALL be generated when the server takes a snapshot of the cumulative energy imported by the server, exported from the server, or both, but not more frequently than the rate mentioned in the description above of the related attribute. */
    pub mod CumulativeEnergyMeasured {
        pub const EnergyImported: u32 = 0;
        pub const EnergyExported: u32 = 1;
    }
/** This event SHALL be generated when the server reaches the end of a reporting period for imported energy, exported energy, or both. */
    pub mod PeriodicEnergyMeasured {
        pub const EnergyImported: u32 = 0;
        pub const EnergyExported: u32 = 1;
    }
}
pub mod ClosureControl {
    pub mod OverallCurrentStateStruct {
        pub const Position: u32 = 0;
        pub const Latch: u32 = 1;
        pub const Speed: u32 = 2;
        pub const SecureState: u32 = 3;
    }
    pub mod OverallTargetStateStruct {
        pub const Position: u32 = 0;
        pub const Latch: u32 = 1;
        pub const Speed: u32 = 2;
    }
/** On receipt of this command, the closure SHALL operate to update its position, latch state and/or motion speed. */
    pub mod MoveTo {
        pub const Position: u32 = 0;
        pub const Latch: u32 = 1;
        pub const Speed: u32 = 2;
    }
/** This event SHALL be generated when a reportable error condition is detected. */
    pub mod OperationalError {
        pub const ErrorState: u32 = 0;
    }
/** This event, if supported, SHALL be generated when the MainStateEnum attribute changes state to and from disengaged, indicating if the actuator is Engaged or Disengaged. */
    pub mod EngageStateChanged {
        pub const EngageValue: u32 = 0;
    }
/** This event, if supported, SHALL be generated when the SecureState field in the OverallCurrentState attribute changes. */
    pub mod SecureStateChanged {
        pub const SecureValue: u32 = 0;
    }
}
pub mod Identify {
/** This command starts or stops the receiving device identifying itself. */
    pub mod Identify {
        pub const IdentifyTime: u32 = 0;
    }
/** This command allows the support of feedback to the user, such as a certain light effect. */
    pub mod TriggerEffect {
        pub const EffectIdentifier: u32 = 0;
        pub const EffectVariant: u32 = 1;
    }
}
pub mod Binding {
    pub mod TargetStruct {
        pub const Node: u32 = 1;
        pub const Group: u32 = 2;
        pub const Endpoint: u32 = 3;
        pub const Cluster: u32 = 4;
    }
}
pub mod EnergyEVSEMode {
    pub mod ModeOptionStruct {
        pub const Label: u32 = 0;
        pub const Mode: u32 = 1;
        pub const ModeTags: u32 = 2;
    }
    pub mod ModeTagStruct {
        pub const MfgCode: u32 = 0;
        pub const Value: u32 = 1;
    }
/** This command is used to change device modes. */
    pub mod ChangeToMode {
        pub const NewMode: u32 = 0;
    }
/** This command is sent by the device on receipt of the ChangeToMode command. */
    pub mod ChangeToModeResponse {
        pub const Status: u32 = 0;
        pub const StatusText: u32 = 1;
    }
}
pub mod BooleanStateConfiguration {
/** This command is used to suppress the specified alarm mode. */
    pub mod SuppressAlarm {
        pub const AlarmsToSuppress: u32 = 0;
    }
/** This command is used to enable or disable the specified alarm mode. */
    pub mod EnableDisableAlarm {
        pub const AlarmsToEnableDisable: u32 = 0;
    }
/** This event SHALL be generated after any bits in the AlarmsActive and/or AlarmsSuppressed attributes change. */
    pub mod AlarmsStateChanged {
        pub const AlarmsActive: u32 = 0;
        pub const AlarmsSuppressed: u32 = 1;
    }
/** This event SHALL be generated when the device registers or clears a fault. */
    pub mod SensorFault {
        pub const SensorFault: u32 = 0;
    }
}
pub mod EnergyPreference {
    pub mod BalanceStruct {
        pub const Step: u32 = 0;
        pub const Label: u32 = 1;
    }
}
pub mod ScenesManagement {
    pub mod AttributeValuePairStruct {
        pub const AttributeID: u32 = 0;
        pub const ValueUnsigned8: u32 = 1;
        pub const ValueSigned8: u32 = 2;
        pub const ValueUnsigned16: u32 = 3;
        pub const ValueSigned16: u32 = 4;
        pub const ValueUnsigned32: u32 = 5;
        pub const ValueSigned32: u32 = 6;
        pub const ValueUnsigned64: u32 = 7;
        pub const ValueSigned64: u32 = 8;
    }
    pub mod ExtensionFieldSetStruct {
        pub const ClusterID: u32 = 0;
        pub const AttributeValueList: u32 = 1;
    }
    pub mod SceneInfoStruct {
        pub const SceneCount: u32 = 0;
        pub const CurrentScene: u32 = 1;
        pub const CurrentGroup: u32 = 2;
        pub const SceneValid: u32 = 3;
        pub const RemainingCapacity: u32 = 4;
    }
/** Add a scene to the scene table. Extension field sets are input as '{"ClusterID": VALUE, "AttributeValueList":[{"AttributeID": VALUE, "Value*": VALUE}]}'. */
    pub mod AddScene {
        pub const GroupID: u32 = 0;
        pub const SceneID: u32 = 1;
        pub const TransitionTime: u32 = 2;
        pub const SceneName: u32 = 3;
        pub const ExtensionFieldSetStructs: u32 = 4;
    }
/** The command is generated in response to a received unicast AddScene command, */
    pub mod AddSceneResponse {
        pub const Status: u32 = 0;
        pub const GroupID: u32 = 1;
        pub const SceneID: u32 = 2;
    }
/** Retrieves the requested scene entry from its Scene table. */
    pub mod ViewScene {
        pub const GroupID: u32 = 0;
        pub const SceneID: u32 = 1;
    }
/** The command is generated in response to a received unicast ViewScene command */
    pub mod ViewSceneResponse {
        pub const Status: u32 = 0;
        pub const GroupID: u32 = 1;
        pub const SceneID: u32 = 2;
        pub const TransitionTime: u32 = 3;
        pub const SceneName: u32 = 4;
        pub const ExtensionFieldSetStructs: u32 = 5;
    }
/** Removes the requested scene entry, corresponding to the value of the GroupID field, from its Scene Table */
    pub mod RemoveScene {
        pub const GroupID: u32 = 0;
        pub const SceneID: u32 = 1;
    }
/** The command is generated in response to a received unicast RemoveScene command */
    pub mod RemoveSceneResponse {
        pub const Status: u32 = 0;
        pub const GroupID: u32 = 1;
        pub const SceneID: u32 = 2;
    }
/** Remove all scenes, corresponding to the value of the GroupID field, from its Scene Table */
    pub mod RemoveAllScenes {
        pub const GroupID: u32 = 0;
    }
/** The command is generated in response to a received unicast RemoveAllScenes command */
    pub mod RemoveAllScenesResponse {
        pub const Status: u32 = 0;
        pub const GroupID: u32 = 1;
    }
/** Adds the scene entry into its Scene Table along with all extension field sets corresponding to the current state of other clusters on the same endpoint */
    pub mod StoreScene {
        pub const GroupID: u32 = 0;
        pub const SceneID: u32 = 1;
    }
/** The command is generated in response to a received unicast StoreScene command */
    pub mod StoreSceneResponse {
        pub const Status: u32 = 0;
        pub const GroupID: u32 = 1;
        pub const SceneID: u32 = 2;
    }
/** Set the attributes and corresponding state for each other cluster implemented on the endpoint accordingly to the resquested scene entry in the Scene Table */
    pub mod RecallScene {
        pub const GroupID: u32 = 0;
        pub const SceneID: u32 = 1;
        pub const TransitionTime: u32 = 2;
    }
/** This command can be used to get the used scene identifiers within a certain group, for the endpoint that implements this cluster. */
    pub mod GetSceneMembership {
        pub const GroupID: u32 = 0;
    }
/** The command is generated in response to a received unicast GetSceneMembership command */
    pub mod GetSceneMembershipResponse {
        pub const Status: u32 = 0;
        pub const Capacity: u32 = 1;
        pub const GroupID: u32 = 2;
        pub const SceneList: u32 = 3;
    }
/** This command allows a client to efficiently copy scenes from one group/scene identifier pair to another group/scene identifier pair. */
    pub mod CopyScene {
        pub const Mode: u32 = 0;
        pub const GroupIdentifierFrom: u32 = 1;
        pub const SceneIdentifierFrom: u32 = 2;
        pub const GroupIdentifierTo: u32 = 3;
        pub const SceneIdentifierTo: u32 = 4;
    }
/** The command is generated in response to a received unicast CopyScene command */
    pub mod CopySceneResponse {
        pub const Status: u32 = 0;
        pub const GroupIdentifierFrom: u32 = 1;
        pub const SceneIdentifierFrom: u32 = 2;
    }
}
pub mod HEPAFilterMonitoring {
    pub mod ReplacementProductStruct {
        pub const ProductIdentifierType: u32 = 0;
        pub const ProductIdentifierValue: u32 = 1;
    }
}
pub mod ActivatedCarbonFilterMonitoring {
    pub mod ReplacementProductStruct {
        pub const ProductIdentifierType: u32 = 0;
        pub const ProductIdentifierValue: u32 = 1;
    }
}
pub mod WaterTankLevelMonitoring {
    pub mod ReplacementProductStruct {
        pub const ProductIdentifierType: u32 = 0;
        pub const ProductIdentifierValue: u32 = 1;
    }
}
pub mod GeneralCommissioning {
    pub mod BasicCommissioningInfo {
        pub const FailSafeExpiryLengthSeconds: u32 = 0;
        pub const MaxCumulativeFailsafeSeconds: u32 = 1;
    }
/** This command is used to arm or disarm the fail-safe timer. */
    pub mod ArmFailSafe {
        pub const ExpiryLengthSeconds: u32 = 0;
        pub const Breadcrumb: u32 = 1;
    }
/** This command is used to report the result of the ArmFailSafe command. */
    pub mod ArmFailSafeResponse {
        pub const ErrorCode: u32 = 0;
        pub const DebugText: u32 = 1;
    }
/** This command is used to set the regulatory configuration for the device. */
    pub mod SetRegulatoryConfig {
        pub const NewRegulatoryConfig: u32 = 0;
        pub const CountryCode: u32 = 1;
        pub const Breadcrumb: u32 = 2;
    }
/** This command is used to report the result of the SetRegulatoryConfig command. */
    pub mod SetRegulatoryConfigResponse {
        pub const ErrorCode: u32 = 0;
        pub const DebugText: u32 = 1;
    }
/** This command is used to report the result of the CommissioningComplete command. */
    pub mod CommissioningCompleteResponse {
        pub const ErrorCode: u32 = 0;
        pub const DebugText: u32 = 1;
    }
/** This command is used to set the user acknowledgements received in the Enhanced Setup Flow Terms & Conditions into the node. */
    pub mod SetTCAcknowledgements {
        pub const TCVersion: u32 = 0;
        pub const TCUserResponse: u32 = 1;
    }
/** This command is used to report the result of the SetTCAcknowledgements command. */
    pub mod SetTCAcknowledgementsResponse {
        pub const ErrorCode: u32 = 0;
    }
}
pub mod OperationalCredentials {
    pub mod FabricDescriptorStruct {
        pub const RootPublicKey: u32 = 1;
        pub const VendorID: u32 = 2;
        pub const FabricID: u32 = 3;
        pub const NodeID: u32 = 4;
        pub const Label: u32 = 5;
        pub const VIDVerificationStatement: u32 = 6;
    }
    pub mod NOCStruct {
        pub const NOC: u32 = 1;
        pub const ICAC: u32 = 2;
        pub const VVSC: u32 = 3;
    }
/** Sender is requesting attestation information from the receiver. */
    pub mod AttestationRequest {
        pub const AttestationNonce: u32 = 0;
    }
/** An attestation information confirmation from the server. */
    pub mod AttestationResponse {
        pub const AttestationElements: u32 = 0;
        pub const AttestationSignature: u32 = 1;
    }
/** Sender is requesting a device attestation certificate from the receiver. */
    pub mod CertificateChainRequest {
        pub const CertificateType: u32 = 0;
    }
/** A device attestation certificate (DAC) or product attestation intermediate (PAI) certificate from the server. */
    pub mod CertificateChainResponse {
        pub const Certificate: u32 = 0;
    }
/** Sender is requesting a certificate signing request (CSR) from the receiver. */
    pub mod CSRRequest {
        pub const CSRNonce: u32 = 0;
        pub const IsForUpdateNOC: u32 = 1;
    }
/** A certificate signing request (CSR) from the server. */
    pub mod CSRResponse {
        pub const NOCSRElements: u32 = 0;
        pub const AttestationSignature: u32 = 1;
    }
/** Sender is requesting to add the new node operational certificates. */
    pub mod AddNOC {
        pub const NOCValue: u32 = 0;
        pub const ICACValue: u32 = 1;
        pub const IPKValue: u32 = 2;
        pub const CaseAdminSubject: u32 = 3;
        pub const AdminVendorId: u32 = 4;
    }
/** This command SHALL replace the NOC and optional associated ICAC (if present) scoped under the accessing fabric upon successful validation of all arguments and preconditions. */
    pub mod UpdateNOC {
        pub const NOCValue: u32 = 0;
        pub const ICACValue: u32 = 1;
    }
/** Response to several commands in this cluster. */
    pub mod NOCResponse {
        pub const StatusCode: u32 = 0;
        pub const FabricIndex: u32 = 1;
        pub const DebugText: u32 = 2;
    }
/** This command SHALL be used by an Administrative Node to set the user-visible Label field for a given Fabric, as reflected by entries in the Fabrics attribute. */
    pub mod UpdateFabricLabel {
        pub const Label: u32 = 0;
    }
/** This command is used by Administrative Nodes to remove a given fabric index and delete all associated fabric-scoped data. */
    pub mod RemoveFabric {
        pub const FabricIndex: u32 = 0;
    }
/** This command SHALL add a Trusted Root CA Certificate, provided as its CHIP Certificate representation. */
    pub mod AddTrustedRootCertificate {
        pub const RootCACertificate: u32 = 0;
    }
/** This command SHALL be used to update any of the accessing fabric's associated VendorID, VidVerificatioNStatement or VVSC (Vendor Verification Signing Certificate). */
    pub mod SetVIDVerificationStatement {
        pub const VendorID: u32 = 0;
        pub const VIDVerificationStatement: u32 = 1;
        pub const VVSC: u32 = 2;
    }
/** This command SHALL be used to request that the server authenticate the fabric associated with the FabricIndex given. */
    pub mod SignVIDVerificationRequest {
        pub const FabricIndex: u32 = 0;
        pub const ClientChallenge: u32 = 1;
    }
/** This command SHALL contain the response of the SignVIDVerificationRequest. */
    pub mod SignVIDVerificationResponse {
        pub const FabricIndex: u32 = 0;
        pub const FabricBindingVersion: u32 = 1;
        pub const Signature: u32 = 2;
    }
}
pub mod TargetNavigator {
    pub mod TargetInfoStruct {
        pub const Identifier: u32 = 0;
        pub const Name: u32 = 1;
    }
/** Upon receipt, this SHALL navigation the UX to the target identified. */
    pub mod NavigateTarget {
        pub const Target: u32 = 0;
        pub const Data: u32 = 1;
    }
/** This command SHALL be generated in response to NavigateTarget commands. */
    pub mod NavigateTargetResponse {
        pub const Status: u32 = 0;
        pub const Data: u32 = 1;
    }
/** This field SHALL indicate the updated target list as defined by the TargetList attribute if there is a change in the list of targets. Otherwise this field can be omitted from the event. */
    pub mod TargetUpdated {
        pub const TargetList: u32 = 0;
        pub const CurrentTarget: u32 = 1;
        pub const Data: u32 = 2;
    }
}
pub mod FanControl {
/** This command speeds up or slows down the fan, in steps, without a client having to know the fan speed. */
    pub mod Step {
        pub const Direction: u32 = 0;
        pub const Wrap: u32 = 1;
        pub const LowestOff: u32 = 2;
    }
}
pub mod GlobalElements {
    pub mod AtomicAttributeStatusStruct {
        pub const AttributeID: u32 = 0;
        pub const StatusCode: u32 = 1;
    }
    pub mod CurrencyStruct {
        pub const Currency: u32 = 0;
        pub const DecimalPoints: u32 = 1;
    }
    pub mod ICECandidateStruct {
        pub const Candidate: u32 = 0;
        pub const SDPMid: u32 = 1;
        pub const SDPMLineIndex: u32 = 2;
    }
    pub mod ICEServerStruct {
        pub const URLs: u32 = 0;
        pub const Username: u32 = 1;
        pub const Credential: u32 = 2;
        pub const CAID: u32 = 3;
    }
    pub mod LocationDescriptorStruct {
        pub const LocationName: u32 = 0;
        pub const FloorNumber: u32 = 1;
        pub const AreaType: u32 = 2;
    }
    pub mod MeasurementAccuracyRangeStruct {
        pub const RangeMin: u32 = 0;
        pub const RangeMax: u32 = 1;
        pub const PercentMax: u32 = 2;
        pub const PercentMin: u32 = 3;
        pub const PercentTypical: u32 = 4;
        pub const FixedMax: u32 = 5;
        pub const FixedMin: u32 = 6;
        pub const FixedTypical: u32 = 7;
    }
    pub mod MeasurementAccuracyStruct {
        pub const MeasurementType: u32 = 0;
        pub const Measured: u32 = 1;
        pub const MinMeasuredValue: u32 = 2;
        pub const MaxMeasuredValue: u32 = 3;
        pub const AccuracyRanges: u32 = 4;
    }
    pub mod PowerThresholdStruct {
        pub const PowerThreshold: u32 = 0;
        pub const ApparentPowerThreshold: u32 = 1;
        pub const PowerThresholdSource: u32 = 2;
    }
    pub mod PriceStruct {
        pub const Amount: u32 = 0;
        pub const Currency: u32 = 1;
    }
    pub mod SemanticTagStruct {
        pub const MfgCode: u32 = 0;
        pub const NamespaceID: u32 = 1;
        pub const Tag: u32 = 2;
        pub const Label: u32 = 3;
    }
    pub mod ViewportStruct {
        pub const X1: u32 = 0;
        pub const Y1: u32 = 1;
        pub const X2: u32 = 2;
        pub const Y2: u32 = 3;
    }
    pub mod WebRTCSessionStruct {
        pub const ID: u32 = 0;
        pub const PeerNodeID: u32 = 1;
        pub const PeerEndpointID: u32 = 2;
        pub const StreamUsage: u32 = 3;
        pub const VideoStreamID: u32 = 4;
        pub const AudioStreamID: u32 = 5;
        pub const MetadataEnabled: u32 = 6;
        pub const VideoStreams: u32 = 7;
        pub const AudioStreams: u32 = 8;
    }
    pub mod AtomicResponse {
        pub const StatusCode: u32 = 0;
        pub const AttributeStatus: u32 = 1;
        pub const Timeout: u32 = 2;
    }
    pub mod AtomicRequest {
        pub const RequestType: u32 = 0;
        pub const AttributeRequests: u32 = 1;
        pub const Timeout: u32 = 2;
    }
}
pub mod DoorLock {
    pub mod CredentialStruct {
        pub const CredentialType: u32 = 0;
        pub const CredentialIndex: u32 = 1;
    }
/** This command causes the lock device to lock the door. */
    pub mod LockDoor {
        pub const PINCode: u32 = 0;
    }
/** This command causes the lock device to unlock the door. */
    pub mod UnlockDoor {
        pub const PINCode: u32 = 0;
    }
/** This command causes the lock device to unlock the door with a timeout parameter. */
    pub mod UnlockWithTimeout {
        pub const Timeout: u32 = 0;
        pub const PINCode: u32 = 1;
    }
/** Set a weekly repeating schedule for a specified user. */
    pub mod SetWeekDaySchedule {
        pub const WeekDayIndex: u32 = 0;
        pub const UserIndex: u32 = 1;
        pub const DaysMask: u32 = 2;
        pub const StartHour: u32 = 3;
        pub const StartMinute: u32 = 4;
        pub const EndHour: u32 = 5;
        pub const EndMinute: u32 = 6;
    }
/** Retrieve the specific weekly schedule for the specific user. */
    pub mod GetWeekDaySchedule {
        pub const WeekDayIndex: u32 = 0;
        pub const UserIndex: u32 = 1;
    }
/** Returns the weekly repeating schedule data for the specified schedule index. */
    pub mod GetWeekDayScheduleResponse {
        pub const WeekDayIndex: u32 = 0;
        pub const UserIndex: u32 = 1;
        pub const Status: u32 = 2;
        pub const DaysMask: u32 = 3;
        pub const StartHour: u32 = 4;
        pub const StartMinute: u32 = 5;
        pub const EndHour: u32 = 6;
        pub const EndMinute: u32 = 7;
    }
/** Clear the specific weekly schedule or all weekly schedules for the specific user. */
    pub mod ClearWeekDaySchedule {
        pub const WeekDayIndex: u32 = 0;
        pub const UserIndex: u32 = 1;
    }
/** Set a time-specific schedule ID for a specified user. */
    pub mod SetYearDaySchedule {
        pub const YearDayIndex: u32 = 0;
        pub const UserIndex: u32 = 1;
        pub const LocalStartTime: u32 = 2;
        pub const LocalEndTime: u32 = 3;
    }
/** Returns the year day schedule data for the specified schedule and user indexes. */
    pub mod GetYearDaySchedule {
        pub const YearDayIndex: u32 = 0;
        pub const UserIndex: u32 = 1;
    }
/** Returns the year day schedule data for the specified schedule and user indexes. */
    pub mod GetYearDayScheduleResponse {
        pub const YearDayIndex: u32 = 0;
        pub const UserIndex: u32 = 1;
        pub const Status: u32 = 2;
        pub const LocalStartTime: u32 = 3;
        pub const LocalEndTime: u32 = 4;
    }
/** Clears the specific year day schedule or all year day schedules for the specific user. */
    pub mod ClearYearDaySchedule {
        pub const YearDayIndex: u32 = 0;
        pub const UserIndex: u32 = 1;
    }
/** Set the holiday Schedule by specifying local start time and local end time with respect to any Lock Operating Mode. */
    pub mod SetHolidaySchedule {
        pub const HolidayIndex: u32 = 0;
        pub const LocalStartTime: u32 = 1;
        pub const LocalEndTime: u32 = 2;
        pub const OperatingMode: u32 = 3;
    }
/** Get the holiday schedule for the specified index. */
    pub mod GetHolidaySchedule {
        pub const HolidayIndex: u32 = 0;
    }
/** Returns the Holiday Schedule Entry for the specified Holiday ID. */
    pub mod GetHolidayScheduleResponse {
        pub const HolidayIndex: u32 = 0;
        pub const Status: u32 = 1;
        pub const LocalStartTime: u32 = 2;
        pub const LocalEndTime: u32 = 3;
        pub const OperatingMode: u32 = 4;
    }
/** Clears the holiday schedule or all holiday schedules. */
    pub mod ClearHolidaySchedule {
        pub const HolidayIndex: u32 = 0;
    }
/** Set User into the lock. */
    pub mod SetUser {
        pub const OperationType: u32 = 0;
        pub const UserIndex: u32 = 1;
        pub const UserName: u32 = 2;
        pub const UserUniqueID: u32 = 3;
        pub const UserStatus: u32 = 4;
        pub const UserType: u32 = 5;
        pub const CredentialRule: u32 = 6;
    }
/** Retrieve User. */
    pub mod GetUser {
        pub const UserIndex: u32 = 0;
    }
/** Returns the User for the specified UserIndex. */
    pub mod GetUserResponse {
        pub const UserIndex: u32 = 0;
        pub const UserName: u32 = 1;
        pub const UserUniqueID: u32 = 2;
        pub const UserStatus: u32 = 3;
        pub const UserType: u32 = 4;
        pub const CredentialRule: u32 = 5;
        pub const Credentials: u32 = 6;
        pub const CreatorFabricIndex: u32 = 7;
        pub const LastModifiedFabricIndex: u32 = 8;
        pub const NextUserIndex: u32 = 9;
    }
/** Clears a User or all Users. */
    pub mod ClearUser {
        pub const UserIndex: u32 = 0;
    }
/** Set a credential (e.g. PIN, RFID, Fingerprint, etc.) into the lock for a new user, existing user, or ProgrammingUser. */
    pub mod SetCredential {
        pub const OperationType: u32 = 0;
        pub const Credential: u32 = 1;
        pub const CredentialData: u32 = 2;
        pub const UserIndex: u32 = 3;
        pub const UserStatus: u32 = 4;
        pub const UserType: u32 = 5;
    }
/** Returns the status for setting the specified credential. */
    pub mod SetCredentialResponse {
        pub const Status: u32 = 0;
        pub const UserIndex: u32 = 1;
        pub const NextCredentialIndex: u32 = 2;
    }
/** Retrieve the status of a particular credential (e.g. PIN, RFID, Fingerprint, etc.) by index. */
    pub mod GetCredentialStatus {
        pub const Credential: u32 = 0;
    }
/** Returns the status for the specified credential. */
    pub mod GetCredentialStatusResponse {
        pub const CredentialExists: u32 = 0;
        pub const UserIndex: u32 = 1;
        pub const CreatorFabricIndex: u32 = 2;
        pub const LastModifiedFabricIndex: u32 = 3;
        pub const NextCredentialIndex: u32 = 4;
        pub const CredentialData: u32 = 5;
    }
/** Clear one, one type, or all credentials except ProgrammingPIN credential. */
    pub mod ClearCredential {
        pub const Credential: u32 = 0;
    }
/** This command causes the lock device to unlock the door without pulling the latch. */
    pub mod UnboltDoor {
        pub const PINCode: u32 = 0;
    }
/** This command communicates an Aliro Reader configuration to the lock. */
    pub mod SetAliroReaderConfig {
        pub const SigningKey: u32 = 0;
        pub const VerificationKey: u32 = 1;
        pub const GroupIdentifier: u32 = 2;
        pub const GroupResolvingKey: u32 = 3;
    }
/** The door lock cluster provides several alarms which can be sent when there is a critical state on the door lock. */
    pub mod DoorLockAlarm {
        pub const AlarmCode: u32 = 0;
    }
/** The door lock server sends out a DoorStateChange event when the door lock door state changes. */
    pub mod DoorStateChange {
        pub const DoorState: u32 = 0;
    }
/** The door lock server sends out a LockOperation event when the event is triggered by the various lock operation sources. */
    pub mod LockOperation {
        pub const LockOperationType: u32 = 0;
        pub const OperationSource: u32 = 1;
        pub const UserIndex: u32 = 2;
        pub const FabricIndex: u32 = 3;
        pub const SourceNode: u32 = 4;
        pub const Credentials: u32 = 5;
    }
/** The door lock server sends out a LockOperationError event when a lock operation fails for various reasons. */
    pub mod LockOperationError {
        pub const LockOperationType: u32 = 0;
        pub const OperationSource: u32 = 1;
        pub const OperationError: u32 = 2;
        pub const UserIndex: u32 = 3;
        pub const FabricIndex: u32 = 4;
        pub const SourceNode: u32 = 5;
        pub const Credentials: u32 = 6;
    }
/** The door lock server sends out a LockUserChange event when a lock user, schedule, or credential change has occurred. */
    pub mod LockUserChange {
        pub const LockDataType: u32 = 0;
        pub const DataOperationType: u32 = 1;
        pub const OperationSource: u32 = 2;
        pub const UserIndex: u32 = 3;
        pub const FabricIndex: u32 = 4;
        pub const SourceNode: u32 = 5;
        pub const DataIndex: u32 = 6;
    }
}
pub mod WebRTCTransportProvider {
    pub mod SFrameStruct {
        pub const CipherSuite: u32 = 0;
        pub const BaseKey: u32 = 1;
        pub const KID: u32 = 2;
    }
/** Requests that the Provider initiates a new session with the Offer / Answer flow in a way that allows for options to be passed and work with devices needing the standby flow. */
    pub mod SolicitOffer {
        pub const StreamUsage: u32 = 0;
        pub const OriginatingEndpointID: u32 = 1;
        pub const VideoStreamID: u32 = 2;
        pub const AudioStreamID: u32 = 3;
        pub const ICEServers: u32 = 4;
        pub const ICETransportPolicy: u32 = 5;
        pub const MetadataEnabled: u32 = 6;
        pub const SFrameConfig: u32 = 7;
        pub const VideoStreams: u32 = 8;
        pub const AudioStreams: u32 = 9;
    }
/** This command SHALL be generated in response to a SolicitOffer command. */
    pub mod SolicitOfferResponse {
        pub const WebRTCSessionID: u32 = 0;
        pub const DeferredOffer: u32 = 1;
        pub const VideoStreamID: u32 = 2;
        pub const AudioStreamID: u32 = 3;
    }
/** This command allows an SDP Offer to be set and start a new session. */
    pub mod ProvideOffer {
        pub const WebRTCSessionID: u32 = 0;
        pub const SDP: u32 = 1;
        pub const StreamUsage: u32 = 2;
        pub const OriginatingEndpointID: u32 = 3;
        pub const VideoStreamID: u32 = 4;
        pub const AudioStreamID: u32 = 5;
        pub const ICEServers: u32 = 6;
        pub const ICETransportPolicy: u32 = 7;
        pub const MetadataEnabled: u32 = 8;
        pub const SFrameConfig: u32 = 9;
        pub const VideoStreams: u32 = 10;
        pub const AudioStreams: u32 = 11;
    }
/** This command contains information about the session and streams created as a response to the requestor's offer. */
    pub mod ProvideOfferResponse {
        pub const WebRTCSessionID: u32 = 0;
        pub const VideoStreamID: u32 = 1;
        pub const AudioStreamID: u32 = 2;
    }
/** This command SHALL be initiated from a Node in response to an Offer that was previously received from a remote peer. */
    pub mod ProvideAnswer {
        pub const WebRTCSessionID: u32 = 0;
        pub const SDP: u32 = 1;
    }
/** This command allows for string based ICE candidates generated after the initial Offer / Answer exchange, via a JSEP onicecandidate event, a DOM rtcpeerconnectioniceevent event, or other WebRTC compliant implementations, to be added to a session during the gathering phase. */
    pub mod ProvideICECandidates {
        pub const WebRTCSessionID: u32 = 0;
        pub const ICECandidates: u32 = 1;
    }
/** This command instructs the stream provider to end the WebRTC session. */
    pub mod EndSession {
        pub const WebRTCSessionID: u32 = 0;
        pub const Reason: u32 = 1;
    }
}
pub mod ThreadBorderRouterManagement {
/** This command is sent in response to GetActiveDatasetRequest or GetPendingDatasetRequest command. */
    pub mod DatasetResponse {
        pub const Dataset: u32 = 0;
    }
/** This command SHALL be used to set the active Dataset of the Thread network to which the Border Router is connected, when there is no active dataset already. */
    pub mod SetActiveDatasetRequest {
        pub const ActiveDataset: u32 = 0;
        pub const Breadcrumb: u32 = 1;
    }
/** This command SHALL be used to set or update the pending Dataset of the Thread network to which the Border Router is connected, if the Border Router supports PANChange Feature. */
    pub mod SetPendingDatasetRequest {
        pub const PendingDataset: u32 = 0;
    }
}
pub mod CameraAVStreamManagement {
    pub mod AVMetadataStruct {
        pub const UTCTime: u32 = 1;
        pub const MotionZonesActive: u32 = 2;
        pub const BlackAndWhiteActive: u32 = 3;
        pub const UserDefined: u32 = 4;
    }
    pub mod AudioCapabilitiesStruct {
        pub const MaxNumberOfChannels: u32 = 0;
        pub const SupportedCodecs: u32 = 1;
        pub const SupportedSampleRates: u32 = 2;
        pub const SupportedBitDepths: u32 = 3;
    }
    pub mod AudioStreamStruct {
        pub const AudioStreamID: u32 = 0;
        pub const StreamUsage: u32 = 1;
        pub const AudioCodec: u32 = 2;
        pub const ChannelCount: u32 = 3;
        pub const SampleRate: u32 = 4;
        pub const BitRate: u32 = 5;
        pub const BitDepth: u32 = 6;
        pub const ReferenceCount: u32 = 7;
    }
    pub mod RateDistortionTradeOffPointsStruct {
        pub const Codec: u32 = 0;
        pub const Resolution: u32 = 1;
        pub const MinBitRate: u32 = 2;
    }
    pub mod SnapshotCapabilitiesStruct {
        pub const Resolution: u32 = 0;
        pub const MaxFrameRate: u32 = 1;
        pub const ImageCodec: u32 = 2;
        pub const RequiresEncodedPixels: u32 = 3;
        pub const RequiresHardwareEncoder: u32 = 4;
    }
    pub mod SnapshotStreamStruct {
        pub const SnapshotStreamID: u32 = 0;
        pub const ImageCodec: u32 = 1;
        pub const FrameRate: u32 = 2;
        pub const MinResolution: u32 = 3;
        pub const MaxResolution: u32 = 4;
        pub const Quality: u32 = 5;
        pub const ReferenceCount: u32 = 6;
        pub const EncodedPixels: u32 = 7;
        pub const HardwareEncoder: u32 = 8;
        pub const WatermarkEnabled: u32 = 9;
        pub const OSDEnabled: u32 = 10;
    }
    pub mod VideoResolutionStruct {
        pub const Width: u32 = 0;
        pub const Height: u32 = 1;
    }
    pub mod VideoSensorParamsStruct {
        pub const SensorWidth: u32 = 0;
        pub const SensorHeight: u32 = 1;
        pub const MaxFPS: u32 = 2;
        pub const MaxHDRFPS: u32 = 3;
    }
    pub mod VideoStreamStruct {
        pub const VideoStreamID: u32 = 0;
        pub const StreamUsage: u32 = 1;
        pub const VideoCodec: u32 = 2;
        pub const MinFrameRate: u32 = 3;
        pub const MaxFrameRate: u32 = 4;
        pub const MinResolution: u32 = 5;
        pub const MaxResolution: u32 = 6;
        pub const MinBitRate: u32 = 7;
        pub const MaxBitRate: u32 = 8;
        pub const KeyFrameInterval: u32 = 9;
        pub const WatermarkEnabled: u32 = 10;
        pub const OSDEnabled: u32 = 11;
        pub const ReferenceCount: u32 = 12;
    }
/** This command SHALL allocate an audio stream on the camera and return an allocated audio stream identifier. */
    pub mod AudioStreamAllocate {
        pub const StreamUsage: u32 = 0;
        pub const AudioCodec: u32 = 1;
        pub const ChannelCount: u32 = 2;
        pub const SampleRate: u32 = 3;
        pub const BitRate: u32 = 4;
        pub const BitDepth: u32 = 5;
    }
/** This command SHALL be sent by the camera in response to the AudioStreamAllocate command, carrying the newly allocated or re-used audio stream identifier. */
    pub mod AudioStreamAllocateResponse {
        pub const AudioStreamID: u32 = 0;
    }
/** This command SHALL deallocate an audio stream on the camera, corresponding to the given audio stream identifier. */
    pub mod AudioStreamDeallocate {
        pub const AudioStreamID: u32 = 0;
    }
/** This command SHALL allocate a video stream on the camera and return an allocated video stream identifier. */
    pub mod VideoStreamAllocate {
        pub const StreamUsage: u32 = 0;
        pub const VideoCodec: u32 = 1;
        pub const MinFrameRate: u32 = 2;
        pub const MaxFrameRate: u32 = 3;
        pub const MinResolution: u32 = 4;
        pub const MaxResolution: u32 = 5;
        pub const MinBitRate: u32 = 6;
        pub const MaxBitRate: u32 = 7;
        pub const KeyFrameInterval: u32 = 8;
        pub const WatermarkEnabled: u32 = 9;
        pub const OSDEnabled: u32 = 10;
    }
/** This command SHALL be sent by the camera in response to the VideoStreamAllocate command, carrying the newly allocated or re-used video stream identifier. */
    pub mod VideoStreamAllocateResponse {
        pub const VideoStreamID: u32 = 0;
    }
/** This command SHALL be used to modify a stream specified by the VideoStreamID. */
    pub mod VideoStreamModify {
        pub const VideoStreamID: u32 = 0;
        pub const WatermarkEnabled: u32 = 1;
        pub const OSDEnabled: u32 = 2;
    }
/** This command SHALL deallocate a video stream on the camera, corresponding to the given video stream identifier. */
    pub mod VideoStreamDeallocate {
        pub const VideoStreamID: u32 = 0;
    }
/** This command SHALL allocate a snapshot stream on the device and return an allocated snapshot stream identifier. */
    pub mod SnapshotStreamAllocate {
        pub const ImageCodec: u32 = 0;
        pub const MaxFrameRate: u32 = 1;
        pub const MinResolution: u32 = 2;
        pub const MaxResolution: u32 = 3;
        pub const Quality: u32 = 4;
        pub const WatermarkEnabled: u32 = 5;
        pub const OSDEnabled: u32 = 6;
    }
/** This command SHALL be sent by the device in response to the SnapshotStreamAllocate command, carrying the newly allocated or re-used snapshot stream identifier. */
    pub mod SnapshotStreamAllocateResponse {
        pub const SnapshotStreamID: u32 = 0;
    }
/** This command SHALL be used to modify a stream specified by the VideoStreamID. */
    pub mod SnapshotStreamModify {
        pub const SnapshotStreamID: u32 = 0;
        pub const WatermarkEnabled: u32 = 1;
        pub const OSDEnabled: u32 = 2;
    }
/** This command SHALL deallocate an snapshot stream on the camera, corresponding to the given snapshot stream identifier. */
    pub mod SnapshotStreamDeallocate {
        pub const SnapshotStreamID: u32 = 0;
    }
/** This command SHALL set the relative priorities of the various stream usages on the camera. */
    pub mod SetStreamPriorities {
        pub const StreamPriorities: u32 = 0;
    }
/** This command SHALL return a Snapshot from the camera. */
    pub mod CaptureSnapshot {
        pub const SnapshotStreamID: u32 = 0;
        pub const RequestedResolution: u32 = 1;
    }
/** This command SHALL be sent by the device in response to the CaptureSnapshot command, carrying the requested snapshot. */
    pub mod CaptureSnapshotResponse {
        pub const Data: u32 = 0;
        pub const ImageCodec: u32 = 1;
        pub const Resolution: u32 = 2;
    }
}
pub mod JointFabricAdministrator {
/** This command SHALL be generated in response to a ICACCSRRequest command. */
    pub mod ICACCSRResponse {
        pub const ICACCSR: u32 = 0;
    }
/** This command SHALL be generated and executed during Joint Commissioning Method and subsequently be responded in the form of an ICACResponse command. */
    pub mod AddICAC {
        pub const ICACValue: u32 = 1;
    }
/** This command SHALL be generated in response to the AddICAC command. */
    pub mod ICACResponse {
        pub const StatusCode: u32 = 0;
    }
/** This command SHALL fail with a InvalidAdministratorFabricIndex status code sent back to the initiator if the AdministratorFabricIndex field has the value of null. */
    pub mod OpenJointCommissioningWindow {
        pub const CommissioningTimeout: u32 = 0;
        pub const PAKEPasscodeVerifier: u32 = 1;
        pub const Discriminator: u32 = 2;
        pub const Iterations: u32 = 3;
        pub const Salt: u32 = 4;
    }
/** This command SHALL be generated in response to the Transfer Anchor Request command. */
    pub mod TransferAnchorResponse {
        pub const StatusCode: u32 = 0;
    }
/** This command SHALL be used for communicating to client the endpoint that holds the Joint Fabric Administrator Cluster. */
    pub mod AnnounceJointFabricAdministrator {
        pub const EndpointID: u32 = 0;
    }
}
pub mod RVCOperationalState {
    pub mod ErrorStateStruct {
        pub const ErrorStateID: u32 = 0;
        pub const ErrorStateLabel: u32 = 1;
        pub const ErrorStateDetails: u32 = 2;
    }
    pub mod OperationalStateStruct {
        pub const OperationalStateID: u32 = 0;
        pub const OperationalStateLabel: u32 = 1;
    }
/** This command SHALL be generated in response to any of the Start, Stop, Pause, or Resume commands. */
    pub mod OperationalCommandResponse {
        pub const CommandResponseState: u32 = 0;
    }
/** OperationalError */
    pub mod OperationalError {
        pub const ErrorState: u32 = 0;
    }
/** OperationCompletion */
    pub mod OperationCompletion {
        pub const CompletionErrorCode: u32 = 0;
        pub const TotalOperationalTime: u32 = 1;
        pub const PausedTime: u32 = 2;
    }
}
pub mod KeypadInput {
/** Upon receipt, this SHALL process a keycode as input to the media endpoint. */
    pub mod SendKey {
        pub const KeyCode: u32 = 0;
    }
/** This command SHALL be generated in response to a SendKey command. */
    pub mod SendKeyResponse {
        pub const Status: u32 = 0;
    }
}
pub mod Groups {
/** The AddGroup command allows a client to add group membership in a particular group for the server endpoint. */
    pub mod AddGroup {
        pub const GroupID: u32 = 0;
        pub const GroupName: u32 = 1;
    }
/** The AddGroupResponse is sent by the Groups cluster server in response to an AddGroup command. */
    pub mod AddGroupResponse {
        pub const Status: u32 = 0;
        pub const GroupID: u32 = 1;
    }
/** The ViewGroup command allows a client to request that the server responds with a ViewGroupResponse command containing the name string for a particular group. */
    pub mod ViewGroup {
        pub const GroupID: u32 = 0;
    }
/** The ViewGroupResponse command is sent by the Groups cluster server in response to a ViewGroup command. */
    pub mod ViewGroupResponse {
        pub const Status: u32 = 0;
        pub const GroupID: u32 = 1;
        pub const GroupName: u32 = 2;
    }
/** The GetGroupMembership command allows a client to inquire about the group membership of the server endpoint, in a number of ways. */
    pub mod GetGroupMembership {
        pub const GroupList: u32 = 0;
    }
/** The GetGroupMembershipResponse command is sent by the Groups cluster server in response to a GetGroupMembership command. */
    pub mod GetGroupMembershipResponse {
        pub const Capacity: u32 = 0;
        pub const GroupList: u32 = 1;
    }
/** The RemoveGroup command allows a client to request that the server removes the membership for the server endpoint, if any, in a particular group. */
    pub mod RemoveGroup {
        pub const GroupID: u32 = 0;
    }
/** The RemoveGroupResponse command is generated by the server in response to the receipt of a RemoveGroup command. */
    pub mod RemoveGroupResponse {
        pub const Status: u32 = 0;
        pub const GroupID: u32 = 1;
    }
/** The AddGroupIfIdentifying command allows a client to add group membership in a particular group for the server endpoint, on condition that the endpoint is identifying itself. */
    pub mod AddGroupIfIdentifying {
        pub const GroupID: u32 = 0;
        pub const GroupName: u32 = 1;
    }
}
pub mod ClosureDimension {
    pub mod DimensionStateStruct {
        pub const Position: u32 = 0;
        pub const Latch: u32 = 1;
        pub const Speed: u32 = 2;
    }
    pub mod RangePercent100thsStruct {
        pub const Min: u32 = 0;
        pub const Max: u32 = 1;
    }
    pub mod UnitRangeStruct {
        pub const Min: u32 = 0;
        pub const Max: u32 = 1;
    }
/** This command is used to move a dimension of the closure to a target position. */
    pub mod SetTarget {
        pub const Position: u32 = 0;
        pub const Latch: u32 = 1;
        pub const Speed: u32 = 2;
    }
/** This command is used to move a dimension of the closure to a target position by a number of steps. */
    pub mod Step {
        pub const Direction: u32 = 0;
        pub const NumberOfSteps: u32 = 1;
        pub const Speed: u32 = 2;
    }
}
pub mod RefrigeratorAlarm {
    pub mod Reset {
        pub const Alarms: u32 = 0;
    }
    pub mod ModifyEnabledAlarms {
        pub const Mask: u32 = 0;
    }
/** This event SHALL be generated when one or more alarms change state. */
    pub mod Notify {
        pub const Active: u32 = 0;
        pub const Inactive: u32 = 1;
        pub const State: u32 = 2;
        pub const Mask: u32 = 3;
    }
}
pub mod MediaInput {
    pub mod InputInfoStruct {
        pub const Index: u32 = 0;
        pub const InputType: u32 = 1;
        pub const Name: u32 = 2;
        pub const Description: u32 = 3;
    }
/** Upon receipt, this command SHALL change the media input on the device to the input at a specific index in the Input List. */
    pub mod SelectInput {
        pub const Index: u32 = 0;
    }
/** Upon receipt, this command SHALL rename the input at a specific index in the Input List. */
    pub mod RenameInput {
        pub const Index: u32 = 0;
        pub const Name: u32 = 1;
    }
}
pub mod OccupancySensing {
    pub mod HoldTimeLimitsStruct {
        pub const HoldTimeMin: u32 = 0;
        pub const HoldTimeMax: u32 = 1;
        pub const HoldTimeDefault: u32 = 2;
    }
/** If this event is supported, it SHALL be generated when the Occupancy attribute changes. */
    pub mod OccupancyChanged {
        pub const Occupancy: u32 = 0;
    }
}
pub mod TLSCertificateManagement {
    pub mod TLSCertStruct {
        pub const CAID: u32 = 0;
        pub const Certificate: u32 = 1;
    }
    pub mod TLSClientCertificateDetailStruct {
        pub const CCDID: u32 = 0;
        pub const ClientCertificate: u32 = 1;
        pub const IntermediateCertificates: u32 = 2;
    }
/** This command SHALL provision a newly provided certificate, or rotate an existing one, based on the contents of the CAID field. */
    pub mod ProvisionRootCertificate {
        pub const Certificate: u32 = 0;
        pub const CAID: u32 = 1;
    }
/** This command SHALL be generated in response to a ProvisionRootCertificate command. */
    pub mod ProvisionRootCertificateResponse {
        pub const CAID: u32 = 0;
    }
/** This command SHALL return the specified TLS root certificate, or all provisioned TLS root certificates for the accessing fabric, based on the contents of the CAID field. */
    pub mod FindRootCertificate {
        pub const CAID: u32 = 0;
    }
/** This command SHALL be generated in response to a FindRootCertificate command. */
    pub mod FindRootCertificateResponse {
        pub const CertificateDetails: u32 = 0;
    }
/** This command SHALL return the CAID for the passed in fingerprint. */
    pub mod LookupRootCertificate {
        pub const Fingerprint: u32 = 0;
    }
/** This command SHALL be generated in response to a LookupRootCertificate command. */
    pub mod LookupRootCertificateResponse {
        pub const CAID: u32 = 0;
    }
/** This command SHALL be generated to request the server removes the certificate provisioned to the provided Certificate Authority ID. */
    pub mod RemoveRootCertificate {
        pub const CAID: u32 = 0;
    }
/** This command SHALL be generated to request the Node generates a certificate signing request for a new TLS key pair or use an existing CCDID for certificate rotation. */
    pub mod ClientCSR {
        pub const Nonce: u32 = 0;
        pub const CCDID: u32 = 1;
    }
/** This command SHALL be generated in response to a ClientCSR command. */
    pub mod ClientCSRResponse {
        pub const CCDID: u32 = 0;
        pub const CSR: u32 = 1;
        pub const NonceSignature: u32 = 2;
    }
/** This command SHALL be generated to request the Node provisions newly provided Client Certificate Details, or rotate an existing client certificate. */
    pub mod ProvisionClientCertificate {
        pub const CCDID: u32 = 0;
        pub const ClientCertificate: u32 = 1;
        pub const IntermediateCertificates: u32 = 2;
    }
/** This command SHALL return the TLSClientCertificateDetailStruct for the passed in CCDID, or all TLS client certificates for the accessing fabric, based on the contents of the CCDID field. */
    pub mod FindClientCertificate {
        pub const CCDID: u32 = 0;
    }
/** This command SHALL be generated in response to a FindClientCertificate command. */
    pub mod FindClientCertificateResponse {
        pub const CertificateDetails: u32 = 0;
    }
/** This command SHALL return the CCDID for the passed in Fingerprint. */
    pub mod LookupClientCertificate {
        pub const Fingerprint: u32 = 0;
    }
/** This command SHALL be generated in response to a LookupClientCertificate command. */
    pub mod LookupClientCertificateResponse {
        pub const CCDID: u32 = 0;
    }
/** This command SHALL be used to request the Node removes all stored information for the provided CCDID. */
    pub mod RemoveClientCertificate {
        pub const CCDID: u32 = 0;
    }
}
pub mod CommodityTariff {
    pub mod AuxiliaryLoadSwitchSettingsStruct {
        pub const Number: u32 = 0;
        pub const RequiredState: u32 = 1;
    }
    pub mod AuxiliaryLoadSwitchesSettingsStruct {
        pub const SwitchStates: u32 = 0;
    }
    pub mod CalendarPeriodStruct {
        pub const StartDate: u32 = 0;
        pub const DayPatternIDs: u32 = 1;
    }
    pub mod DayEntryStruct {
        pub const DayEntryID: u32 = 0;
        pub const StartTime: u32 = 1;
        pub const Duration: u32 = 2;
        pub const RandomizationOffset: u32 = 3;
        pub const RandomizationType: u32 = 4;
    }
    pub mod DayPatternStruct {
        pub const DayPatternID: u32 = 0;
        pub const DaysOfWeek: u32 = 1;
        pub const DayEntryIDs: u32 = 2;
    }
    pub mod DayStruct {
        pub const Date: u32 = 0;
        pub const DayType: u32 = 1;
        pub const DayEntryIDs: u32 = 2;
    }
    pub mod PeakPeriodStruct {
        pub const Severity: u32 = 0;
        pub const PeakPeriod: u32 = 1;
    }
    pub mod TariffComponentStruct {
        pub const TariffComponentID: u32 = 0;
        pub const Price: u32 = 1;
        pub const FriendlyCredit: u32 = 2;
        pub const AuxiliaryLoad: u32 = 3;
        pub const PeakPeriod: u32 = 4;
        pub const PowerThreshold: u32 = 5;
        pub const Threshold: u32 = 6;
        pub const Label: u32 = 7;
        pub const Predicted: u32 = 8;
    }
    pub mod TariffInformationStruct {
        pub const TariffLabel: u32 = 0;
        pub const ProviderName: u32 = 1;
        pub const Currency: u32 = 2;
        pub const BlockMode: u32 = 3;
    }
    pub mod TariffPeriodStruct {
        pub const Label: u32 = 0;
        pub const DayEntryIDs: u32 = 1;
        pub const TariffComponentIDs: u32 = 2;
    }
    pub mod TariffPriceStruct {
        pub const PriceType: u32 = 0;
        pub const Price: u32 = 1;
        pub const PriceLevel: u32 = 2;
    }
/** The GetTariffComponent command allows a client to request information for a tariff component identifier that may no longer be available in the TariffPeriods attributes. */
    pub mod GetTariffComponent {
        pub const TariffComponentID: u32 = 0;
    }
/** The GetTariffComponentResponse command is sent in response to a GetTariffComponent command. */
    pub mod GetTariffComponentResponse {
        pub const Label: u32 = 0;
        pub const DayEntryIDs: u32 = 1;
        pub const TariffComponent: u32 = 2;
    }
/** The GetDayEntry command allows a client to request information for a calendar day entry identifier that may no longer be available in the CalendarPeriods or IndividualDays attributes. */
    pub mod GetDayEntry {
        pub const DayEntryID: u32 = 0;
    }
/** The GetDayEntryResponse command is sent in response to a GetDayEntry command. */
    pub mod GetDayEntryResponse {
        pub const DayEntry: u32 = 0;
    }
}
pub mod Thermostat {
    pub mod PresetStruct {
        pub const PresetHandle: u32 = 0;
        pub const PresetScenario: u32 = 1;
        pub const Name: u32 = 2;
        pub const CoolingSetpoint: u32 = 3;
        pub const HeatingSetpoint: u32 = 4;
        pub const BuiltIn: u32 = 5;
    }
    pub mod PresetTypeStruct {
        pub const PresetScenario: u32 = 0;
        pub const NumberOfPresets: u32 = 1;
        pub const PresetTypeFeatures: u32 = 2;
    }
    pub mod ScheduleStruct {
        pub const ScheduleHandle: u32 = 0;
        pub const SystemMode: u32 = 1;
        pub const Name: u32 = 2;
        pub const PresetHandle: u32 = 3;
        pub const Transitions: u32 = 4;
        pub const BuiltIn: u32 = 5;
    }
    pub mod ScheduleTransitionStruct {
        pub const DayOfWeek: u32 = 0;
        pub const TransitionTime: u32 = 1;
        pub const PresetHandle: u32 = 2;
        pub const SystemMode: u32 = 3;
        pub const CoolingSetpoint: u32 = 4;
        pub const HeatingSetpoint: u32 = 5;
    }
    pub mod ScheduleTypeStruct {
        pub const SystemMode: u32 = 0;
        pub const NumberOfSchedules: u32 = 1;
        pub const ScheduleTypeFeatures: u32 = 2;
    }
    pub mod WeeklyScheduleTransitionStruct {
        pub const TransitionTime: u32 = 0;
        pub const HeatSetpoint: u32 = 1;
        pub const CoolSetpoint: u32 = 2;
    }
/** Upon receipt, the attributes for the indicated setpoint(s) SHALL have the amount specified in the Amount field added to them. */
    pub mod SetpointRaiseLower {
        pub const Mode: u32 = 0;
        pub const Amount: u32 = 1;
    }
/** Upon receipt, if the Schedules attribute contains a ScheduleStruct whose ScheduleHandle field matches the value of the ScheduleHandle field, the server SHALL set the thermostat's ActiveScheduleHandle attribute to the value of the ScheduleHandle field. */
    pub mod SetActiveScheduleRequest {
        pub const ScheduleHandle: u32 = 0;
    }
/** ID */
    pub mod SetActivePresetRequest {
        pub const PresetHandle: u32 = 0;
    }
}
pub mod Channel {
    pub mod ChannelInfoStruct {
        pub const MajorNumber: u32 = 0;
        pub const MinorNumber: u32 = 1;
        pub const Name: u32 = 2;
        pub const CallSign: u32 = 3;
        pub const AffiliateCallSign: u32 = 4;
        pub const Identifier: u32 = 5;
        pub const Type: u32 = 6;
    }
    pub mod ChannelPagingStruct {
        pub const PreviousToken: u32 = 0;
        pub const NextToken: u32 = 1;
    }
    pub mod LineupInfoStruct {
        pub const OperatorName: u32 = 0;
        pub const LineupName: u32 = 1;
        pub const PostalCode: u32 = 2;
        pub const LineupInfoType: u32 = 3;
    }
    pub mod PageTokenStruct {
        pub const Limit: u32 = 0;
        pub const After: u32 = 1;
        pub const Before: u32 = 2;
    }
    pub mod ProgramCastStruct {
        pub const Name: u32 = 0;
        pub const Role: u32 = 1;
    }
    pub mod ProgramCategoryStruct {
        pub const Category: u32 = 0;
        pub const SubCategory: u32 = 1;
    }
    pub mod ProgramStruct {
        pub const Identifier: u32 = 0;
        pub const Channel: u32 = 1;
        pub const StartTime: u32 = 2;
        pub const EndTime: u32 = 3;
        pub const Title: u32 = 4;
        pub const Subtitle: u32 = 5;
        pub const Description: u32 = 6;
        pub const AudioLanguages: u32 = 7;
        pub const Ratings: u32 = 8;
        pub const ThumbnailUrl: u32 = 9;
        pub const PosterArtUrl: u32 = 10;
        pub const DvbiUrl: u32 = 11;
        pub const ReleaseDate: u32 = 12;
        pub const ParentalGuidanceText: u32 = 13;
        pub const RecordingFlag: u32 = 14;
        pub const SeriesInfo: u32 = 15;
        pub const CategoryList: u32 = 16;
        pub const CastList: u32 = 17;
        pub const ExternalIDList: u32 = 18;
    }
    pub mod SeriesInfoStruct {
        pub const Season: u32 = 0;
        pub const Episode: u32 = 1;
    }
/** Change the channel on the media player to the channel case-insensitive exact matching the value passed as an argument. */
    pub mod ChangeChannel {
        pub const Match: u32 = 0;
    }
/** Upon receipt, this SHALL display the active status of the input list on screen. */
    pub mod ChangeChannelResponse {
        pub const Status: u32 = 0;
        pub const Data: u32 = 1;
    }
/** Change the channel on the media plaeyer to the channel with the given Number in the ChannelList attribute. */
    pub mod ChangeChannelByNumber {
        pub const MajorNumber: u32 = 0;
        pub const MinorNumber: u32 = 1;
    }
/** This command provides channel up and channel down functionality, but allows channel index jumps of size Count. When the value of the increase or decrease is larger than the number of channels remaining in the given direction, then the behavior SHALL be to return to the beginning (or end) of the channel list and continue. For example, if the current channel is at index 0 and count value of -1 is given, then the current channel should change to the last channel. */
    pub mod SkipChannel {
        pub const Count: u32 = 0;
    }
/** This command retrieves the program guide. It accepts several filter parameters to return specific schedule and program information from a content app. The command shall receive in response a ProgramGuideResponse. */
    pub mod GetProgramGuide {
        pub const StartTime: u32 = 0;
        pub const EndTime: u32 = 1;
        pub const ChannelList: u32 = 2;
        pub const PageToken: u32 = 3;
        pub const RecordingFlag: u32 = 5;
        pub const ExternalIDList: u32 = 6;
        pub const Data: u32 = 7;
    }
/** This command is a response to the GetProgramGuide command. */
    pub mod ProgramGuideResponse {
        pub const Paging: u32 = 0;
        pub const ProgramList: u32 = 1;
    }
/** Record a specific program or series when it goes live. This functionality enables DVR recording features. */
    pub mod RecordProgram {
        pub const ProgramIdentifier: u32 = 0;
        pub const ShouldRecordSeries: u32 = 1;
        pub const ExternalIDList: u32 = 2;
        pub const Data: u32 = 3;
    }
/** Cancel recording for a specific program or series. */
    pub mod CancelRecordProgram {
        pub const ProgramIdentifier: u32 = 0;
        pub const ShouldRecordSeries: u32 = 1;
        pub const ExternalIDList: u32 = 2;
        pub const Data: u32 = 3;
    }
}
pub mod EcosystemInformation {
    pub mod DeviceTypeStruct {
        pub const DeviceType: u32 = 0;
        pub const Revision: u32 = 1;
    }
    pub mod EcosystemDeviceStruct {
        pub const DeviceName: u32 = 0;
        pub const DeviceNameLastEdit: u32 = 1;
        pub const BridgedEndpoint: u32 = 2;
        pub const OriginalEndpoint: u32 = 3;
        pub const DeviceTypes: u32 = 4;
        pub const UniqueLocationIDs: u32 = 5;
        pub const UniqueLocationIDsLastEdit: u32 = 6;
    }
    pub mod EcosystemLocationStruct {
        pub const UniqueLocationID: u32 = 0;
        pub const LocationDescriptor: u32 = 1;
        pub const LocationDescriptorLastEdit: u32 = 2;
    }
}
pub mod OvenMode {
    pub mod ModeOptionStruct {
        pub const Label: u32 = 0;
        pub const Mode: u32 = 1;
        pub const ModeTags: u32 = 2;
    }
    pub mod ModeTagStruct {
        pub const MfgCode: u32 = 0;
        pub const Value: u32 = 1;
    }
/** This command is used to change device modes. */
    pub mod ChangeToMode {
        pub const NewMode: u32 = 0;
    }
/** This command is sent by the device on receipt of the ChangeToModeWithStatus command. */
    pub mod ChangeToModeResponse {
        pub const Status: u32 = 0;
        pub const StatusText: u32 = 1;
    }
}
pub mod DeviceEnergyManagement {
    pub mod ConstraintsStruct {
        pub const StartTime: u32 = 0;
        pub const Duration: u32 = 1;
        pub const NominalPower: u32 = 2;
        pub const MaximumEnergy: u32 = 3;
        pub const LoadControl: u32 = 4;
    }
    pub mod CostStruct {
        pub const CostType: u32 = 0;
        pub const Value: u32 = 1;
        pub const DecimalPoints: u32 = 2;
        pub const Currency: u32 = 3;
    }
    pub mod ForecastStruct {
        pub const ForecastID: u32 = 0;
        pub const ActiveSlotNumber: u32 = 1;
        pub const StartTime: u32 = 2;
        pub const EndTime: u32 = 3;
        pub const EarliestStartTime: u32 = 4;
        pub const LatestEndTime: u32 = 5;
        pub const IsPausable: u32 = 6;
        pub const Slots: u32 = 7;
        pub const ForecastUpdateReason: u32 = 8;
    }
    pub mod PowerAdjustCapabilityStruct {
        pub const PowerAdjustCapability: u32 = 0;
        pub const Cause: u32 = 1;
    }
    pub mod PowerAdjustStruct {
        pub const MinPower: u32 = 0;
        pub const MaxPower: u32 = 1;
        pub const MinDuration: u32 = 2;
        pub const MaxDuration: u32 = 3;
    }
    pub mod SlotAdjustmentStruct {
        pub const SlotIndex: u32 = 0;
        pub const NominalPower: u32 = 1;
        pub const Duration: u32 = 2;
    }
    pub mod SlotStruct {
        pub const MinDuration: u32 = 0;
        pub const MaxDuration: u32 = 1;
        pub const DefaultDuration: u32 = 2;
        pub const ElapsedSlotTime: u32 = 3;
        pub const RemainingSlotTime: u32 = 4;
        pub const SlotIsPausable: u32 = 5;
        pub const MinPauseDuration: u32 = 6;
        pub const MaxPauseDuration: u32 = 7;
        pub const ManufacturerESAState: u32 = 8;
        pub const NominalPower: u32 = 9;
        pub const MinPower: u32 = 10;
        pub const MaxPower: u32 = 11;
        pub const NominalEnergy: u32 = 12;
        pub const Costs: u32 = 13;
        pub const MinPowerAdjustment: u32 = 14;
        pub const MaxPowerAdjustment: u32 = 15;
        pub const MinDurationAdjustment: u32 = 16;
        pub const MaxDurationAdjustment: u32 = 17;
    }
/** Allows a client to request an adjustment in the power consumption of an ESA for a specified duration. */
    pub mod PowerAdjustRequest {
        pub const Power: u32 = 0;
        pub const Duration: u32 = 1;
        pub const Cause: u32 = 2;
    }
/** Allows a client to adjust the start time of a Forecast sequence that has not yet started operation (i.e. where the current Forecast StartTime is in the future). */
    pub mod StartTimeAdjustRequest {
        pub const RequestedStartTime: u32 = 0;
        pub const Cause: u32 = 1;
    }
/** Allows a client to temporarily pause an operation and reduce the ESAs energy demand. */
    pub mod PauseRequest {
        pub const Duration: u32 = 0;
        pub const Cause: u32 = 1;
    }
/** Allows a client to modify a Forecast within the limits allowed by the ESA. */
    pub mod ModifyForecastRequest {
        pub const ForecastID: u32 = 0;
        pub const SlotAdjustments: u32 = 1;
        pub const Cause: u32 = 2;
    }
/** Allows a client to ask the ESA to recompute its Forecast based on power and time constraints. */
    pub mod RequestConstraintBasedForecast {
        pub const Constraints: u32 = 0;
        pub const Cause: u32 = 1;
    }
/** This event SHALL be generated when the Power Adjustment session ends. */
    pub mod PowerAdjustEnd {
        pub const Cause: u32 = 0;
        pub const Duration: u32 = 1;
        pub const EnergyUse: u32 = 2;
    }
/** This event SHALL be generated when the ESA leaves the Paused state and resumes operation. */
    pub mod Resumed {
        pub const Cause: u32 = 0;
    }
}
pub mod TemperatureControl {
/** The SetTemperature command SHALL have the following data fields: */
    pub mod SetTemperature {
        pub const TargetTemperature: u32 = 0;
        pub const TargetTemperatureLevel: u32 = 1;
    }
}
pub mod DeviceEnergyManagementMode {
    pub mod ModeOptionStruct {
        pub const Label: u32 = 0;
        pub const Mode: u32 = 1;
        pub const ModeTags: u32 = 2;
    }
    pub mod ModeTagStruct {
        pub const MfgCode: u32 = 0;
        pub const Value: u32 = 1;
    }
/** This command is used to change device modes. */
    pub mod ChangeToMode {
        pub const NewMode: u32 = 0;
    }
/** This command is sent by the device on receipt of the ChangeToMode command. */
    pub mod ChangeToModeResponse {
        pub const Status: u32 = 0;
        pub const StatusText: u32 = 1;
    }
}
pub mod Chime {
    pub mod ChimeSoundStruct {
        pub const ChimeID: u32 = 0;
        pub const Name: u32 = 1;
    }
}
pub mod LaundryWasherMode {
    pub mod ModeOptionStruct {
        pub const Label: u32 = 0;
        pub const Mode: u32 = 1;
        pub const ModeTags: u32 = 2;
    }
    pub mod ModeTagStruct {
        pub const MfgCode: u32 = 0;
        pub const Value: u32 = 1;
    }
/** This command is used to change device modes.
 * On receipt of this command the device SHALL respond with a ChangeToModeResponse command. */
    pub mod ChangeToMode {
        pub const NewMode: u32 = 0;
    }
/** This command is sent by the device on receipt of the ChangeToModeWithStatus command. */
    pub mod ChangeToModeResponse {
        pub const Status: u32 = 0;
        pub const StatusText: u32 = 1;
    }
}
pub mod ValveConfigurationandControl {
/** This command is used to set the valve to its open position. */
    pub mod Open {
        pub const OpenDuration: u32 = 0;
        pub const TargetLevel: u32 = 1;
    }
/** This event SHALL be generated when the valve state changed. */
    pub mod ValveStateChanged {
        pub const ValveState: u32 = 0;
        pub const ValveLevel: u32 = 1;
    }
/** This event SHALL be generated when the valve registers or clears a fault, e.g. not being able to transition to the requested target level or state. */
    pub mod ValveFault {
        pub const ValveFault: u32 = 0;
    }
}
pub mod OvenCavityOperationalState {
    pub mod ErrorStateStruct {
        pub const ErrorStateID: u32 = 0;
        pub const ErrorStateLabel: u32 = 1;
        pub const ErrorStateDetails: u32 = 2;
    }
    pub mod OperationalStateStruct {
        pub const OperationalStateID: u32 = 0;
        pub const OperationalStateLabel: u32 = 1;
    }
/** This command SHALL be generated in response to any of the Start, Stop, Pause, or Resume commands. */
    pub mod OperationalCommandResponse {
        pub const CommandResponseState: u32 = 0;
    }
/** OperationalError */
    pub mod OperationalError {
        pub const ErrorState: u32 = 0;
    }
/** OperationCompletion */
    pub mod OperationCompletion {
        pub const CompletionErrorCode: u32 = 0;
        pub const TotalOperationalTime: u32 = 1;
        pub const PausedTime: u32 = 2;
    }
}
