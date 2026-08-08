libertas_matter_macros::matter_events! {
/** This cluster is used for managing the content control (including "parental control") settings on a media device such as a TV, or Set-top Box. */
pub mod ContentControl {
/** This event SHALL be generated when the RemainingScreenTime equals 0. */
    pub const RemainingScreenTimeExpired: u32 = 0x00;
/** This event SHALL be generated when entering a period of blocked content as configured in the BlockContentTimeWindow attribute. */
    pub const EnteringBlockContentTimeWindow: u32 = 0x01;
}
/** This cluster exposes interactions with a switch device, for the purpose of using those interactions by other devices.
 * Two types of switch devices are supported: latching switch (e.g. rocker switch) and momentary switch (e.g. push button), distinguished with their feature flags.
 * Interactions with the switch device are exposed as attributes (for the latching switch) and as events (for both types of switches). An interested party MAY subscribe to these attributes/events and thus be informed of the interactions, and can perform actions based on this, for example by sending commands to perform an action such as controlling a light or a window shade. */
pub mod Switch {
/** This event SHALL be generated, when the latching switch is moved to a new position. */
    pub const SwitchLatched: u32 = 0x00;
/** This event SHALL be generated, when the momentary switch starts to be pressed (after debouncing). */
    pub const InitialPress: u32 = 0x01;
/** This event SHALL be generated when the momentary switch has been pressed for a "long" time. */
    pub const LongPress: u32 = 0x02;
/** If the server has the Action Switch (AS) feature flag set, this event SHALL NOT be generated at all, since setting the Action Switch feature flag forbids the Momentary Switch ShortRelease (MSR) feature flag from being set. */
    pub const ShortRelease: u32 = 0x03;
/** This event SHALL be generated, when the momentary switch has been released (after debouncing) and after having been pressed for a long time, i.e. this event SHALL be generated when the switch is released if a LongPress event has been generated since the previous InitialPress event. */
    pub const LongRelease: u32 = 0x04;
/** If the server has the Action Switch (AS) feature flag set, this event SHALL NOT be generated at all. */
    pub const MultiPressOngoing: u32 = 0x05;
/** This event SHALL be generated to indicate how many times the momentary switch has been pressed in a multi-press sequence, after it has been detected that the sequence has ended. */
    pub const MultiPressComplete: u32 = 0x06;
}
/** This cluster is used to allow clients to control the operation of a hot water heating appliance so that it can be used with energy management. */
pub mod WaterHeaterManagement {
/** This event SHALL be generated whenever a Boost command is accepted. */
    pub const BoostStarted: u32 = 0x00;
/** This event SHALL be generated whenever the BoostState transitions from Active to Inactive. */
    pub const BoostEnded: u32 = 0x01;
}
/** The General Diagnostics Cluster, along with other diagnostics clusters, provide a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub mod GeneralDiagnostics {
/** Indicate a change in the set of hardware faults currently detected by the Node. */
    pub const HardwareFaultChange: u32 = 0x00;
/** Indicate a change in the set of radio faults currently detected by the Node. */
    pub const RadioFaultChange: u32 = 0x01;
/** Indicate a change in the set of network faults currently detected by the Node. */
    pub const NetworkFaultChange: u32 = 0x02;
/** Indicate the reason that caused the device to start-up. */
    pub const BootReason: u32 = 0x03;
}
/** Accurate time is required for a number of reasons, including scheduling, display and validating security materials. */
pub mod TimeSynchronization {
/** This event SHALL be generated when the node stops applying the current DSTOffset and there are no entries in the list with a larger ValidStarting time, indicating the need to possibly get new DST data. */
    pub const DSTTableEmpty: u32 = 0x00;
/** This event SHALL be generated when the node starts or stops applying a DST offset. */
    pub const DSTStatus: u32 = 0x01;
/** This event SHALL be generated when the node changes its time zone offset or name. */
    pub const TimeZoneStatus: u32 = 0x02;
/** This event SHALL be generated if the node has not generated a TimeFailure event in the last hour, and the node is unable to get a time from any source. */
    pub const TimeFailure: u32 = 0x03;
/** This event SHALL be generated if the TrustedTimeSource is set to null upon fabric removal or by a SetTrustedTimeSource command. */
    pub const MissingTrustedTimeSource: u32 = 0x04;
}
/** This cluster provides an interface to a boolean state called StateValue. */
pub mod BooleanState {
/** If this event is supported, it SHALL be generated when the StateValue attribute changes. */
    pub const StateChange: u32 = 0x00;
}
/** The Commodity Price Cluster provides the mechanism for communicating Gas, Energy, or Water pricing information within the premises. */
pub mod CommodityPrice {
/** This event SHALL be generated when the value of the CurrentPrice attribute changes. */
    pub const PriceChange: u32 = 0x00;
}
/** The Thread Network Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems */
pub mod ThreadNetworkDiagnostics {
/** The ConnectionStatus Event SHALL indicate that a Node's connection status to a Thread network has changed. */
    pub const ConnectionStatus: u32 = 0x00;
/** The NetworkFaultChange Event SHALL indicate a change in the set of network faults currently detected by the Node. */
    pub const NetworkFaultChange: u32 = 0x01;
}
/** This cluster provides a standardized way for a Node (typically a Bridge, but could be any Node) to expose action information. */
pub mod Actions {
/** This event SHALL be generated when there is a change in the State of an ActionID during the execution of an action and the most recent command using that ActionID used an InvokeID data field. */
    pub const StateChanged: u32 = 0x00;
/** This event SHALL be generated when there is some error which prevents the action from its normal planned execution and the most recent command using that ActionID used an InvokeID data field. */
    pub const ActionFailed: u32 = 0x01;
}
/** Electric Vehicle Supply Equipment (EVSE) is equipment used to charge an Electric Vehicle (EV) or Plug-In Hybrid Electric Vehicle. This cluster provides an interface to the functionality of Electric Vehicle Supply Equipment (EVSE) management. */
pub mod EnergyEVSE {
/** This event SHALL be generated when the EV is plugged in. */
    pub const EVConnected: u32 = 0x00;
/** This event SHALL be generated when the EV is unplugged or not detected (having been previously plugged in). */
    pub const EVNotDetected: u32 = 0x01;
/** This event SHALL be generated whenever the EV starts charging or discharging, except when an EV has switched between charging and discharging under the control of the PowerAdjustment feature of the Device Energy Management cluster of the associated Device Energy Management device. */
    pub const EnergyTransferStarted: u32 = 0x02;
/** This event SHALL be generated whenever the EV stops charging or discharging, except when an EV has switched between charging and discharging under the control of the PowerAdjustment feature of the Device Energy Management cluster of the associated Device Energy Management device. */
    pub const EnergyTransferStopped: u32 = 0x03;
/** If the EVSE detects a fault it SHALL generate a Fault Event. */
    pub const Fault: u32 = 0x04;
/** This event SHALL be generated when a RFID card has been read. */
    pub const RFID: u32 = 0x05;
}
/** This Cluster serves two purposes towards a Node communicating with a Bridge: indicate that the functionality on
 * the Endpoint where it is placed (and its Parts) is bridged from a non-CHIP technology; and provide a centralized
 * collection of attributes that the Node MAY collect to aid in conveying information regarding the Bridged Device to a user,
 * such as the vendor name, the model name, or user-assigned name. */
pub mod BridgedDeviceBasicInformation {
/** The StartUp event SHALL be generated by a Node as soon as reasonable after completing a boot or reboot process. */
    pub const StartUp: u32 = 0x00;
/** The ShutDown event SHOULD be generated by a Node prior to any orderly shutdown sequence on a best-effort basis. */
    pub const ShutDown: u32 = 0x01;
/** The Leave event SHOULD be generated by the bridge when it detects that the associated device has left the non-Matter network. */
    pub const Leave: u32 = 0x02;
/** This event SHALL be generated when there is a change in the Reachable attribute. */
    pub const ReachableChanged: u32 = 0x03;
/** This event (when supported) SHALL be generated the next time a bridged device becomes active after a KeepActive command is received. */
    pub const ActiveChanged: u32 = 0x80;
}
/** The Software Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub mod SoftwareDiagnostics {
/** This Event SHALL be generated when a software fault occurs on the Node. */
    pub const SoftwareFault: u32 = 0x00;
}
/** This cluster provides an interface to manage regions of interest, or Zones, which can be either manufacturer or user defined. */
pub mod ZoneManagement {
/** This event SHALL be generated when a Zone is first triggered. */
    pub const ZoneTriggered: u32 = 0x00;
/** This event SHALL be generated when either the TriggerDetectedDuration value is exceeded by the TimeSinceInitialTrigger value or the MaxDuration value is exceeded by the TimeSinceInitialTrigger value, as described in xrefstyle=full. */
    pub const ZoneStopped: u32 = 0x01;
}
/** This cluster supports remotely monitoring and, where supported, changing the operational state of any device where a state machine is a part of the operation. */
pub mod OperationalState {
/** OperationalError */
    pub const OperationalError: u32 = 0x00;
/** OperationCompletion */
    pub const OperationCompletion: u32 = 0x01;
}
/** Supports the ability for clients to request the commissioning of themselves or other nodes onto a fabric which the cluster server can commission onto. */
pub mod CommissionerControl {
/** This event SHALL be generated by the server following a RequestCommissioningApproval command which the server responded to with SUCCESS. */
    pub const CommissioningRequestResult: u32 = 0x00;
}
/** This cluster implements the upload of Audio and Video streams from the Push AV Stream Transport Cluster using suitable push-based transports. */
pub mod PushAVStreamTransport {
/** This event SHALL indicate a push transport transmission has begun. */
    pub const PushTransportBegin: u32 = 0x00;
/** This event SHALL indicate a push transport upload of the indicated recording has completed. */
    pub const PushTransportEnd: u32 = 0x01;
}
/** Attributes and commands for configuring the Dishwasher alarm. */
pub mod DishwasherAlarm {
/** This event SHALL be generated when one or more alarms change state, and SHALL have these fields: */
    pub const Notify: u32 = 0x00;
}
/** This cluster provides an interface for observing and managing the state of smoke and CO alarms. */
pub mod SmokeCOAlarm {
/** This event SHALL be generated when SmokeState attribute changes to either Warning or Critical state. */
    pub const SmokeAlarm: u32 = 0x00;
/** This event SHALL be generated when COState attribute changes to either Warning or Critical state. */
    pub const COAlarm: u32 = 0x01;
/** This event SHALL be generated when BatteryAlert attribute changes to either Warning or Critical state. */
    pub const LowBattery: u32 = 0x02;
/** This event SHALL be generated when the device detects a hardware fault that leads to setting HardwareFaultAlert to True. */
    pub const HardwareFault: u32 = 0x03;
/** This event SHALL be generated when the EndOfServiceAlert is set to Expired. */
    pub const EndOfService: u32 = 0x04;
/** This event SHALL be generated when the SelfTest completes, and the attribute TestInProgress changes to False. */
    pub const SelfTestComplete: u32 = 0x05;
/** This event SHALL be generated when the DeviceMuted attribute changes to Muted. */
    pub const AlarmMuted: u32 = 0x06;
/** This event SHALL be generated when DeviceMuted attribute changes to NotMuted. */
    pub const MuteEnded: u32 = 0x07;
/** This event SHALL be generated when the device hosting the server receives a smoke alarm from an interconnected sensor. */
    pub const InterconnectSmokeAlarm: u32 = 0x08;
/** This event SHALL be generated when the device hosting the server receives a smoke alarm from an interconnected sensor. */
    pub const InterconnectCOAlarm: u32 = 0x09;
/** This event SHALL be generated when ExpressedState attribute returns to Normal state. */
    pub const AllClear: u32 = 0x0A;
}
/** This cluster provides an interface for passing messages to be presented by a device. */
pub mod Messages {
/** This event SHALL be generated when the message is confirmed by the user, or when the expiration date of the message is reached. */
    pub const MessageQueued: u32 = 0x00;
/** This event SHALL be generated when the message is presented to the user. */
    pub const MessagePresented: u32 = 0x01;
/** This event SHALL be generated when the message is confirmed by the user, or when the expiration date of the message is reached. */
    pub const MessageComplete: u32 = 0x02;
}
/** This cluster provides commands that facilitate user account login on a Content App or a node. For example, a Content App running on a Video Player device, which is represented as an endpoint (see [TV Architecture]), can use this cluster to help make the user account on the Content App match the user account on the Client. */
pub mod AccountLogin {
/** This event can be used by the Content App to indicate that the current user has logged out. */
    pub const LoggedOut: u32 = 0x00;
}
/** This cluster provides a mechanism for querying data about electrical power as measured by the server. */
pub mod ElectricalPowerMeasurement {
/** If supported, this event SHALL be generated at the end of a measurement period. */
    pub const MeasurementPeriodRanges: u32 = 0x00;
}
/** This cluster is used to describe the configuration and capabilities of a physical power source that provides power to the Node. */
pub mod PowerSource {
/** The WiredFaultChange Event SHALL be generated when the set of wired faults currently detected by the Node on this wired power source changes. */
    pub const WiredFaultChange: u32 = 0x00;
/** The BatFaultChange Event SHALL be generated when the set of battery faults currently detected by the Node on this battery power source changes. */
    pub const BatFaultChange: u32 = 0x01;
/** The BatChargeFaultChange Event SHALL be generated when the set of charge faults currently detected by the Node on this battery power source changes. */
    pub const BatChargeFaultChange: u32 = 0x02;
}
/** The Electrical Grid Conditions Cluster provides the mechanism for communicating electricity grid carbon intensity to devices within the premises in units of Grams of CO2e per kWh. */
pub mod ElectricalGridConditions {
/** This event SHALL be generated when the value of the CurrentConditions attribute changes. */
    pub const CurrentConditionsChanged: u32 = 0x00;
}
/** This cluster provides attributes and events for determining basic information about Nodes, which supports both
 * Commissioning and operational determination of Node characteristics, such as Vendor ID, Product ID and serial number,
 * which apply to the whole Node. Also allows setting user device information such as location. */
pub mod BasicInformation {
/** The StartUp event SHALL be generated by a Node as soon as reasonable after completing a boot or reboot process. */
    pub const StartUp: u32 = 0x00;
/** The ShutDown event SHOULD be generated by a Node prior to any orderly shutdown sequence on a best-effort basis. */
    pub const ShutDown: u32 = 0x01;
/** The Leave event SHOULD be generated by a Node prior to permanently leaving a given Fabric, such as when the RemoveFabric command is invoked for a given fabric, or triggered by factory reset or some other manufacturer specific action to disable or reset the operational data in the Node. */
    pub const Leave: u32 = 0x02;
/** This event (when supported) SHALL be generated when there is a change in the Reachable attribute. */
    pub const ReachableChanged: u32 = 0x03;
}
/** This cluster provides an interface for controlling Media Playback (PLAY, PAUSE, etc) on a media device such as a TV or Speaker. */
pub mod MediaPlayback {
/** If supported, this event SHALL be generated when there is a change in any of the supported attributes of the Media Playback cluster. */
    pub const StateChanged: u32 = 0x00;
}
/** The Wi-Fi Network Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub mod WiFiNetworkDiagnostics {
/** The Disconnection Event SHALL indicate that a Node's Wi-Fi connection has been disconnected as a result of de-authenticated or dis-association and indicates the reason. */
    pub const Disconnection: u32 = 0x00;
/** The AssociationFailure event SHALL indicate that a Node has attempted to connect, or reconnect, to a Wi-Fi access point, but is unable to successfully associate or authenticate, after exhausting all internal retries of its supplicant. */
    pub const AssociationFailure: u32 = 0x01;
/** The ConnectionStatus Event SHALL indicate that a Node's connection status to a Wi-Fi network has changed. */
    pub const ConnectionStatus: u32 = 0x02;
}
/** Provides an interface for downloading and applying OTA software updates */
pub mod OTASoftwareUpdateRequestor {
/** This event SHALL be generated when a change of the UpdateState attribute occurs due to an OTA Requestor moving through the states necessary to query for updates. */
    pub const StateTransition: u32 = 0x00;
/** This event SHALL be generated whenever a new version starts executing after being applied due to a software update. */
    pub const VersionApplied: u32 = 0x01;
/** This event SHALL be generated whenever an error occurs during OTA Requestor download operation. */
    pub const DownloadError: u32 = 0x02;
}
/** The Access Control Cluster exposes a data model view of a
 * Node's Access Control List (ACL), which codifies the rules used to manage
 * and enforce Access Control for the Node's endpoints and their associated
 * cluster instances. */
pub mod AccessControl {
/** The server SHALL generate AccessControlEntryChanged events whenever its ACL attribute data is changed by an Administrator. */
    pub const AccessControlEntryChanged: u32 = 0x00;
/** The server SHALL generate AccessControlExtensionChanged events whenever its extension attribute data is changed by an Administrator. */
    pub const AccessControlExtensionChanged: u32 = 0x01;
/** The server SHALL generate a FabricRestrictionReviewUpdate event to indicate completion of a fabric restriction review. */
    pub const FabricRestrictionReviewUpdate: u32 = 0x02;
}
/** This cluster provides a mechanism for querying data about the electrical energy imported or provided by the server. */
pub mod ElectricalEnergyMeasurement {
/** This event SHALL be generated when the server takes a snapshot of the cumulative energy imported by the server, exported from the server, or both, but not more frequently than the rate mentioned in the description above of the related attribute. */
    pub const CumulativeEnergyMeasured: u32 = 0x00;
/** This event SHALL be generated when the server reaches the end of a reporting period for imported energy, exported energy, or both. */
    pub const PeriodicEnergyMeasured: u32 = 0x01;
}
/** This cluster provides an interface for controlling a Closure. */
pub mod ClosureControl {
/** This event SHALL be generated when a reportable error condition is detected. */
    pub const OperationalError: u32 = 0x00;
/** This event, if supported, SHALL be generated when the overall operation ends, either successfully or otherwise. */
    pub const MovementCompleted: u32 = 0x01;
/** This event, if supported, SHALL be generated when the MainStateEnum attribute changes state to and from disengaged, indicating if the actuator is Engaged or Disengaged. */
    pub const EngageStateChanged: u32 = 0x02;
/** This event, if supported, SHALL be generated when the SecureState field in the OverallCurrentState attribute changes. */
    pub const SecureStateChanged: u32 = 0x03;
}
/** This cluster is used to configure a boolean sensor. */
pub mod BooleanStateConfiguration {
/** This event SHALL be generated after any bits in the AlarmsActive and/or AlarmsSuppressed attributes change. */
    pub const AlarmsStateChanged: u32 = 0x00;
/** This event SHALL be generated when the device registers or clears a fault. */
    pub const SensorFault: u32 = 0x01;
}
/** An interface for configuring and controlling pumps. */
pub mod PumpConfigurationandControl {
/** SupplyVoltageLow */
    pub const SupplyVoltageLow: u32 = 0x00;
/** SupplyVoltageHigh */
    pub const SupplyVoltageHigh: u32 = 0x01;
/** PowerMissingPhase */
    pub const PowerMissingPhase: u32 = 0x02;
/** SystemPressureLow */
    pub const SystemPressureLow: u32 = 0x03;
/** SystemPressureHigh */
    pub const SystemPressureHigh: u32 = 0x04;
/** DryRunning */
    pub const DryRunning: u32 = 0x05;
/** MotorTemperatureHigh */
    pub const MotorTemperatureHigh: u32 = 0x06;
/** PumpMotorFatalFailure */
    pub const PumpMotorFatalFailure: u32 = 0x07;
/** ElectronicTemperatureHigh */
    pub const ElectronicTemperatureHigh: u32 = 0x08;
/** PumpBlocked */
    pub const PumpBlocked: u32 = 0x09;
/** SensorFailure */
    pub const SensorFailure: u32 = 0x0A;
/** ElectronicNonFatalFailure */
    pub const ElectronicNonFatalFailure: u32 = 0x0B;
/** ElectronicFatalFailure */
    pub const ElectronicFatalFailure: u32 = 0x0C;
/** GeneralFault */
    pub const GeneralFault: u32 = 0x0D;
/** Leakage */
    pub const Leakage: u32 = 0x0E;
/** AirDetection */
    pub const AirDetection: u32 = 0x0F;
/** TurbineOperation */
    pub const TurbineOperation: u32 = 0x10;
}
/** This cluster provides an interface for UX navigation within a set of targets on a device or endpoint. */
pub mod TargetNavigator {
/** This field SHALL indicate the updated target list as defined by the TargetList attribute if there is a change in the list of targets. Otherwise this field can be omitted from the event. */
    pub const TargetUpdated: u32 = 0x00;
}
/** An interface to a generic way to secure a door */
pub mod DoorLock {
/** The door lock cluster provides several alarms which can be sent when there is a critical state on the door lock. */
    pub const DoorLockAlarm: u32 = 0x00;
/** The door lock server sends out a DoorStateChange event when the door lock door state changes. */
    pub const DoorStateChange: u32 = 0x01;
/** The door lock server sends out a LockOperation event when the event is triggered by the various lock operation sources. */
    pub const LockOperation: u32 = 0x02;
/** The door lock server sends out a LockOperationError event when a lock operation fails for various reasons. */
    pub const LockOperationError: u32 = 0x03;
/** The door lock server sends out a LockUserChange event when a lock user, schedule, or credential change has occurred. */
    pub const LockUserChange: u32 = 0x04;
}
/** This cluster supports remotely monitoring and, where supported, changing the operational state of a Robotic Vacuum. */
pub mod RVCOperationalState {
/** OperationalError */
    pub const OperationalError: u32 = 0x00;
/** OperationCompletion */
    pub const OperationCompletion: u32 = 0x01;
}
/** Attributes and commands for configuring the Refrigerator alarm. */
pub mod RefrigeratorAlarm {
/** This event SHALL be generated when one or more alarms change state. */
    pub const Notify: u32 = 0x00;
}
/** The server cluster provides an interface to occupancy sensing functionality based on one or more sensing modalities, including configuration and provision of notifications of occupancy status. */
pub mod OccupancySensing {
/** If this event is supported, it SHALL be generated when the Occupancy attribute changes. */
    pub const OccupancyChanged: u32 = 0x00;
}
/** This cluster allows a client to manage the power draw of a device. An example of such a client could be an Energy Management System (EMS) which controls an Energy Smart Appliance (ESA). */
pub mod DeviceEnergyManagement {
/** This event SHALL be generated when the Power Adjustment session is started. */
    pub const PowerAdjustStart: u32 = 0x00;
/** This event SHALL be generated when the Power Adjustment session ends. */
    pub const PowerAdjustEnd: u32 = 0x01;
/** This event SHALL be generated when the ESA enters the Paused state. */
    pub const Paused: u32 = 0x02;
/** This event SHALL be generated when the ESA leaves the Paused state and resumes operation. */
    pub const Resumed: u32 = 0x03;
}
/** This cluster is used to configure a valve. */
pub mod ValveConfigurationandControl {
/** This event SHALL be generated when the valve state changed. */
    pub const ValveStateChanged: u32 = 0x00;
/** This event SHALL be generated when the valve registers or clears a fault, e.g. not being able to transition to the requested target level or state. */
    pub const ValveFault: u32 = 0x01;
}
/** This cluster supports remotely monitoring and, where supported, changing the operational state of an Oven. */
pub mod OvenCavityOperationalState {
/** OperationalError */
    pub const OperationalError: u32 = 0x00;
/** OperationCompletion */
    pub const OperationCompletion: u32 = 0x01;
}
}
