libertas_matter_macros::matter_commands! {
/** This cluster is used for managing the content control (including "parental control") settings on a media device such as a TV, or Set-top Box. */
pub mod ContentControl {
/** The purpose of this command is to update the PIN used for protecting configuration of the content control settings. */
    pub const UpdatePIN: u32 = 0x00;
/** The purpose of this command is to reset the PIN. */
    pub const ResetPIN: u32 = 0x01;
/** This command SHALL be generated in response to a ResetPIN command. */
    pub const ResetPINResponse: u32 = 0x02;
/** The purpose of this command is to turn on the Content Control feature on a media device. */
    pub const Enable: u32 = 0x03;
/** The purpose of this command is to turn off the Content Control feature on a media device. */
    pub const Disable: u32 = 0x04;
/** The purpose of this command is to add the extra screen time for the user. */
    pub const AddBonusTime: u32 = 0x05;
/** The purpose of this command is to set the ScreenDailyTime attribute. */
    pub const SetScreenDailyTime: u32 = 0x06;
/** The purpose of this command is to specify whether programs with no Content rating must be blocked by this media device. */
    pub const BlockUnratedContent: u32 = 0x07;
/** The purpose of this command is to specify whether programs with no Content rating must be blocked by this media device. */
    pub const UnblockUnratedContent: u32 = 0x08;
/** The purpose of this command is to set the OnDemandRatingThreshold attribute. */
    pub const SetOnDemandRatingThreshold: u32 = 0x09;
/** The purpose of this command is to set ScheduledContentRatingThreshold attribute. */
    pub const SetScheduledContentRatingThreshold: u32 = 0x0A;
/** The purpose of this command is to set BlockChannelList attribute. */
    pub const AddBlockChannels: u32 = 0x0B;
/** The purpose of this command is to remove channels from the BlockChannelList attribute. */
    pub const RemoveBlockChannels: u32 = 0x0C;
/** The purpose of this command is to set applications to the BlockApplicationList attribute. */
    pub const AddBlockApplications: u32 = 0x0D;
/** The purpose of this command is to remove applications from the BlockApplicationList attribute. */
    pub const RemoveBlockApplications: u32 = 0x0E;
/** The purpose of this command is to set the BlockContentTimeWindow attribute. */
    pub const SetBlockContentTimeWindow: u32 = 0x0F;
/** The purpose of this command is to remove the selected time windows from the BlockContentTimeWindow attribute. */
    pub const RemoveBlockContentTimeWindow: u32 = 0x10;
}
/** Attributes and commands for configuring the microwave oven control, and reporting cooking stats. */
pub mod MicrowaveOvenControl {
/** This command is used to set the cooking parameters associated with the operation of the device. */
    pub const SetCookingParameters: u32 = 0x00;
/** This command is used to add more time to the CookTime attribute of the server. */
    pub const AddMoreTime: u32 = 0x01;
}
/** This cluster is used to allow clients to control the operation of a hot water heating appliance so that it can be used with energy management. */
pub mod WaterHeaterManagement {
/** Allows a client to request that the water heater is put into a Boost state. */
    pub const Boost: u32 = 0x00;
/** Allows a client to cancel an ongoing Boost operation. */
    pub const CancelBoost: u32 = 0x01;
}
/** The Ethernet Network Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub mod EthernetNetworkDiagnostics {
/** This command is used to reset the count attributes. */
    pub const ResetCounts: u32 = 0x00;
}
/** This cluster provides an interface for launching content on a media player device such as a TV or Speaker. */
pub mod ContentLauncher {
/** Upon receipt, this SHALL launch the specified content with optional search criteria. */
    pub const LaunchContent: u32 = 0x00;
/** Upon receipt, this SHALL launch content from the specified URL. */
    pub const LaunchURL: u32 = 0x01;
/** This command SHALL be generated in response to LaunchContent command. */
    pub const LauncherResponse: u32 = 0x02;
}
/** The General Diagnostics Cluster, along with other diagnostics clusters, provide a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub mod GeneralDiagnostics {
/** Provide a means for certification tests to trigger some test-plan-specific events */
    pub const TestEventTrigger: u32 = 0x00;
/** Take a snapshot of system time and epoch time. */
    pub const TimeSnapshot: u32 = 0x01;
/** Response for the TimeSnapshot command. */
    pub const TimeSnapshotResponse: u32 = 0x02;
/** Request a variable length payload response. */
    pub const PayloadTestRequest: u32 = 0x03;
/** Response for the PayloadTestRequest command. */
    pub const PayloadTestResponse: u32 = 0x04;
}
/** Allows servers to ensure that listed clients are notified when a server is available for communication. */
pub mod ICDManagement {
/** This command allows a client to register itself with the ICD to be notified when the device is available for communication. */
    pub const RegisterClient: u32 = 0x00;
/** This command SHALL be sent by the ICD Management Cluster server in response to a successful RegisterClient command. */
    pub const RegisterClientResponse: u32 = 0x01;
/** This command allows a client to unregister itself with the ICD. */
    pub const UnregisterClient: u32 = 0x02;
/** This command allows a client to request that the server stays in active mode for at least a given time duration (in milliseconds) from when this command is received. */
    pub const StayActiveRequest: u32 = 0x03;
/** This message SHALL be sent by the ICD in response to the StayActiveRequest command and SHALL contain the computed duration (in milliseconds) that the ICD intends to stay active for. */
    pub const StayActiveResponse: u32 = 0x04;
}
/** Functionality to configure, enable, disable network credentials and access on a Matter device. */
pub mod NetworkCommissioning {
/** Detemine the set of networks the device sees as available. */
    pub const ScanNetworks: u32 = 0x00;
/** Relay the set of networks the device sees as available back to the client. */
    pub const ScanNetworksResponse: u32 = 0x01;
/** Add or update the credentials for a given Wi-Fi network. */
    pub const AddOrUpdateWiFiNetwork: u32 = 0x02;
/** Add or update the credentials for a given Thread network. */
    pub const AddOrUpdateThreadNetwork: u32 = 0x03;
/** Remove the definition of a given network (including its credentials). */
    pub const RemoveNetwork: u32 = 0x04;
/** Response command for various commands that add/remove/modify network credentials. */
    pub const NetworkConfigResponse: u32 = 0x05;
/** Connect to the specified network, using previously-defined credentials. */
    pub const ConnectNetwork: u32 = 0x06;
/** Command that indicates whether we have succcessfully connected to a network. */
    pub const ConnectNetworkResponse: u32 = 0x07;
/** Modify the order in which networks will be presented in the Networks attribute. */
    pub const ReorderNetwork: u32 = 0x08;
}
/** Accurate time is required for a number of reasons, including scheduling, display and validating security materials. */
pub mod TimeSynchronization {
/** This command is used to set the UTC time of the node. */
    pub const SetUTCTime: u32 = 0x00;
/** This command is used to set the TrustedTimeSource attribute. */
    pub const SetTrustedTimeSource: u32 = 0x01;
/** This command is used to set the time zone of the node. */
    pub const SetTimeZone: u32 = 0x02;
/** THis command is used to report the result of a SetTimeZone command. */
    pub const SetTimeZoneResponse: u32 = 0x03;
/** This command is used to set the DST offsets for a node. */
    pub const SetDSTOffset: u32 = 0x04;
/** This command is used to set the DefaultNTP attribute. */
    pub const SetDefaultNTP: u32 = 0x05;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod RVCRunMode {
/** This command is used to change device modes.
 * On receipt of this command the device SHALL respond with a ChangeToModeResponse command. */
    pub const ChangeToMode: u32 = 0x00;
/** This command is sent by the device on receipt of the ChangeToModeWithStatus command. */
    pub const ChangeToModeResponse: u32 = 0x01;
}
/** The Commodity Price Cluster provides the mechanism for communicating Gas, Energy, or Water pricing information within the premises. */
pub mod CommodityPrice {
/** Upon receipt, this SHALL generate a GetDetailedPrice Response command. */
    pub const GetDetailedPriceRequest: u32 = 0x00;
/** This command SHALL be generated in response to a GetDetailedPrice Request command. */
    pub const GetDetailedPriceResponse: u32 = 0x01;
/** Upon receipt, this SHALL generate a GetDetailedForecast Response command. */
    pub const GetDetailedForecastRequest: u32 = 0x02;
/** This command SHALL be generated in response to a GetDetailedForecast Request command. */
    pub const GetDetailedForecastResponse: u32 = 0x03;
}
/** This cluster provides an interface for launching content on a media player device such as a TV or Speaker. */
pub mod ApplicationLauncher {
/** Upon receipt of this command, the server SHALL launch the application with optional data. */
    pub const LaunchApp: u32 = 0x00;
/** Upon receipt of this command, the server SHALL stop the application if it is running. */
    pub const StopApp: u32 = 0x01;
/** Upon receipt of this command, the server SHALL hide the application. */
    pub const HideApp: u32 = 0x02;
/** This command SHALL be generated in response to LaunchApp/StopApp/HideApp commands. */
    pub const LauncherResponse: u32 = 0x03;
}
/** The Thread Network Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems */
pub mod ThreadNetworkDiagnostics {
/** Reception of this command SHALL reset the following attributes to 0: */
    pub const ResetCounts: u32 = 0x00;
}
/** This cluster provides a standardized way for a Node (typically a Bridge, but could be any Node) to expose action information. */
pub mod Actions {
/** This command is used to trigger an instantaneous action. */
    pub const InstantAction: u32 = 0x00;
/** This command is used to trigger an instantaneous action with a transition over a given time. */
    pub const InstantActionWithTransition: u32 = 0x01;
/** This command is used to trigger the commencement of an action. */
    pub const StartAction: u32 = 0x02;
/** This command is used to trigger the commencement of an action with a duration. */
    pub const StartActionWithDuration: u32 = 0x03;
/** This command is used to stop an action. */
    pub const StopAction: u32 = 0x04;
/** This command is used to pause an action. */
    pub const PauseAction: u32 = 0x05;
/** This command is used to pause an action with a duration. */
    pub const PauseActionWithDuration: u32 = 0x06;
/** This command is used to resume an action. */
    pub const ResumeAction: u32 = 0x07;
/** This command is used to enable an action. */
    pub const EnableAction: u32 = 0x08;
/** This command is used to enable an action with a duration. */
    pub const EnableActionWithDuration: u32 = 0x09;
/** This command is used to disable an action. */
    pub const DisableAction: u32 = 0x0A;
/** This command is used to disable an action with a duration. */
    pub const DisableActionWithDuration: u32 = 0x0B;
}
/** The cluster provides commands for retrieving unstructured diagnostic logs from a Node that may be used to aid in diagnostics. */
pub mod DiagnosticLogs {
/** Reception of this command starts the process of retrieving diagnostic logs from a Node. */
    pub const RetrieveLogsRequest: u32 = 0x00;
/** This SHALL be generated as a response to the RetrieveLogsRequest. */
    pub const RetrieveLogsResponse: u32 = 0x01;
}
/** The Group Key Management Cluster is the mechanism by which group keys are managed. */
pub mod GroupKeyManagement {
/** Write a new set of keys for the given key set id. */
    pub const KeySetWrite: u32 = 0x00;
/** Read the keys for a given key set id. */
    pub const KeySetRead: u32 = 0x01;
/** Response to KeySetRead */
    pub const KeySetReadResponse: u32 = 0x02;
/** Revoke a Root Key from a Group */
    pub const KeySetRemove: u32 = 0x03;
/** Return the list of Group Key Sets associated with the accessing fabric */
    pub const KeySetReadAllIndices: u32 = 0x04;
/** Reseponse to KeySetReadAllIndices */
    pub const KeySetReadAllIndicesResponse: u32 = 0x05;
}
/** Attributes and commands for controlling devices that can be set to a level between fully 'On' and fully 'Off.' */
pub mod LevelControl {
/** This command will move the device to the specified level. */
    pub const MoveToLevel: u32 = 0x00;
/** This command will move the device using the specified values. */
    pub const Move: u32 = 0x01;
/** This command will do a relative step change of the device using the specified values. */
    pub const Step: u32 = 0x02;
/** This command will stop the actions of various other commands that are still in progress. */
    pub const Stop: u32 = 0x03;
/** This command will move the device to the specified level. */
    pub const MoveToLevelWithOnOff: u32 = 0x04;
/** This command will move the device using the specified values. */
    pub const MoveWithOnOff: u32 = 0x05;
/** This command will do a relative step change of the device using the specified values. */
    pub const StepWithOnOff: u32 = 0x06;
/** This command will stop the actions of various other commands that are still in progress. */
    pub const StopWithOnOff: u32 = 0x07;
/** This command will cause the device to change the current frequency to the requested value. */
    pub const MoveToClosestFrequency: u32 = 0x08;
}
/** Electric Vehicle Supply Equipment (EVSE) is equipment used to charge an Electric Vehicle (EV) or Plug-In Hybrid Electric Vehicle. This cluster provides an interface to the functionality of Electric Vehicle Supply Equipment (EVSE) management. */
pub mod EnergyEVSE {
/** The GetTargetsResponse is sent in response to the GetTargets Command. */
    pub const GetTargetsResponse: u32 = 0x00;
/** Allows a client to disable the EVSE from charging and discharging. */
    pub const Disable: u32 = 0x01;
/** This command allows a client to enable the EVSE to charge an EV, and to provide or update the maximum and minimum charge current. */
    pub const EnableCharging: u32 = 0x02;
/** Upon receipt, this SHALL allow a client to enable the discharge of an EV, and to provide or update the maximum discharge current. */
    pub const EnableDischarging: u32 = 0x03;
/** Allows a client to put the EVSE into a self-diagnostics mode. */
    pub const StartDiagnostics: u32 = 0x04;
/** Allows a client to set the user specified charging targets. */
    pub const SetTargets: u32 = 0x05;
/** Allows a client to retrieve the current set of charging targets. */
    pub const GetTargets: u32 = 0x06;
/** Allows a client to clear all stored charging targets. */
    pub const ClearTargets: u32 = 0x07;
}
/** This cluster provides an interface for sending targeted commands to an Observer of a Content App on a Video Player device such as a Streaming Media Player, Smart TV or Smart Screen. The cluster server for Content App Observer is implemented by an endpoint that communicates with a Content App, such as a Casting Video Client. The cluster client for Content App Observer is implemented by a Content App endpoint. A Content App is informed of the NodeId of an Observer when a binding is set on the Content App. The Content App can then send the ContentAppMessage to the Observer (server cluster), and the Observer responds with a ContentAppMessageResponse. */
pub mod ContentAppObserver {
/** Upon receipt, the data field MAY be parsed and interpreted. Message encoding is specific to the Content App. A Content App MAY when possible read attributes from the Basic Information Cluster on the Observer and use this to determine the Message encoding. */
    pub const ContentAppMessage: u32 = 0x00;
/** This command SHALL be generated in response to ContentAppMessage command. */
    pub const ContentAppMessageResponse: u32 = 0x01;
}
/** This Cluster serves two purposes towards a Node communicating with a Bridge: indicate that the functionality on
 * the Endpoint where it is placed (and its Parts) is bridged from a non-CHIP technology; and provide a centralized
 * collection of attributes that the Node MAY collect to aid in conveying information regarding the Bridged Device to a user,
 * such as the vendor name, the model name, or user-assigned name. */
pub mod BridgedDeviceBasicInformation {
/** Upon receipt, the server SHALL attempt to keep the bridged device active for the duration specified by the command, when the device is next active. */
    pub const KeepActive: u32 = 0x80;
}
/** The Software Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub mod SoftwareDiagnostics {
/** This command is used to reset the high watermarks for heap and stack memory. */
    pub const ResetWatermarks: u32 = 0x00;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod DishwasherMode {
/** This command is used to change device modes.
 * On receipt of this command the device SHALL respond with a ChangeToModeResponse command. */
    pub const ChangeToMode: u32 = 0x00;
/** This command is sent by the device on receipt of the ChangeToModeWithStatus command. */
    pub const ChangeToModeResponse: u32 = 0x01;
}
/** Commands to trigger a Node to allow a new Administrator to commission it. */
pub mod AdministratorCommissioning {
/** This command is used by a current Administrator to instruct a Node to go into commissioning mode. */
    pub const OpenCommissioningWindow: u32 = 0x00;
/** This command MAY be used by a current Administrator to instruct a Node to go into commissioning mode, if the node supports the Basic Commissioning Method. */
    pub const OpenBasicCommissioningWindow: u32 = 0x01;
/** This command is used by a current Administrator to instruct a Node to revoke any active OpenCommissioningWindow or OpenBasicCommissioningWindow command. */
    pub const RevokeCommissioning: u32 = 0x02;
}
/** This cluster provides an interface to manage regions of interest, or Zones, which can be either manufacturer or user defined. */
pub mod ZoneManagement {
/** This command SHALL create and store a TwoD Cartesian Zone. */
    pub const CreateTwoDCartesianZone: u32 = 0x00;
/** This command SHALL be generated in response to a CreateTwoDCartesianZone command. */
    pub const CreateTwoDCartesianZoneResponse: u32 = 0x01;
/** The UpdateTwoDCartesianZone SHALL update a stored TwoD Cartesian Zone. */
    pub const UpdateTwoDCartesianZone: u32 = 0x02;
/** This command SHALL remove the user-defined Zone indicated by ZoneID. */
    pub const RemoveZone: u32 = 0x03;
/** This command is used to create or update a Trigger for the specified motion Zone. */
    pub const CreateOrUpdateTrigger: u32 = 0x04;
/** This command SHALL remove the Trigger for the provided ZoneID. */
    pub const RemoveTrigger: u32 = 0x05;
}
/** The Joint Fabric Datastore Cluster is a cluster that provides a mechanism for the Joint Fabric Administrators to manage the set of Nodes, Groups, and Group membership among Nodes in the Joint Fabric. */
pub mod JointFabricDatastore {
/** This command SHALL be used to add a KeySet to the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const AddKeySet: u32 = 0x00;
/** This command SHALL be used to update a KeySet in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const UpdateKeySet: u32 = 0x01;
/** This command SHALL be used to remove a KeySet from the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const RemoveKeySet: u32 = 0x02;
/** This command SHALL be used to add a group to the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const AddGroup: u32 = 0x03;
/** This command SHALL be used to update a group in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const UpdateGroup: u32 = 0x04;
/** This command SHALL be used to remove a group from the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const RemoveGroup: u32 = 0x05;
/** This command SHALL be used to add an admin to the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const AddAdmin: u32 = 0x06;
/** This command SHALL be used to update an admin in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const UpdateAdmin: u32 = 0x07;
/** This command SHALL be used to remove an admin from the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const RemoveAdmin: u32 = 0x08;
/** The command SHALL be used to add a node to the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const AddPendingNode: u32 = 0x09;
/** The command SHALL be used to request that Datastore information relating to a Node of the accessing fabric is refreshed. */
    pub const RefreshNode: u32 = 0x0A;
/** The command SHALL be used to update the friendly name for a node in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const UpdateNode: u32 = 0x0B;
/** This command SHALL be used to remove a node from the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const RemoveNode: u32 = 0x0C;
/** This command SHALL be used to update the state of an endpoint for a node in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const UpdateEndpointForNode: u32 = 0x0D;
/** This command SHALL be used to add a Group ID to an endpoint for a node in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const AddGroupIDToEndpointForNode: u32 = 0x0E;
/** This command SHALL be used to remove a Group ID from an endpoint for a node in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const RemoveGroupIDFromEndpointForNode: u32 = 0x0F;
/** This command SHALL be used to add a binding to an endpoint for a node in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const AddBindingToEndpointForNode: u32 = 0x10;
/** This command SHALL be used to remove a binding from an endpoint for a node in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const RemoveBindingFromEndpointForNode: u32 = 0x11;
/** This command SHALL be used to add an ACL to a node in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const AddACLToNode: u32 = 0x12;
/** This command SHALL be used to remove an ACL from a node in the Joint Fabric Datastore Cluster of the accessing fabric. */
    pub const RemoveACLFromNode: u32 = 0x13;
}
/** This cluster supports remotely monitoring and, where supported, changing the operational state of any device where a state machine is a part of the operation. */
pub mod OperationalState {
/** Upon receipt, the device SHALL pause its operation if it is possible based on the current function of the server. */
    pub const Pause: u32 = 0x00;
/** Upon receipt, the device SHALL stop its operation if it is at a position where it is safe to do so and/or permitted. */
    pub const Stop: u32 = 0x01;
/** Upon receipt, the device SHALL start its operation if it is safe to do so and the device is in an operational state from which it can be started. */
    pub const Start: u32 = 0x02;
/** Upon receipt, the device SHALL resume its operation from the point it was at when it received the Pause command, or from the point when it was paused by means outside of this cluster (for example by manual button press). */
    pub const Resume: u32 = 0x03;
/** This command SHALL be generated in response to any of the Start, Stop, Pause, or Resume commands. */
    pub const OperationalCommandResponse: u32 = 0x04;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod MicrowaveOvenMode {
    pub const ChangeToMode: u32 = 0x00;
    pub const ChangeToModeResponse: u32 = 0x01;
}
/** Supports the ability for clients to request the commissioning of themselves or other nodes onto a fabric which the cluster server can commission onto. */
pub mod CommissionerControl {
/** This command is sent by a client to request approval for a future CommissionNode call. */
    pub const RequestCommissioningApproval: u32 = 0x00;
/** This command is sent by a client to request that the server begins commissioning a previously approved request. */
    pub const CommissionNode: u32 = 0x01;
/** When received within the timeout specified by ResponseTimeoutSeconds in the CommissionNode command, the client SHALL open a commissioning window on a node which matches the VendorID and ProductID provided in the associated RequestCommissioningApproval command. */
    pub const ReverseOpenCommissioningWindow: u32 = 0x02;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod ModeSelect {
/** On receipt of this command, if the NewMode field indicates a valid mode transition within the supported list, the server SHALL set the CurrentMode attribute to the NewMode value, otherwise, the server SHALL respond with an INVALID_COMMAND status response. */
    pub const ChangeToMode: u32 = 0x00;
}
/** This cluster implements the upload of Audio and Video streams from the Push AV Stream Transport Cluster using suitable push-based transports. */
pub mod PushAVStreamTransport {
/** This command SHALL allocate a transport and return a PushTransportConnectionID. */
    pub const AllocatePushTransport: u32 = 0x00;
/** This command SHALL be generated in response to a successful AllocatePushTransport command. */
    pub const AllocatePushTransportResponse: u32 = 0x01;
/** This command SHALL be generated to request the Node deallocates the specified transport. */
    pub const DeallocatePushTransport: u32 = 0x02;
/** This command is used to request the Node modifies the configuration of the specified push transport. */
    pub const ModifyPushTransport: u32 = 0x03;
/** This command SHALL be generated to request the Node modifies the Transport Status of a specified transport or all transports. */
    pub const SetTransportStatus: u32 = 0x04;
/** This command SHALL be generated to request the Node to manually start the specified push transport. */
    pub const ManuallyTriggerTransport: u32 = 0x05;
/** This command SHALL return the Transport Configuration for the specified push transport or all allocated transports for the fabric if null. */
    pub const FindTransport: u32 = 0x06;
/** This command SHALL be generated in response to a successful FindTransport command. */
    pub const FindTransportResponse: u32 = 0x07;
}
/** This cluster provides an interface for controlling the Output on a media device such as a TV. */
pub mod AudioOutput {
/** Upon receipt, this SHALL change the output on the device to the output at a specific index in the Output List. */
    pub const SelectOutput: u32 = 0x00;
/** Upon receipt, this SHALL rename the output at a specific index in the Output List. */
    pub const RenameOutput: u32 = 0x01;
}
/** Attributes and commands for switching devices between 'On' and 'Off' states. */
pub mod OnOff {
/** On receipt of this command, a device SHALL enter its ‘Off’ state. This state is device dependent, but it is recommended that it is used for power off or similar functions. On receipt of the Off command, the OnTime attribute SHALL be set to 0. */
    pub const Off: u32 = 0x00;
/** On receipt of this command, a device SHALL enter its ‘On’ state. This state is device dependent, but it is recommended that it is used for power on or similar functions. On receipt of the On command, if the value of the OnTime attribute is equal to 0, the device SHALL set the OffWaitTime attribute to 0. */
    pub const On: u32 = 0x01;
/** On receipt of this command, if a device is in its ‘Off’ state it SHALL enter its ‘On’ state. Otherwise, if it is in its ‘On’ state it SHALL enter its ‘Off’ state. On receipt of the Toggle command, if the value of the OnOff attribute is equal to FALSE and if the value of the OnTime attribute is equal to 0, the device SHALL set the OffWaitTime attribute to 0. If the value of the OnOff attribute is equal to TRUE, the OnTime attribute SHALL be set to 0. */
    pub const Toggle: u32 = 0x02;
/** The OffWithEffect command allows devices to be turned off using enhanced ways of fading. */
    pub const OffWithEffect: u32 = 0x40;
/** This command allows the recall of the settings when the device was turned off. */
    pub const OnWithRecallGlobalScene: u32 = 0x41;
/** This command allows devices to be turned on for a specific duration with a guarded off duration so that SHOULD the device be subsequently turned off, further OnWithTimedOff commands, received during this time, are prevented from turning the devices back on. */
    pub const OnWithTimedOff: u32 = 0x42;
}
/** Attributes and commands for controlling the color properties of a color-capable light. */
pub mod ColorControl {
/** Move to specified hue. */
    pub const MoveToHue: u32 = 0x00;
/** Move hue up or down at specified rate. */
    pub const MoveHue: u32 = 0x01;
/** Step hue up or down by specified size at specified rate. */
    pub const StepHue: u32 = 0x02;
/** Move to specified saturation. */
    pub const MoveToSaturation: u32 = 0x03;
/** Move saturation up or down at specified rate. */
    pub const MoveSaturation: u32 = 0x04;
/** Step saturation up or down by specified size at specified rate. */
    pub const StepSaturation: u32 = 0x05;
/** Move to hue and saturation. */
    pub const MoveToHueAndSaturation: u32 = 0x06;
/** Move to specified color. */
    pub const MoveToColor: u32 = 0x07;
/** Moves the color. */
    pub const MoveColor: u32 = 0x08;
/** Steps the lighting to a specific color. */
    pub const StepColor: u32 = 0x09;
/** Move to a specific color temperature. */
    pub const MoveToColorTemperature: u32 = 0x0A;
/** Command description for EnhancedMoveToHue */
    pub const EnhancedMoveToHue: u32 = 0x40;
/** Command description for EnhancedMoveHue */
    pub const EnhancedMoveHue: u32 = 0x41;
/** Command description for EnhancedStepHue */
    pub const EnhancedStepHue: u32 = 0x42;
/** Command description for EnhancedMoveToHueAndSaturation */
    pub const EnhancedMoveToHueAndSaturation: u32 = 0x43;
/** Command description for ColorLoopSet */
    pub const ColorLoopSet: u32 = 0x44;
/** Command description for StopMoveStep */
    pub const StopMoveStep: u32 = 0x47;
/** Command description for MoveColorTemperature */
    pub const MoveColorTemperature: u32 = 0x4B;
/** Command description for StepColorTemperature */
    pub const StepColorTemperature: u32 = 0x4C;
}
/** Provides an interface for providing OTA software updates */
pub mod OTASoftwareUpdateProvider {
/** Determine availability of a new Software Image */
    pub const QueryImage: u32 = 0x00;
/** Response to QueryImage command */
    pub const QueryImageResponse: u32 = 0x01;
/** Determine next action to take for a downloaded Software Image */
    pub const ApplyUpdateRequest: u32 = 0x02;
/** Reponse to ApplyUpdateRequest command */
    pub const ApplyUpdateResponse: u32 = 0x03;
/** Notify OTA Provider that an update was applied */
    pub const NotifyUpdateApplied: u32 = 0x04;
}
/** Attributes and commands for configuring the Dishwasher alarm. */
pub mod DishwasherAlarm {
/** This command resets active and latched alarms (if possible). */
    pub const Reset: u32 = 0x00;
/** This command allows a client to request that an alarm be enabled or suppressed at the server. */
    pub const ModifyEnabledAlarms: u32 = 0x01;
}
/** This cluster provides an interface for observing and managing the state of smoke and CO alarms. */
pub mod SmokeCOAlarm {
/** This command SHALL initiate a device self-test. */
    pub const SelfTestRequest: u32 = 0x00;
}
/** Functionality to retrieve operational information about a managed Wi-Fi network. */
pub mod WiFiNetworkManagement {
/** This command is used to request the current WPA-Personal passphrase or PSK associated with the Wi-Fi network provided by this device. */
    pub const NetworkPassphraseRequest: u32 = 0x00;
/** This command SHALL be generated in response to a NetworkPassphraseRequest command. */
    pub const NetworkPassphraseResponse: u32 = 0x01;
}
/** This cluster provides an interface into controls associated with the operation of a device that provides pan, tilt, and zoom functions, either mechanically, or against a digital image. */
pub mod CameraAVSettingsUserLevelManagement {
/** This command SHALL move the camera to the provided values for pan, tilt, and zoom in the mechanical PTZ. */
    pub const MPTZSetPosition: u32 = 0x00;
/** This command SHALL move the camera by the delta values relative to the currently defined position. */
    pub const MPTZRelativeMove: u32 = 0x01;
/** This command SHALL move the camera to the positions specified by the Preset passed. */
    pub const MPTZMoveToPreset: u32 = 0x02;
/** This command allows creating a new preset or updating the values of an existing one. */
    pub const MPTZSavePreset: u32 = 0x03;
/** This command SHALL remove a preset entry from the PresetMptzTable. */
    pub const MPTZRemovePreset: u32 = 0x04;
/** This command allows for setting the digital viewport for a specific Video Stream. */
    pub const DPTZSetViewport: u32 = 0x05;
/** This command SHALL change the per stream viewport by the amount specified in a relative fashion. */
    pub const DPTZRelativeMove: u32 = 0x06;
}
/** This cluster provides an interface for passing messages to be presented by a device. */
pub mod Messages {
/** Command for requesting messages be presented */
    pub const PresentMessagesRequest: u32 = 0x00;
/** Command for cancelling message present requests */
    pub const CancelMessagesRequest: u32 = 0x01;
}
/** This cluster provides commands that facilitate user account login on a Content App or a node. For example, a Content App running on a Video Player device, which is represented as an endpoint (see [TV Architecture]), can use this cluster to help make the user account on the Content App match the user account on the Client. */
pub mod AccountLogin {
/** The purpose of this command is to determine if the active user account of the given Content App matches the active user account of a given Commissionee, and when it does, return a Setup PIN which can be used for password-authenticated session establishment (PASE) with the Commissionee. */
    pub const GetSetupPIN: u32 = 0x00;
/** This message is sent in response to the GetSetupPIN command, and contains the Setup PIN, or null when the account identified in the request does not match the active account of the running Content App. */
    pub const GetSetupPINResponse: u32 = 0x01;
/** The purpose of this command is to allow the Content App to assume the user account of a given Commissionee by leveraging the Setup PIN input by the user during the commissioning process. */
    pub const Login: u32 = 0x02;
/** The purpose of this command is to instruct the Content App to clear the current user account. */
    pub const Logout: u32 = 0x03;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod RVCCleanMode {
/** This command is used to change device modes.
 * On receipt of this command the device SHALL respond with a ChangeToModeResponse command. */
    pub const ChangeToMode: u32 = 0x00;
/** This command is sent by the device on receipt of the ChangeToModeWithStatus command. */
    pub const ChangeToModeResponse: u32 = 0x01;
}
/** This cluster provides an interface for controlling Media Playback (PLAY, PAUSE, etc) on a media device such as a TV or Speaker. */
pub mod MediaPlayback {
/** Upon receipt, this SHALL play media. */
    pub const Play: u32 = 0x00;
/** Upon receipt, this SHALL pause media. */
    pub const Pause: u32 = 0x01;
/** Upon receipt, this SHALL stop media. User experience is context-specific. This will often navigate the user back to the location where media was originally launched. */
    pub const Stop: u32 = 0x02;
/** Upon receipt, this SHALL Start Over with the current media playback item. */
    pub const StartOver: u32 = 0x03;
/** Upon receipt, this SHALL cause the handler to be invoked for "Previous". User experience is context-specific. This will often Go back to the previous media playback item. */
    pub const Previous: u32 = 0x04;
/** Upon receipt, this SHALL cause the handler to be invoked for "Next". User experience is context-specific. This will often Go forward to the next media playback item. */
    pub const Next: u32 = 0x05;
/** Upon receipt, this SHALL Rewind through media. Different Rewind speeds can be used on the TV based upon the number of sequential calls to this function. This is to avoid needing to define every speed now (multiple fast, slow motion, etc). */
    pub const Rewind: u32 = 0x06;
/** Upon receipt, this SHALL Advance through media. Different FF speeds can be used on the TV based upon the number of sequential calls to this function. This is to avoid needing to define every speed now (multiple fast, slow motion, etc). */
    pub const FastForward: u32 = 0x07;
/** Upon receipt, this SHALL Skip forward in the media by the given number of seconds, using the data as follows: */
    pub const SkipForward: u32 = 0x08;
/** Upon receipt, this SHALL Skip backward in the media by the given number of seconds, using the data as follows: */
    pub const SkipBackward: u32 = 0x09;
/** This command SHALL be generated in response to various Playback Request commands. */
    pub const PlaybackResponse: u32 = 0x0A;
/** Upon receipt, this SHALL Skip backward in the media by the given number of seconds, using the data as follows: */
    pub const Seek: u32 = 0x0B;
/** Upon receipt, the server SHALL set the active Audio Track to the one identified by the TrackID in the Track catalog for the streaming media. If the TrackID does not exist in the Track catalog, OR does not correspond to the streaming media OR no media is being streamed at the time of receipt of this command, the server will return an error status of INVALID_ARGUMENT. */
    pub const ActivateAudioTrack: u32 = 0x0C;
/** Upon receipt, the server SHALL set the active Text Track to the one identified by the TrackID in the Track catalog for the streaming media. If the TrackID does not exist in the Track catalog, OR does not correspond to the streaming media OR no media is being streamed at the time of receipt of this command, the server SHALL return an error status of INVALID_ARGUMENT. */
    pub const ActivateTextTrack: u32 = 0x0D;
/** If a Text Track is active (i.e. being displayed), upon receipt of this command, the server SHALL stop displaying it. */
    pub const DeactivateTextTrack: u32 = 0x0E;
}
/** Provides an interface for controlling and adjusting automatic window coverings. */
pub mod WindowCovering {
/** Moves window covering to InstalledOpenLimitLift and InstalledOpenLimitTilt */
    pub const UpOrOpen: u32 = 0x00;
/** Moves window covering to InstalledClosedLimitLift and InstalledCloseLimitTilt */
    pub const DownOrClose: u32 = 0x01;
/** Stop any adjusting of window covering */
    pub const StopMotion: u32 = 0x02;
/** Go to lift percentage specified */
    pub const GoToLiftPercentage: u32 = 0x05;
/** Go to tilt percentage specified */
    pub const GoToTiltPercentage: u32 = 0x08;
}
/** The Wi-Fi Network Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub mod WiFiNetworkDiagnostics {
/** This command is used to reset the count attributes. */
    pub const ResetCounts: u32 = 0x00;
}
/** Provides an interface for downloading and applying OTA software updates */
pub mod OTASoftwareUpdateRequestor {
/** Announce the presence of an OTA Provider */
    pub const AnnounceOTAProvider: u32 = 0x00;
}
/** The WebRTC transport requestor cluster provides a way for stream consumers (e.g. Matter Stream Viewer) to establish a WebRTC connection with a stream provider. */
pub mod WebRTCTransportRequestor {
/** This command provides the stream requestor with WebRTC session details. */
    pub const Offer: u32 = 0x00;
/** This command provides the stream requestor with the WebRTC session details (i.e. Session ID and SDP answer), It is the next command in the Offer/Answer flow to the ProvideOffer command. */
    pub const Answer: u32 = 0x01;
/** This command allows for the object based ICE candidates generated after the initial Offer / Answer exchange, via a JSEP onicecandidate event, a DOM rtcpeerconnectioniceevent event, or other WebRTC compliant implementations, to be added to a session during the gathering phase. */
    pub const ICECandidates: u32 = 0x02;
/** This command notifies the stream requestor that the provider has ended the WebRTC session. */
    pub const End: u32 = 0x03;
}
/** Manages the names and credentials of Thread networks visible to the user. */
pub mod ThreadNetworkDirectory {
/** Adds an entry to the ThreadNetworks attribute with the specified Thread Operational Dataset. */
    pub const AddNetwork: u32 = 0x00;
/** Removes the network with the given Extended PAN ID from the ThreadNetworks attribute. */
    pub const RemoveNetwork: u32 = 0x01;
/** Retrieves the Thread Operational Dataset with the given Extended PAN ID. */
    pub const GetOperationalDataset: u32 = 0x02;
/** Contains the Thread Operational Dataset for the Extended PAN specified in GetOperationalDataset. */
    pub const OperationalDatasetResponse: u32 = 0x03;
}
/** The Service Area cluster provides an interface for controlling the areas where a device should operate, and for querying the current area being serviced. */
pub mod ServiceArea {
/** This command is used to select a set of device areas, where the device is to operate. */
    pub const SelectAreas: u32 = 0x00;
/** This command is sent by the device on receipt of the SelectAreas command. */
    pub const SelectAreasResponse: u32 = 0x01;
/** This command is used to skip the given area, and to attempt operating at other areas on the SupportedAreas attribute list. */
    pub const SkipArea: u32 = 0x02;
/** This command is sent by the device on receipt of the SkipArea command. */
    pub const SkipAreaResponse: u32 = 0x03;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod RefrigeratorAndTemperatureControlledCabinetMode {
/** This command is used to change device modes.
 * On receipt of this command the device SHALL respond with a ChangeToModeResponse command. */
    pub const ChangeToMode: u32 = 0x00;
/** This command is sent by the device on receipt of the ChangeToModeWithStatus command. */
    pub const ChangeToModeResponse: u32 = 0x01;
}
/** The Access Control Cluster exposes a data model view of a
 * Node's Access Control List (ACL), which codifies the rules used to manage
 * and enforce Access Control for the Node's endpoints and their associated
 * cluster instances. */
pub mod AccessControl {
/** This command signals to the service associated with the device vendor that the fabric administrator would like a review of the current restrictions on the accessing fabric. */
    pub const ReviewFabricRestrictions: u32 = 0x00;
/** Returns the review token for the request, which can be used to correlate with a FabricRestrictionReviewUpdate event. */
    pub const ReviewFabricRestrictionsResponse: u32 = 0x01;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod WaterHeaterMode {
/** This command is used to change device modes. */
    pub const ChangeToMode: u32 = 0x00;
/** This command is sent by the device on receipt of the ChangeToMode command. */
    pub const ChangeToModeResponse: u32 = 0x01;
}
/** This Cluster is used to provision TLS Endpoints with enough information to facilitate subsequent connection. */
pub mod TLSClientManagement {
/** This command is used to provision a TLS Endpoint for the provided Hostname / Port combination. */
    pub const ProvisionEndpoint: u32 = 0x00;
/** This command is used to report the result of the ProvisionEndpoint command. */
    pub const ProvisionEndpointResponse: u32 = 0x01;
/** This command is used to find a TLS Endpoint by its ID. */
    pub const FindEndpoint: u32 = 0x02;
/** This command is used to report the result of the FindEndpoint command. */
    pub const FindEndpointResponse: u32 = 0x03;
/** This command is used to remove a TLS Endpoint by its ID. */
    pub const RemoveEndpoint: u32 = 0x04;
}
/** This cluster provides an interface for controlling a Closure. */
pub mod ClosureControl {
/** On receipt of this command, the closure SHALL stop its movement as fast as the closure is able too. */
    pub const Stop: u32 = 0x00;
/** On receipt of this command, the closure SHALL operate to update its position, latch state and/or motion speed. */
    pub const MoveTo: u32 = 0x01;
/** This command is used to trigger a calibration of the closure. */
    pub const Calibrate: u32 = 0x02;
}
/** Attributes and commands for putting a device into Identification mode (e.g. flashing a light). */
pub mod Identify {
/** This command starts or stops the receiving device identifying itself. */
    pub const Identify: u32 = 0x00;
/** This command allows the support of feedback to the user, such as a certain light effect. */
    pub const TriggerEffect: u32 = 0x40;
}
/** This cluster provides an interface for managing low power mode on a device. */
pub mod LowPower {
/** This command SHALL put the device into low power mode. */
    pub const Sleep: u32 = 0x00;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod EnergyEVSEMode {
/** This command is used to change device modes. */
    pub const ChangeToMode: u32 = 0x00;
/** This command is sent by the device on receipt of the ChangeToMode command. */
    pub const ChangeToModeResponse: u32 = 0x01;
}
/** This cluster is used to configure a boolean sensor. */
pub mod BooleanStateConfiguration {
/** This command is used to suppress the specified alarm mode. */
    pub const SuppressAlarm: u32 = 0x00;
/** This command is used to enable or disable the specified alarm mode. */
    pub const EnableDisableAlarm: u32 = 0x01;
}
/** Attributes and commands for scene configuration and manipulation. */
pub mod ScenesManagement {
/** Add a scene to the scene table. Extension field sets are input as '{"ClusterID": VALUE, "AttributeValueList":[{"AttributeID": VALUE, "Value*": VALUE}]}'. */
    pub const AddScene: u32 = 0x00;
/** The command is generated in response to a received unicast AddScene command, */
    pub const AddSceneResponse: u32 = 0x00;
/** Retrieves the requested scene entry from its Scene table. */
    pub const ViewScene: u32 = 0x01;
/** The command is generated in response to a received unicast ViewScene command */
    pub const ViewSceneResponse: u32 = 0x01;
/** Removes the requested scene entry, corresponding to the value of the GroupID field, from its Scene Table */
    pub const RemoveScene: u32 = 0x02;
/** The command is generated in response to a received unicast RemoveScene command */
    pub const RemoveSceneResponse: u32 = 0x02;
/** Remove all scenes, corresponding to the value of the GroupID field, from its Scene Table */
    pub const RemoveAllScenes: u32 = 0x03;
/** The command is generated in response to a received unicast RemoveAllScenes command */
    pub const RemoveAllScenesResponse: u32 = 0x03;
/** Adds the scene entry into its Scene Table along with all extension field sets corresponding to the current state of other clusters on the same endpoint */
    pub const StoreScene: u32 = 0x04;
/** The command is generated in response to a received unicast StoreScene command */
    pub const StoreSceneResponse: u32 = 0x04;
/** Set the attributes and corresponding state for each other cluster implemented on the endpoint accordingly to the resquested scene entry in the Scene Table */
    pub const RecallScene: u32 = 0x05;
/** This command can be used to get the used scene identifiers within a certain group, for the endpoint that implements this cluster. */
    pub const GetSceneMembership: u32 = 0x06;
/** The command is generated in response to a received unicast GetSceneMembership command */
    pub const GetSceneMembershipResponse: u32 = 0x06;
/** This command allows a client to efficiently copy scenes from one group/scene identifier pair to another group/scene identifier pair. */
    pub const CopyScene: u32 = 0x40;
/** The command is generated in response to a received unicast CopyScene command */
    pub const CopySceneResponse: u32 = 0x40;
}
/** Attributes and commands for monitoring HEPA filters in a device */
pub mod HEPAFilterMonitoring {
/** Upon receipt, the device SHALL reset the Condition and ChangeIndicator attributes, indicating full resource availability and readiness for use, as initially configured. */
    pub const ResetCondition: u32 = 0x00;
}
/** Attributes and commands for monitoring HEPA filters in a device */
pub mod ActivatedCarbonFilterMonitoring {
/** Upon receipt, the device SHALL reset the Condition and ChangeIndicator attributes, indicating full resource availability and readiness for use, as initially configured. */
    pub const ResetCondition: u32 = 0x00;
}
/** Attributes and commands for monitoring HEPA filters in a device */
pub mod WaterTankLevelMonitoring {
/** Upon receipt, the device SHALL reset the Condition and ChangeIndicator attributes, indicating full resource availability and readiness for use, as initially configured. */
    pub const ResetCondition: u32 = 0x00;
}
/** This cluster is used to manage global aspects of the Commissioning flow. */
pub mod GeneralCommissioning {
/** This command is used to arm or disarm the fail-safe timer. */
    pub const ArmFailSafe: u32 = 0x00;
/** This command is used to report the result of the ArmFailSafe command. */
    pub const ArmFailSafeResponse: u32 = 0x01;
/** This command is used to set the regulatory configuration for the device. */
    pub const SetRegulatoryConfig: u32 = 0x02;
/** This command is used to report the result of the SetRegulatoryConfig command. */
    pub const SetRegulatoryConfigResponse: u32 = 0x03;
/** This command is used to indicate that the commissioning process is complete. */
    pub const CommissioningComplete: u32 = 0x04;
/** This command is used to report the result of the CommissioningComplete command. */
    pub const CommissioningCompleteResponse: u32 = 0x05;
/** This command is used to set the user acknowledgements received in the Enhanced Setup Flow Terms & Conditions into the node. */
    pub const SetTCAcknowledgements: u32 = 0x06;
/** This command is used to report the result of the SetTCAcknowledgements command. */
    pub const SetTCAcknowledgementsResponse: u32 = 0x07;
}
/** This cluster is used to add or remove Operational Credentials on a Commissionee or Node, as well as manage the associated Fabrics. */
pub mod OperationalCredentials {
/** Sender is requesting attestation information from the receiver. */
    pub const AttestationRequest: u32 = 0x00;
/** An attestation information confirmation from the server. */
    pub const AttestationResponse: u32 = 0x01;
/** Sender is requesting a device attestation certificate from the receiver. */
    pub const CertificateChainRequest: u32 = 0x02;
/** A device attestation certificate (DAC) or product attestation intermediate (PAI) certificate from the server. */
    pub const CertificateChainResponse: u32 = 0x03;
/** Sender is requesting a certificate signing request (CSR) from the receiver. */
    pub const CSRRequest: u32 = 0x04;
/** A certificate signing request (CSR) from the server. */
    pub const CSRResponse: u32 = 0x05;
/** Sender is requesting to add the new node operational certificates. */
    pub const AddNOC: u32 = 0x06;
/** This command SHALL replace the NOC and optional associated ICAC (if present) scoped under the accessing fabric upon successful validation of all arguments and preconditions. */
    pub const UpdateNOC: u32 = 0x07;
/** Response to several commands in this cluster. */
    pub const NOCResponse: u32 = 0x08;
/** This command SHALL be used by an Administrative Node to set the user-visible Label field for a given Fabric, as reflected by entries in the Fabrics attribute. */
    pub const UpdateFabricLabel: u32 = 0x09;
/** This command is used by Administrative Nodes to remove a given fabric index and delete all associated fabric-scoped data. */
    pub const RemoveFabric: u32 = 0x0A;
/** This command SHALL add a Trusted Root CA Certificate, provided as its CHIP Certificate representation. */
    pub const AddTrustedRootCertificate: u32 = 0x0B;
/** This command SHALL be used to update any of the accessing fabric's associated VendorID, VidVerificatioNStatement or VVSC (Vendor Verification Signing Certificate). */
    pub const SetVIDVerificationStatement: u32 = 0x0C;
/** This command SHALL be used to request that the server authenticate the fabric associated with the FabricIndex given. */
    pub const SignVIDVerificationRequest: u32 = 0x0D;
/** This command SHALL contain the response of the SignVIDVerificationRequest. */
    pub const SignVIDVerificationResponse: u32 = 0x0E;
}
/** This cluster provides an interface for UX navigation within a set of targets on a device or endpoint. */
pub mod TargetNavigator {
/** Upon receipt, this SHALL navigation the UX to the target identified. */
    pub const NavigateTarget: u32 = 0x00;
/** This command SHALL be generated in response to NavigateTarget commands. */
    pub const NavigateTargetResponse: u32 = 0x01;
}
/** An interface for controlling a fan in a heating/cooling system. */
pub mod FanControl {
/** This command speeds up or slows down the fan, in steps, without a client having to know the fan speed. */
    pub const Step: u32 = 0x00;
}
pub mod GlobalElements {
    pub const AtomicResponse: u32 = 0xFD;
    pub const AtomicRequest: u32 = 0xFE;
}
/** An interface to a generic way to secure a door */
pub mod DoorLock {
/** This command causes the lock device to lock the door. */
    pub const LockDoor: u32 = 0x00;
/** This command causes the lock device to unlock the door. */
    pub const UnlockDoor: u32 = 0x01;
    pub const Toggle: u32 = 0x02;
/** This command causes the lock device to unlock the door with a timeout parameter. */
    pub const UnlockWithTimeout: u32 = 0x03;
/** Set a weekly repeating schedule for a specified user. */
    pub const SetWeekDaySchedule: u32 = 0x0B;
/** Retrieve the specific weekly schedule for the specific user. */
    pub const GetWeekDaySchedule: u32 = 0x0C;
/** Returns the weekly repeating schedule data for the specified schedule index. */
    pub const GetWeekDayScheduleResponse: u32 = 0x0C;
/** Clear the specific weekly schedule or all weekly schedules for the specific user. */
    pub const ClearWeekDaySchedule: u32 = 0x0D;
/** Set a time-specific schedule ID for a specified user. */
    pub const SetYearDaySchedule: u32 = 0x0E;
/** Returns the year day schedule data for the specified schedule and user indexes. */
    pub const GetYearDaySchedule: u32 = 0x0F;
/** Returns the year day schedule data for the specified schedule and user indexes. */
    pub const GetYearDayScheduleResponse: u32 = 0x0F;
/** Clears the specific year day schedule or all year day schedules for the specific user. */
    pub const ClearYearDaySchedule: u32 = 0x10;
/** Set the holiday Schedule by specifying local start time and local end time with respect to any Lock Operating Mode. */
    pub const SetHolidaySchedule: u32 = 0x11;
/** Get the holiday schedule for the specified index. */
    pub const GetHolidaySchedule: u32 = 0x12;
/** Returns the Holiday Schedule Entry for the specified Holiday ID. */
    pub const GetHolidayScheduleResponse: u32 = 0x12;
/** Clears the holiday schedule or all holiday schedules. */
    pub const ClearHolidaySchedule: u32 = 0x13;
/** Set User into the lock. */
    pub const SetUser: u32 = 0x1A;
/** Retrieve User. */
    pub const GetUser: u32 = 0x1B;
/** Returns the User for the specified UserIndex. */
    pub const GetUserResponse: u32 = 0x1C;
/** Clears a User or all Users. */
    pub const ClearUser: u32 = 0x1D;
/** Set a credential (e.g. PIN, RFID, Fingerprint, etc.) into the lock for a new user, existing user, or ProgrammingUser. */
    pub const SetCredential: u32 = 0x22;
/** Returns the status for setting the specified credential. */
    pub const SetCredentialResponse: u32 = 0x23;
/** Retrieve the status of a particular credential (e.g. PIN, RFID, Fingerprint, etc.) by index. */
    pub const GetCredentialStatus: u32 = 0x24;
/** Returns the status for the specified credential. */
    pub const GetCredentialStatusResponse: u32 = 0x25;
/** Clear one, one type, or all credentials except ProgrammingPIN credential. */
    pub const ClearCredential: u32 = 0x26;
/** This command causes the lock device to unlock the door without pulling the latch. */
    pub const UnboltDoor: u32 = 0x27;
/** This command communicates an Aliro Reader configuration to the lock. */
    pub const SetAliroReaderConfig: u32 = 0x28;
/** This command clears an existing Aliro Reader configuration for the lock. */
    pub const ClearAliroReaderConfig: u32 = 0x29;
}
/** The WebRTC transport provider cluster provides a way for stream providers (e.g. Cameras) to stream or receive their data through WebRTC. */
pub mod WebRTCTransportProvider {
/** Requests that the Provider initiates a new session with the Offer / Answer flow in a way that allows for options to be passed and work with devices needing the standby flow. */
    pub const SolicitOffer: u32 = 0x00;
/** This command SHALL be generated in response to a SolicitOffer command. */
    pub const SolicitOfferResponse: u32 = 0x01;
/** This command allows an SDP Offer to be set and start a new session. */
    pub const ProvideOffer: u32 = 0x02;
/** This command contains information about the session and streams created as a response to the requestor's offer. */
    pub const ProvideOfferResponse: u32 = 0x03;
/** This command SHALL be initiated from a Node in response to an Offer that was previously received from a remote peer. */
    pub const ProvideAnswer: u32 = 0x04;
/** This command allows for string based ICE candidates generated after the initial Offer / Answer exchange, via a JSEP onicecandidate event, a DOM rtcpeerconnectioniceevent event, or other WebRTC compliant implementations, to be added to a session during the gathering phase. */
    pub const ProvideICECandidates: u32 = 0x05;
/** This command instructs the stream provider to end the WebRTC session. */
    pub const EndSession: u32 = 0x06;
}
/** Manage the Thread network of Thread Border Router */
pub mod ThreadBorderRouterManagement {
/** This command SHALL be used to request the active operational dataset of the Thread network to which the border router is connected. */
    pub const GetActiveDatasetRequest: u32 = 0x00;
/** This command SHALL be used to request the pending dataset of the Thread network to which the border router is connected. */
    pub const GetPendingDatasetRequest: u32 = 0x01;
/** This command is sent in response to GetActiveDatasetRequest or GetPendingDatasetRequest command. */
    pub const DatasetResponse: u32 = 0x02;
/** This command SHALL be used to set the active Dataset of the Thread network to which the Border Router is connected, when there is no active dataset already. */
    pub const SetActiveDatasetRequest: u32 = 0x03;
/** This command SHALL be used to set or update the pending Dataset of the Thread network to which the Border Router is connected, if the Border Router supports PANChange Feature. */
    pub const SetPendingDatasetRequest: u32 = 0x04;
}
/** The Camera AV Stream Management cluster is used to allow clients to manage, control, and configure various audio, video, and snapshot streams on a camera. */
pub mod CameraAVStreamManagement {
/** This command SHALL allocate an audio stream on the camera and return an allocated audio stream identifier. */
    pub const AudioStreamAllocate: u32 = 0x00;
/** This command SHALL be sent by the camera in response to the AudioStreamAllocate command, carrying the newly allocated or re-used audio stream identifier. */
    pub const AudioStreamAllocateResponse: u32 = 0x01;
/** This command SHALL deallocate an audio stream on the camera, corresponding to the given audio stream identifier. */
    pub const AudioStreamDeallocate: u32 = 0x02;
/** This command SHALL allocate a video stream on the camera and return an allocated video stream identifier. */
    pub const VideoStreamAllocate: u32 = 0x03;
/** This command SHALL be sent by the camera in response to the VideoStreamAllocate command, carrying the newly allocated or re-used video stream identifier. */
    pub const VideoStreamAllocateResponse: u32 = 0x04;
/** This command SHALL be used to modify a stream specified by the VideoStreamID. */
    pub const VideoStreamModify: u32 = 0x05;
/** This command SHALL deallocate a video stream on the camera, corresponding to the given video stream identifier. */
    pub const VideoStreamDeallocate: u32 = 0x06;
/** This command SHALL allocate a snapshot stream on the device and return an allocated snapshot stream identifier. */
    pub const SnapshotStreamAllocate: u32 = 0x07;
/** This command SHALL be sent by the device in response to the SnapshotStreamAllocate command, carrying the newly allocated or re-used snapshot stream identifier. */
    pub const SnapshotStreamAllocateResponse: u32 = 0x08;
/** This command SHALL be used to modify a stream specified by the VideoStreamID. */
    pub const SnapshotStreamModify: u32 = 0x09;
/** This command SHALL deallocate an snapshot stream on the camera, corresponding to the given snapshot stream identifier. */
    pub const SnapshotStreamDeallocate: u32 = 0x0A;
/** This command SHALL set the relative priorities of the various stream usages on the camera. */
    pub const SetStreamPriorities: u32 = 0x0B;
/** This command SHALL return a Snapshot from the camera. */
    pub const CaptureSnapshot: u32 = 0x0C;
/** This command SHALL be sent by the device in response to the CaptureSnapshot command, carrying the requested snapshot. */
    pub const CaptureSnapshotResponse: u32 = 0x0D;
}
/** An instance of the Joint Fabric Administrator Cluster only applies to Joint Fabric Administrator nodes fulfilling the role of Anchor CA. */
pub mod JointFabricAdministrator {
/** This command SHALL be generated during Joint Commissioning Method and subsequently be responded in the form of an ICACCSRResponse command. */
    pub const ICACCSRRequest: u32 = 0x00;
/** This command SHALL be generated in response to a ICACCSRRequest command. */
    pub const ICACCSRResponse: u32 = 0x01;
/** This command SHALL be generated and executed during Joint Commissioning Method and subsequently be responded in the form of an ICACResponse command. */
    pub const AddICAC: u32 = 0x02;
/** This command SHALL be generated in response to the AddICAC command. */
    pub const ICACResponse: u32 = 0x03;
/** This command SHALL fail with a InvalidAdministratorFabricIndex status code sent back to the initiator if the AdministratorFabricIndex field has the value of null. */
    pub const OpenJointCommissioningWindow: u32 = 0x04;
/** This command SHALL be sent by a candidate Joint Fabric Anchor Administrator to the current Joint Fabric Anchor Administrator to request transfer of the Anchor Fabric. */
    pub const TransferAnchorRequest: u32 = 0x05;
/** This command SHALL be generated in response to the Transfer Anchor Request command. */
    pub const TransferAnchorResponse: u32 = 0x06;
/** This command SHALL indicate the completion of the transfer of the Anchor Fabric to another Joint Fabric Ecosystem Administrator. */
    pub const TransferAnchorComplete: u32 = 0x07;
/** This command SHALL be used for communicating to client the endpoint that holds the Joint Fabric Administrator Cluster. */
    pub const AnnounceJointFabricAdministrator: u32 = 0x08;
}
/** This cluster supports remotely monitoring and, where supported, changing the operational state of a Robotic Vacuum. */
pub mod RVCOperationalState {
/** Upon receipt, the device SHALL pause its operation if it is possible based on the current function of the server. */
    pub const Pause: u32 = 0x00;
    pub const Stop: u32 = 0x01;
    pub const Start: u32 = 0x02;
/** Upon receipt, the device SHALL resume its operation from the point it was at when it received the Pause command, or from the point when it was paused by means outside of this cluster (for example by manual button press). */
    pub const Resume: u32 = 0x03;
/** This command SHALL be generated in response to any of the Start, Stop, Pause, or Resume commands. */
    pub const OperationalCommandResponse: u32 = 0x04;
/** On receipt of this command, the device SHALL start seeking the charging dock, if possible in the current state of the device. */
    pub const GoHome: u32 = 0x80;
}
/** This cluster provides an interface for controlling a device like a TV using action commands such as UP, DOWN, and SELECT. */
pub mod KeypadInput {
/** Upon receipt, this SHALL process a keycode as input to the media endpoint. */
    pub const SendKey: u32 = 0x00;
/** This command SHALL be generated in response to a SendKey command. */
    pub const SendKeyResponse: u32 = 0x01;
}
/** Attributes and commands for group configuration and manipulation. */
pub mod Groups {
/** The AddGroup command allows a client to add group membership in a particular group for the server endpoint. */
    pub const AddGroup: u32 = 0x00;
/** The AddGroupResponse is sent by the Groups cluster server in response to an AddGroup command. */
    pub const AddGroupResponse: u32 = 0x00;
/** The ViewGroup command allows a client to request that the server responds with a ViewGroupResponse command containing the name string for a particular group. */
    pub const ViewGroup: u32 = 0x01;
/** The ViewGroupResponse command is sent by the Groups cluster server in response to a ViewGroup command. */
    pub const ViewGroupResponse: u32 = 0x01;
/** The GetGroupMembership command allows a client to inquire about the group membership of the server endpoint, in a number of ways. */
    pub const GetGroupMembership: u32 = 0x02;
/** The GetGroupMembershipResponse command is sent by the Groups cluster server in response to a GetGroupMembership command. */
    pub const GetGroupMembershipResponse: u32 = 0x02;
/** The RemoveGroup command allows a client to request that the server removes the membership for the server endpoint, if any, in a particular group. */
    pub const RemoveGroup: u32 = 0x03;
/** The RemoveGroupResponse command is generated by the server in response to the receipt of a RemoveGroup command. */
    pub const RemoveGroupResponse: u32 = 0x03;
/** The RemoveAllGroups command allows a client to direct the server to remove all group associations for the server endpoint. */
    pub const RemoveAllGroups: u32 = 0x04;
/** The AddGroupIfIdentifying command allows a client to add group membership in a particular group for the server endpoint, on condition that the endpoint is identifying itself. */
    pub const AddGroupIfIdentifying: u32 = 0x05;
}
/** This cluster provides an interface to reflect and control a closure's range of movement, usually involving a panel, by using 6-axis framework. */
pub mod ClosureDimension {
/** This command is used to move a dimension of the closure to a target position. */
    pub const SetTarget: u32 = 0x00;
/** This command is used to move a dimension of the closure to a target position by a number of steps. */
    pub const Step: u32 = 0x01;
}
/** Attributes and commands for configuring the Refrigerator alarm. */
pub mod RefrigeratorAlarm {
    pub const Reset: u32 = 0x00;
    pub const ModifyEnabledAlarms: u32 = 0x01;
}
/** This cluster provides an interface for controlling the Input Selector on a media device such as a TV. */
pub mod MediaInput {
/** Upon receipt, this command SHALL change the media input on the device to the input at a specific index in the Input List. */
    pub const SelectInput: u32 = 0x00;
/** Upon receipt, this command SHALL display the active status of the input list on screen. */
    pub const ShowInputStatus: u32 = 0x01;
/** Upon receipt, this command SHALL hide the input list from the screen. */
    pub const HideInputStatus: u32 = 0x02;
/** Upon receipt, this command SHALL rename the input at a specific index in the Input List. */
    pub const RenameInput: u32 = 0x03;
}
/** This Cluster is used to manage TLS Client Certificates and to provision
 * TLS endpoints with enough information to facilitate subsequent connection. */
pub mod TLSCertificateManagement {
/** This command SHALL provision a newly provided certificate, or rotate an existing one, based on the contents of the CAID field. */
    pub const ProvisionRootCertificate: u32 = 0x00;
/** This command SHALL be generated in response to a ProvisionRootCertificate command. */
    pub const ProvisionRootCertificateResponse: u32 = 0x01;
/** This command SHALL return the specified TLS root certificate, or all provisioned TLS root certificates for the accessing fabric, based on the contents of the CAID field. */
    pub const FindRootCertificate: u32 = 0x02;
/** This command SHALL be generated in response to a FindRootCertificate command. */
    pub const FindRootCertificateResponse: u32 = 0x03;
/** This command SHALL return the CAID for the passed in fingerprint. */
    pub const LookupRootCertificate: u32 = 0x04;
/** This command SHALL be generated in response to a LookupRootCertificate command. */
    pub const LookupRootCertificateResponse: u32 = 0x05;
/** This command SHALL be generated to request the server removes the certificate provisioned to the provided Certificate Authority ID. */
    pub const RemoveRootCertificate: u32 = 0x06;
/** This command SHALL be generated to request the Node generates a certificate signing request for a new TLS key pair or use an existing CCDID for certificate rotation. */
    pub const ClientCSR: u32 = 0x07;
/** This command SHALL be generated in response to a ClientCSR command. */
    pub const ClientCSRResponse: u32 = 0x08;
/** This command SHALL be generated to request the Node provisions newly provided Client Certificate Details, or rotate an existing client certificate. */
    pub const ProvisionClientCertificate: u32 = 0x09;
/** This command SHALL return the TLSClientCertificateDetailStruct for the passed in CCDID, or all TLS client certificates for the accessing fabric, based on the contents of the CCDID field. */
    pub const FindClientCertificate: u32 = 0x0A;
/** This command SHALL be generated in response to a FindClientCertificate command. */
    pub const FindClientCertificateResponse: u32 = 0x0B;
/** This command SHALL return the CCDID for the passed in Fingerprint. */
    pub const LookupClientCertificate: u32 = 0x0C;
/** This command SHALL be generated in response to a LookupClientCertificate command. */
    pub const LookupClientCertificateResponse: u32 = 0x0D;
/** This command SHALL be used to request the Node removes all stored information for the provided CCDID. */
    pub const RemoveClientCertificate: u32 = 0x0E;
}
/** The CommodityTariffCluster provides the mechanism for communicating Commodity Tariff information within the premises. */
pub mod CommodityTariff {
/** The GetTariffComponent command allows a client to request information for a tariff component identifier that may no longer be available in the TariffPeriods attributes. */
    pub const GetTariffComponent: u32 = 0x00;
/** The GetTariffComponentResponse command is sent in response to a GetTariffComponent command. */
    pub const GetTariffComponentResponse: u32 = 0x00;
/** The GetDayEntry command allows a client to request information for a calendar day entry identifier that may no longer be available in the CalendarPeriods or IndividualDays attributes. */
    pub const GetDayEntry: u32 = 0x01;
/** The GetDayEntryResponse command is sent in response to a GetDayEntry command. */
    pub const GetDayEntryResponse: u32 = 0x01;
}
/** An interface for configuring and controlling the functionality of a thermostat. */
pub mod Thermostat {
/** Upon receipt, the attributes for the indicated setpoint(s) SHALL have the amount specified in the Amount field added to them. */
    pub const SetpointRaiseLower: u32 = 0x00;
/** Upon receipt, if the Schedules attribute contains a ScheduleStruct whose ScheduleHandle field matches the value of the ScheduleHandle field, the server SHALL set the thermostat's ActiveScheduleHandle attribute to the value of the ScheduleHandle field. */
    pub const SetActiveScheduleRequest: u32 = 0x05;
/** ID */
    pub const SetActivePresetRequest: u32 = 0x06;
}
/** This cluster provides an interface for controlling the current Channel on a device. */
pub mod Channel {
/** Change the channel on the media player to the channel case-insensitive exact matching the value passed as an argument. */
    pub const ChangeChannel: u32 = 0x00;
/** Upon receipt, this SHALL display the active status of the input list on screen. */
    pub const ChangeChannelResponse: u32 = 0x01;
/** Change the channel on the media plaeyer to the channel with the given Number in the ChannelList attribute. */
    pub const ChangeChannelByNumber: u32 = 0x02;
/** This command provides channel up and channel down functionality, but allows channel index jumps of size Count. When the value of the increase or decrease is larger than the number of channels remaining in the given direction, then the behavior SHALL be to return to the beginning (or end) of the channel list and continue. For example, if the current channel is at index 0 and count value of -1 is given, then the current channel should change to the last channel. */
    pub const SkipChannel: u32 = 0x03;
/** This command retrieves the program guide. It accepts several filter parameters to return specific schedule and program information from a content app. The command shall receive in response a ProgramGuideResponse. */
    pub const GetProgramGuide: u32 = 0x04;
/** This command is a response to the GetProgramGuide command. */
    pub const ProgramGuideResponse: u32 = 0x05;
/** Record a specific program or series when it goes live. This functionality enables DVR recording features. */
    pub const RecordProgram: u32 = 0x06;
/** Cancel recording for a specific program or series. */
    pub const CancelRecordProgram: u32 = 0x07;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod OvenMode {
/** This command is used to change device modes. */
    pub const ChangeToMode: u32 = 0x00;
/** This command is sent by the device on receipt of the ChangeToModeWithStatus command. */
    pub const ChangeToModeResponse: u32 = 0x01;
}
/** This cluster allows a client to manage the power draw of a device. An example of such a client could be an Energy Management System (EMS) which controls an Energy Smart Appliance (ESA). */
pub mod DeviceEnergyManagement {
/** Allows a client to request an adjustment in the power consumption of an ESA for a specified duration. */
    pub const PowerAdjustRequest: u32 = 0x00;
/** Allows a client to cancel an ongoing PowerAdjustmentRequest operation. */
    pub const CancelPowerAdjustRequest: u32 = 0x01;
/** Allows a client to adjust the start time of a Forecast sequence that has not yet started operation (i.e. where the current Forecast StartTime is in the future). */
    pub const StartTimeAdjustRequest: u32 = 0x02;
/** Allows a client to temporarily pause an operation and reduce the ESAs energy demand. */
    pub const PauseRequest: u32 = 0x03;
/** Allows a client to cancel the PauseRequest command and enable earlier resumption of operation. */
    pub const ResumeRequest: u32 = 0x04;
/** Allows a client to modify a Forecast within the limits allowed by the ESA. */
    pub const ModifyForecastRequest: u32 = 0x05;
/** Allows a client to ask the ESA to recompute its Forecast based on power and time constraints. */
    pub const RequestConstraintBasedForecast: u32 = 0x06;
/** Allows a client to request cancellation of a previous adjustment request in a StartTimeAdjustRequest, ModifyForecastRequest or RequestConstraintBasedForecast command. */
    pub const CancelRequest: u32 = 0x07;
}
/** Attributes and commands for configuring the temperature control, and reporting temperature. */
pub mod TemperatureControl {
/** The SetTemperature command SHALL have the following data fields: */
    pub const SetTemperature: u32 = 0x00;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod DeviceEnergyManagementMode {
/** This command is used to change device modes. */
    pub const ChangeToMode: u32 = 0x00;
/** This command is sent by the device on receipt of the ChangeToMode command. */
    pub const ChangeToModeResponse: u32 = 0x01;
}
/** This cluster provides facilities to configure and play Chime sounds, such as those used in a doorbell. */
pub mod Chime {
/** This command will play the currently selected chime or the chime passed in. */
    pub const PlayChimeSound: u32 = 0x00;
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod LaundryWasherMode {
/** This command is used to change device modes.
 * On receipt of this command the device SHALL respond with a ChangeToModeResponse command. */
    pub const ChangeToMode: u32 = 0x00;
/** This command is sent by the device on receipt of the ChangeToModeWithStatus command. */
    pub const ChangeToModeResponse: u32 = 0x01;
}
/** This cluster is used to configure a valve. */
pub mod ValveConfigurationandControl {
/** This command is used to set the valve to its open position. */
    pub const Open: u32 = 0x00;
/** This command is used to set the valve to its closed position. */
    pub const Close: u32 = 0x01;
}
/** This cluster supports remotely monitoring and, where supported, changing the operational state of an Oven. */
pub mod OvenCavityOperationalState {
    pub const Pause: u32 = 0x00;
/** Upon receipt, the device SHALL stop its operation if it is at a position where it is safe to do so and/or permitted. */
    pub const Stop: u32 = 0x01;
/** Upon receipt, the device SHALL start its operation if it is safe to do so and the device is in an operational state from which it can be started. */
    pub const Start: u32 = 0x02;
    pub const Resume: u32 = 0x03;
/** This command SHALL be generated in response to any of the Start, Stop, Pause, or Resume commands. */
    pub const OperationalCommandResponse: u32 = 0x04;
}
}
