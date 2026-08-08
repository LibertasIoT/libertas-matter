/** This cluster is used for managing the content control (including "parental control") settings on a media device such as a TV, or Set-top Box. */
pub const ContentControl: u32 = 0x050F;
/** Attributes and commands for configuring the microwave oven control, and reporting cooking stats. */
pub const MicrowaveOvenControl: u32 = 0x005F;
/** This cluster exposes interactions with a switch device, for the purpose of using those interactions by other devices.
 * Two types of switch devices are supported: latching switch (e.g. rocker switch) and momentary switch (e.g. push button), distinguished with their feature flags.
 * Interactions with the switch device are exposed as attributes (for the latching switch) and as events (for both types of switches). An interested party MAY subscribe to these attributes/events and thus be informed of the interactions, and can perform actions based on this, for example by sending commands to perform an action such as controlling a light or a window shade. */
pub const Switch: u32 = 0x003B;
/** The User Label Cluster provides a feature to tag an endpoint with zero or more labels. */
pub const UserLabel: u32 = 0x0041;
/** This cluster is used to allow clients to control the operation of a hot water heating appliance so that it can be used with energy management. */
pub const WaterHeaterManagement: u32 = 0x0094;
/** The Ethernet Network Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub const EthernetNetworkDiagnostics: u32 = 0x0037;
/** This cluster provides an interface for launching content on a media player device such as a TV or Speaker. */
pub const ContentLauncher: u32 = 0x050A;
/** The General Diagnostics Cluster, along with other diagnostics clusters, provide a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub const GeneralDiagnostics: u32 = 0x0033;
/** Attributes for reporting carbon monoxide concentration measurements */
pub const FormaldehydeConcentrationMeasurement: u32 = 0x042B;
/** Allows servers to ensure that listed clients are notified when a server is available for communication. */
pub const ICDManagement: u32 = 0x0046;
/** Functionality to configure, enable, disable network credentials and access on a Matter device. */
pub const NetworkCommissioning: u32 = 0x0031;
/** Accurate time is required for a number of reasons, including scheduling, display and validating security materials. */
pub const TimeSynchronization: u32 = 0x0038;
/** Attributes and commands for selecting a mode from a list of supported options. */
pub const RVCRunMode: u32 = 0x0054;
/** This cluster provides an interface to a boolean state called StateValue. */
pub const BooleanState: u32 = 0x0045;
/** The Commodity Price Cluster provides the mechanism for communicating Gas, Energy, or Water pricing information within the premises. */
pub const CommodityPrice: u32 = 0x0095;
/** This cluster provides an interface for launching content on a media player device such as a TV or Speaker. */
pub const ApplicationLauncher: u32 = 0x050C;
/** The Thread Network Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems */
pub const ThreadNetworkDiagnostics: u32 = 0x0035;
/** This cluster provides a standardized way for a Node (typically a Bridge, but could be any Node) to expose action information. */
pub const Actions: u32 = 0x0025;
/** Attributes for reporting carbon monoxide concentration measurements */
pub const PM25ConcentrationMeasurement: u32 = 0x042A;
/** The cluster provides commands for retrieving unstructured diagnostic logs from a Node that may be used to aid in diagnostics. */
pub const DiagnosticLogs: u32 = 0x0032;
/** The Group Key Management Cluster is the mechanism by which group keys are managed. */
pub const GroupKeyManagement: u32 = 0x003F;
/** Attributes for reporting carbon monoxide concentration measurements */
pub const CarbonMonoxideConcentrationMeasurement: u32 = 0x040C;
/** This cluster provides information about an application running on a TV or media player device which is represented as an endpoint. */
pub const ApplicationBasic: u32 = 0x050D;
/** Attributes and commands for controlling devices that can be set to a level between fully 'On' and fully 'Off.' */
pub const LevelControl: u32 = 0x0008;
/** Electric Vehicle Supply Equipment (EVSE) is equipment used to charge an Electric Vehicle (EV) or Plug-In Hybrid Electric Vehicle. This cluster provides an interface to the functionality of Electric Vehicle Supply Equipment (EVSE) management. */
pub const EnergyEVSE: u32 = 0x0099;
/** This cluster provides an interface for sending targeted commands to an Observer of a Content App on a Video Player device such as a Streaming Media Player, Smart TV or Smart Screen. The cluster server for Content App Observer is implemented by an endpoint that communicates with a Content App, such as a Casting Video Client. The cluster client for Content App Observer is implemented by a Content App endpoint. A Content App is informed of the NodeId of an Observer when a binding is set on the Content App. The Content App can then send the ContentAppMessage to the Observer (server cluster), and the Observer responds with a ContentAppMessageResponse. */
pub const ContentAppObserver: u32 = 0x0510;
/** This Cluster serves two purposes towards a Node communicating with a Bridge: indicate that the functionality on
 * the Endpoint where it is placed (and its Parts) is bridged from a non-CHIP technology; and provide a centralized
 * collection of attributes that the Node MAY collect to aid in conveying information regarding the Bridged Device to a user,
 * such as the vendor name, the model name, or user-assigned name. */
pub const BridgedDeviceBasicInformation: u32 = 0x0039;
/** The Software Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub const SoftwareDiagnostics: u32 = 0x0034;
/** This cluster is used to describe the configuration and capabilities of a Device's power system. */
pub const PowerSourceConfiguration: u32 = 0x002E;
/** Attributes and commands for selecting a mode from a list of supported options. */
pub const DishwasherMode: u32 = 0x0059;
/** Commands to trigger a Node to allow a new Administrator to commission it. */
pub const AdministratorCommissioning: u32 = 0x003C;
/** This cluster provides an interface to manage regions of interest, or Zones, which can be either manufacturer or user defined. */
pub const ZoneManagement: u32 = 0x0550;
/** The Joint Fabric Datastore Cluster is a cluster that provides a mechanism for the Joint Fabric Administrators to manage the set of Nodes, Groups, and Group membership among Nodes in the Joint Fabric. */
pub const JointFabricDatastore: u32 = 0x0752;
/** This cluster supports remotely monitoring and, where supported, changing the operational state of any device where a state machine is a part of the operation. */
pub const OperationalState: u32 = 0x0060;
/** Attributes and commands for selecting a mode from a list of supported options. */
pub const MicrowaveOvenMode: u32 = 0x005E;
/** This cluster provides a way to access options associated with the operation of
 * a laundry dryer device type. */
pub const LaundryDryerControls: u32 = 0x004A;
/** Supports the ability for clients to request the commissioning of themselves or other nodes onto a fabric which the cluster server can commission onto. */
pub const CommissionerControl: u32 = 0x0751;
/** Attributes and commands for selecting a mode from a list of supported options. */
pub const ModeSelect: u32 = 0x0050;
/** This cluster implements the upload of Audio and Video streams from the Push AV Stream Transport Cluster using suitable push-based transports. */
pub const PushAVStreamTransport: u32 = 0x0555;
/** This cluster provides an interface to soil measurement functionality, including configuration and provision of notifications of soil measurements. */
pub const SoilMeasurement: u32 = 0x0430;
/** Nodes should be expected to be deployed to any and all regions of the world. These global regions
 * may have differing preferences for how dates and times are conveyed. As such, Nodes that visually
 * or audibly convey time information need a mechanism by which they can be configured to use a
 * user’s preferred format. */
pub const TimeFormatLocalization: u32 = 0x002C;
/** This cluster provides an interface for controlling the Output on a media device such as a TV. */
pub const AudioOutput: u32 = 0x050B;
/** Attributes and commands for switching devices between 'On' and 'Off' states. */
pub const OnOff: u32 = 0x0006;
/** Attributes and commands for controlling the color properties of a color-capable light. */
pub const ColorControl: u32 = 0x0300;
/** Attributes for reporting carbon monoxide concentration measurements */
pub const PM10ConcentrationMeasurement: u32 = 0x042D;
/** Provides an interface for providing OTA software updates */
pub const OTASoftwareUpdateProvider: u32 = 0x0029;
/** Attributes and commands for configuring the Dishwasher alarm. */
pub const DishwasherAlarm: u32 = 0x005D;
/** This cluster provides an interface for observing and managing the state of smoke and CO alarms. */
pub const SmokeCOAlarm: u32 = 0x005C;
/** Functionality to retrieve operational information about a managed Wi-Fi network. */
pub const WiFiNetworkManagement: u32 = 0x0451;
/** This cluster provides an interface into controls associated with the operation of a device that provides pan, tilt, and zoom functions, either mechanically, or against a digital image. */
pub const CameraAVSettingsUserLevelManagement: u32 = 0x0552;
/** This cluster provides an interface for passing messages to be presented by a device. */
pub const Messages: u32 = 0x0097;
/** Attributes for reporting carbon monoxide concentration measurements */
pub const CarbonDioxideConcentrationMeasurement: u32 = 0x040D;
/** This cluster provides commands that facilitate user account login on a Content App or a node. For example, a Content App running on a Video Player device, which is represented as an endpoint (see [TV Architecture]), can use this cluster to help make the user account on the Content App match the user account on the Client. */
pub const AccountLogin: u32 = 0x050E;
/** Attributes and commands for selecting a mode from a list of supported options. */
pub const RVCCleanMode: u32 = 0x0055;
/** This cluster provides a mechanism for querying data about electrical power as measured by the server. */
pub const ElectricalPowerMeasurement: u32 = 0x0090;
/** The Fixed Label Cluster provides a feature for the device to tag an endpoint with zero or more read only
 * labels. */
pub const FixedLabel: u32 = 0x0040;
/** Nodes should be expected to be deployed to any and all regions of the world. These global regions
 * may have differing preferences for the units in which values are conveyed in communication to a
 * user. As such, Nodes that visually or audibly convey measurable values to the user need a
 * mechanism by which they can be configured to use a user’s preferred unit. */
pub const UnitLocalization: u32 = 0x002D;
/** This cluster is used to describe the configuration and capabilities of a physical power source that provides power to the Node. */
pub const PowerSource: u32 = 0x002F;
/** Attributes for reporting carbon monoxide concentration measurements */
pub const OzoneConcentrationMeasurement: u32 = 0x0415;
/** The Power Topology Cluster provides a mechanism for expressing how power is flowing between endpoints. */
pub const PowerTopology: u32 = 0x009C;
/** Attributes and commands for configuring the measurement of illuminance, and reporting illuminance measurements. */
pub const IlluminanceMeasurement: u32 = 0x0400;
/** The Commodity Metering Cluster provides the mechanism for communicating commodity consumption information within a premises. */
pub const CommodityMetering: u32 = 0x0B07;
/** The Descriptor Cluster is meant to replace the support from the Zigbee Device Object (ZDO) for describing a node, its endpoints and clusters. */
pub const Descriptor: u32 = 0x001D;
/** The Electrical Grid Conditions Cluster provides the mechanism for communicating electricity grid carbon intensity to devices within the premises in units of Grams of CO2e per kWh. */
pub const ElectricalGridConditions: u32 = 0x00A0;
/** Attributes for reporting carbon monoxide concentration measurements */
pub const NitrogenDioxideConcentrationMeasurement: u32 = 0x0413;
/** Attributes for reporting carbon monoxide concentration measurements */
pub const PM1ConcentrationMeasurement: u32 = 0x042C;
/** This cluster provides attributes and events for determining basic information about Nodes, which supports both
 * Commissioning and operational determination of Node characteristics, such as Vendor ID, Product ID and serial number,
 * which apply to the whole Node. Also allows setting user device information such as location. */
pub const BasicInformation: u32 = 0x0028;
/** Attributes and commands for configuring the measurement of relative humidity, and reporting relative humidity measurements. */
pub const RelativeHumidityMeasurement: u32 = 0x0405;
/** This cluster provides an interface for controlling Media Playback (PLAY, PAUSE, etc) on a media device such as a TV or Speaker. */
pub const MediaPlayback: u32 = 0x0506;
/** Provides an interface for controlling and adjusting automatic window coverings. */
pub const WindowCovering: u32 = 0x0102;
/** The Wi-Fi Network Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub const WiFiNetworkDiagnostics: u32 = 0x0036;
/** Attributes for reporting air quality classification */
pub const AirQuality: u32 = 0x005B;
/** Attributes for reporting carbon monoxide concentration measurements */
pub const TotalVolatileOrganicCompoundsConcentrationMeasurement: u32 = 0x042E;
/** Provides an interface for downloading and applying OTA software updates */
pub const OTASoftwareUpdateRequestor: u32 = 0x002A;
/** The WebRTC transport requestor cluster provides a way for stream consumers (e.g. Matter Stream Viewer) to establish a WebRTC connection with a stream provider. */
pub const WebRTCTransportRequestor: u32 = 0x0554;
/** Manages the names and credentials of Thread networks visible to the user. */
pub const ThreadNetworkDirectory: u32 = 0x0453;
/** The Service Area cluster provides an interface for controlling the areas where a device should operate, and for querying the current area being serviced. */
pub const ServiceArea: u32 = 0x0150;
/** Attributes and commands for selecting a mode from a list of supported options. */
pub const RefrigeratorAndTemperatureControlledCabinetMode: u32 = 0x0052;
/** The Access Control Cluster exposes a data model view of a
 * Node's Access Control List (ACL), which codifies the rules used to manage
 * and enforce Access Control for the Node's endpoints and their associated
 * cluster instances. */
pub const AccessControl: u32 = 0x001F;
/** Attributes and commands for selecting a mode from a list of supported options. */
pub const WaterHeaterMode: u32 = 0x009E;
/** This Cluster is used to provision TLS Endpoints with enough information to facilitate subsequent connection. */
pub const TLSClientManagement: u32 = 0x0802;
/** This cluster provides a mechanism for querying data about the electrical energy imported or provided by the server. */
pub const ElectricalEnergyMeasurement: u32 = 0x0091;
/** This cluster provides an interface for controlling a Closure. */
pub const ClosureControl: u32 = 0x0104;
/** Attributes and commands for putting a device into Identification mode (e.g. flashing a light). */
pub const Identify: u32 = 0x0003;
/** This cluster provides an interface for managing low power mode on a device. */
pub const LowPower: u32 = 0x0508;
/** The Binding Cluster is meant to replace the support from the Zigbee Device Object (ZDO) for supporting the binding table. */
pub const Binding: u32 = 0x001E;
/** Attributes and commands for selecting a mode from a list of supported options. */
pub const EnergyEVSEMode: u32 = 0x009D;
/** This cluster is used to configure a boolean sensor. */
pub const BooleanStateConfiguration: u32 = 0x0080;
/** Attributes for reporting carbon monoxide concentration measurements */
pub const RadonConcentrationMeasurement: u32 = 0x042F;
/** Nodes should be expected to be deployed to any and all regions of the world. These global regions
 * may have differing common languages, units of measurements, and numerical formatting
 * standards. As such, Nodes that visually or audibly convey information need a mechanism by which
 * they can be configured to use a user’s preferred language, units, etc */
pub const LocalizationConfiguration: u32 = 0x002B;
/** This Meter Identification Cluster provides attributes for determining advanced information about utility metering device. */
pub const MeterIdentification: u32 = 0x0B06;
/** This cluster provides an interface to specify preferences for how devices should consume energy. */
pub const EnergyPreference: u32 = 0x009B;
/** Attributes and commands for scene configuration and manipulation. */
pub const ScenesManagement: u32 = 0x0062;
/** Attributes and commands for monitoring HEPA filters in a device */
pub const HEPAFilterMonitoring: u32 = 0x0071;
/** Attributes and commands for monitoring HEPA filters in a device */
pub const ActivatedCarbonFilterMonitoring: u32 = 0x0072;
/** Attributes and commands for monitoring HEPA filters in a device */
pub const WaterTankLevelMonitoring: u32 = 0x0079;
/** This cluster provides an interface for managing low power mode on a device that supports the Wake On LAN protocol. */
pub const WakeOnLAN: u32 = 0x0503;
/** An interface for configuring and controlling pumps. */
pub const PumpConfigurationandControl: u32 = 0x0200;
/** Attributes and commands for configuring the measurement of temperature, and reporting temperature measurements. */
pub const TemperatureMeasurement: u32 = 0x0402;
/** This cluster is used to manage global aspects of the Commissioning flow. */
pub const GeneralCommissioning: u32 = 0x0030;
/** This cluster is used to add or remove Operational Credentials on a Commissionee or Node, as well as manage the associated Fabrics. */
pub const OperationalCredentials: u32 = 0x003E;
/** This cluster provides an interface for UX navigation within a set of targets on a device or endpoint. */
pub const TargetNavigator: u32 = 0x0505;
/** An interface for controlling a fan in a heating/cooling system. */
pub const FanControl: u32 = 0x0202;
/** An interface to a generic way to secure a door */
pub const DoorLock: u32 = 0x0101;
/** Attributes and commands for configuring the measurement of flow, and reporting flow measurements. */
pub const FlowMeasurement: u32 = 0x0404;
/** The WebRTC transport provider cluster provides a way for stream providers (e.g. Cameras) to stream or receive their data through WebRTC. */
pub const WebRTCTransportProvider: u32 = 0x0553;
/** Manage the Thread network of Thread Border Router */
pub const ThreadBorderRouterManagement: u32 = 0x0452;
/** The Camera AV Stream Management cluster is used to allow clients to manage, control, and configure various audio, video, and snapshot streams on a camera. */
pub const CameraAVStreamManagement: u32 = 0x0551;
/** An instance of the Joint Fabric Administrator Cluster only applies to Joint Fabric Administrator nodes fulfilling the role of Anchor CA. */
pub const JointFabricAdministrator: u32 = 0x0753;
/** This cluster supports remotely monitoring and, where supported, changing the operational state of a Robotic Vacuum. */
pub const RVCOperationalState: u32 = 0x0061;
/** This cluster supports remotely monitoring and controlling the different types of functionality available to a washing device, such as a washing machine. */
pub const LaundryWasherControls: u32 = 0x0053;
/** This cluster provides an interface for controlling a device like a TV using action commands such as UP, DOWN, and SELECT. */
pub const KeypadInput: u32 = 0x0509;
/** Attributes and commands for group configuration and manipulation. */
pub const Groups: u32 = 0x0004;
/** This cluster provides an interface to reflect and control a closure's range of movement, usually involving a panel, by using 6-axis framework. */
pub const ClosureDimension: u32 = 0x0105;
/** Attributes and commands for configuring the Refrigerator alarm. */
pub const RefrigeratorAlarm: u32 = 0x0057;
/** An interface for configuring the user interface of a thermostat (which may be remote from the thermostat). */
pub const ThermostatUserInterfaceConfiguration: u32 = 0x0204;
/** This cluster provides an interface for controlling the Input Selector on a media device such as a TV. */
pub const MediaInput: u32 = 0x0507;
/** The server cluster provides an interface to occupancy sensing functionality based on one or more sensing modalities, including configuration and provision of notifications of occupancy status. */
pub const OccupancySensing: u32 = 0x0406;
/** This Cluster is used to manage TLS Client Certificates and to provision
 * TLS endpoints with enough information to facilitate subsequent connection. */
pub const TLSCertificateManagement: u32 = 0x0801;
/** The CommodityTariffCluster provides the mechanism for communicating Commodity Tariff information within the premises. */
pub const CommodityTariff: u32 = 0x0700;
/** Attributes and commands for configuring the measurement of pressure, and reporting pressure measurements. */
pub const PressureMeasurement: u32 = 0x0403;
/** An interface for configuring and controlling the functionality of a thermostat. */
pub const Thermostat: u32 = 0x0201;
/** This cluster provides an interface for controlling the current Channel on a device. */
pub const Channel: u32 = 0x0504;
/** Provides extended device information for all the logical devices represented by a Bridged Node. */
pub const EcosystemInformation: u32 = 0x0750;
/** Attributes and commands for selecting a mode from a list of supported options. */
pub const OvenMode: u32 = 0x0049;
/** This cluster allows a client to manage the power draw of a device. An example of such a client could be an Energy Management System (EMS) which controls an Energy Smart Appliance (ESA). */
pub const DeviceEnergyManagement: u32 = 0x0098;
/** Attributes and commands for configuring the temperature control, and reporting temperature. */
pub const TemperatureControl: u32 = 0x0056;
/** Attributes and commands for selecting a mode from a list of supported options. */
pub const DeviceEnergyManagementMode: u32 = 0x009F;
/** This cluster provides facilities to configure and play Chime sounds, such as those used in a doorbell. */
pub const Chime: u32 = 0x0556;
/** Attributes and commands for selecting a mode from a list of supported options. */
pub const LaundryWasherMode: u32 = 0x0051;
/** This cluster is used to configure a valve. */
pub const ValveConfigurationandControl: u32 = 0x0081;
/** This cluster supports remotely monitoring and, where supported, changing the operational state of an Oven. */
pub const OvenCavityOperationalState: u32 = 0x0048;
