/** This cluster is used for managing the content control (including "parental control") settings on a media device such as a TV, or Set-top Box. */
pub mod ContentControl {
    pub mod StatusCodeEnum {
/** Provided PIN Code does not match the current PIN code. */
        pub const InvalidPINCode: u32 = 0x02;
/** Provided Rating is out of scope of the corresponding Rating list. */
        pub const InvalidRating: u32 = 0x03;
/** Provided Channel(s) is invalid. */
        pub const InvalidChannel: u32 = 0x04;
/** Provided Channel(s) already exists. */
        pub const ChannelAlreadyExist: u32 = 0x05;
/** Provided Channel(s) doesn't exist in BlockChannelList attribute. */
        pub const ChannelNotExist: u32 = 0x06;
/** Provided Application(s) is not identified. */
        pub const UnidentifiableApplication: u32 = 0x07;
/** Provided Application(s) already exists. */
        pub const ApplicationAlreadyExist: u32 = 0x08;
/** Provided Application(s) doesn't exist in BlockApplicationList attribute. */
        pub const ApplicationNotExist: u32 = 0x09;
/** Provided time Window already exists in BlockContentTimeWindow attribute. */
        pub const TimeWindowAlreadyExist: u32 = 0x0A;
/** Provided time window doesn't exist in BlockContentTimeWindow attribute. */
        pub const TimeWindowNotExist: u32 = 0x0B;
    }
    pub mod DayOfWeekBitmap {
/** Sunday */
        pub const Sunday: u32 = 0x01;
/** Monday */
        pub const Monday: u32 = 0x02;
/** Tuesday */
        pub const Tuesday: u32 = 0x04;
/** Wednesday */
        pub const Wednesday: u32 = 0x08;
/** Thursday */
        pub const Thursday: u32 = 0x10;
/** Friday */
        pub const Friday: u32 = 0x20;
/** Saturday */
        pub const Saturday: u32 = 0x40;
    }
}
/** This cluster is used to allow clients to control the operation of a hot water heating appliance so that it can be used with energy management. */
pub mod WaterHeaterManagement {
    pub mod BoostStateEnum {
/** Boost is not currently active */
        pub const Inactive: u32 = 0x00;
/** Boost is currently active */
        pub const Active: u32 = 0x01;
    }
    pub mod WaterHeaterHeatSourceBitmap {
/** Immersion Heating Element 1 */
        pub const ImmersionElement1: u32 = 0x01;
/** Immersion Heating Element 2 */
        pub const ImmersionElement2: u32 = 0x02;
/** Heat pump Heating */
        pub const HeatPump: u32 = 0x04;
/** Boiler Heating (e.g. Gas or Oil) */
        pub const Boiler: u32 = 0x08;
/** Other Heating */
        pub const Other: u32 = 0x10;
    }
}
/** The Ethernet Network Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub mod EthernetNetworkDiagnostics {
    pub mod PHYRateEnum {
/** PHY rate is 10Mbps */
        pub const Rate10M: u32 = 0x00;
/** PHY rate is 100Mbps */
        pub const Rate100M: u32 = 0x01;
/** PHY rate is 1Gbps */
        pub const Rate1G: u32 = 0x02;
/** PHY rate is 2.5Gbps */
        pub const Rate2_5G: u32 = 0x03;
/** PHY rate is 5Gbps */
        pub const Rate5G: u32 = 0x04;
/** PHY rate is 10Gbps */
        pub const Rate10G: u32 = 0x05;
/** PHY rate is 40Gbps */
        pub const Rate40G: u32 = 0x06;
/** PHY rate is 100Gbps */
        pub const Rate100G: u32 = 0x07;
/** PHY rate is 200Gbps */
        pub const Rate200G: u32 = 0x08;
/** PHY rate is 400Gbps */
        pub const Rate400G: u32 = 0x09;
    }
}
/** This cluster provides an interface for launching content on a media player device such as a TV or Speaker. */
pub mod ContentLauncher {
    pub mod MetricTypeEnum {
/** Dimensions defined in a number of Pixels */
        pub const Pixels: u32 = 0x00;
/** Dimensions defined as a percentage */
        pub const Percentage: u32 = 0x01;
    }
    pub mod ParameterEnum {
/** Actor represents an actor credited in video media content; for example, “Gaby Hoffman” */
        pub const Actor: u32 = 0x00;
/** Channel represents the identifying data for a television channel; for example, "PBS" */
        pub const Channel: u32 = 0x01;
/** A character represented in video media content; for example, “Snow White” */
        pub const Character: u32 = 0x02;
/** A director of the video media content; for example, “Spike Lee” */
        pub const Director: u32 = 0x03;
/** An event is a reference to a type of event; examples would include sports, music, or other types of events. For example, searching for "Football games" would search for a 'game' event entity and a 'football' sport entity. */
        pub const Event: u32 = 0x04;
/** A franchise is a video entity which can represent a number of video entities, like movies or TV shows. For example, take the fictional franchise "Intergalactic Wars" which represents a collection of movie trilogies, as well as animated and live action TV shows. This entity type was introduced to account for requests by customers such as "Find Intergalactic Wars movies", which would search for all 'Intergalactic Wars' programs of the MOVIE MediaType, rather than attempting to match to a single title. */
        pub const Franchise: u32 = 0x05;
/** Genre represents the genre of video media content such as action, drama or comedy. */
        pub const Genre: u32 = 0x06;
/** League represents the categorical information for a sporting league; for example, "NCAA" */
        pub const League: u32 = 0x07;
/** Popularity indicates whether the user asks for popular content. */
        pub const Popularity: u32 = 0x08;
/** The provider (MSP) the user wants this media to be played on; for example, "Netflix". */
        pub const Provider: u32 = 0x09;
/** Sport represents the categorical information of a sport; for example, football */
        pub const Sport: u32 = 0x0A;
/** SportsTeam represents the categorical information of a professional sports team; for example, "University of Washington Huskies" */
        pub const SportsTeam: u32 = 0x0B;
/** The type of content requested. Supported types are "Movie", "MovieSeries", "TVSeries", "TVSeason", "TVEpisode", "Trailer", "SportsEvent", "LiveEvent", and "Video" */
        pub const Type: u32 = 0x0C;
/** Video represents the identifying data for a specific piece of video content; for example, "Manchester by the Sea". */
        pub const Video: u32 = 0x0D;
/** Season represents the specific season number within a TV series. */
        pub const Season: u32 = 0x0E;
/** Episode represents a specific episode number within a Season in a TV series. */
        pub const Episode: u32 = 0x0F;
/** Represents a search text input across many parameter types or even outside of the defined param types. */
        pub const Any: u32 = 0x10;
    }
    pub mod StatusEnum {
/** Command succeeded */
        pub const Success: u32 = 0x00;
/** Requested URL could not be reached by device. */
        pub const URLNotAvailable: u32 = 0x01;
/** Requested URL returned 401 error code. */
        pub const AuthFailed: u32 = 0x02;
/** Requested Text Track (in PlaybackPreferences) not available */
        pub const TextTrackNotAvailable: u32 = 0x03;
/** Requested Audio Track (in PlaybackPreferences) not available */
        pub const AudioTrackNotAvailable: u32 = 0x04;
    }
    pub mod SupportedProtocolsBitmap {
/** Device supports Dynamic Adaptive Streaming over HTTP (DASH) */
        pub const DASH: u32 = 0x01;
/** Device supports HTTP Live Streaming (HLS) */
        pub const HLS: u32 = 0x02;
    }
}
/** The General Diagnostics Cluster, along with other diagnostics clusters, provide a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub mod GeneralDiagnostics {
    pub mod BootReasonEnum {
/** The Node is unable to identify the Power-On reason as one of the other provided enumeration values. */
        pub const Unspecified: u32 = 0x00;
/** The Node has booted as the result of physical interaction with the device resulting in a reboot. */
        pub const PowerOnReboot: u32 = 0x01;
/** The Node has rebooted as the result of a brown-out of the Node's power supply. */
        pub const BrownOutReset: u32 = 0x02;
/** The Node has rebooted as the result of a software watchdog timer. */
        pub const SoftwareWatchdogReset: u32 = 0x03;
/** The Node has rebooted as the result of a hardware watchdog timer. */
        pub const HardwareWatchdogReset: u32 = 0x04;
/** The Node has rebooted as the result of a completed software update. */
        pub const SoftwareUpdateCompleted: u32 = 0x05;
/** The Node has rebooted as the result of a software initiated reboot. */
        pub const SoftwareReset: u32 = 0x06;
    }
    pub mod HardwareFaultEnum {
/** The Node has encountered an unspecified fault. */
        pub const Unspecified: u32 = 0x00;
/** The Node has encountered a fault with at least one of its radios. */
        pub const Radio: u32 = 0x01;
/** The Node has encountered a fault with at least one of its sensors. */
        pub const Sensor: u32 = 0x02;
/** The Node has encountered an over-temperature fault that is resettable. */
        pub const ResettableOverTemp: u32 = 0x03;
/** The Node has encountered an over-temperature fault that is not resettable. */
        pub const NonResettableOverTemp: u32 = 0x04;
/** The Node has encountered a fault with at least one of its power sources. */
        pub const PowerSource: u32 = 0x05;
/** The Node has encountered a fault with at least one of its visual displays. */
        pub const VisualDisplayFault: u32 = 0x06;
/** The Node has encountered a fault with at least one of its audio outputs. */
        pub const AudioOutputFault: u32 = 0x07;
/** The Node has encountered a fault with at least one of its user interfaces. */
        pub const UserInterfaceFault: u32 = 0x08;
/** The Node has encountered a fault with its non-volatile memory. */
        pub const NonVolatileMemoryError: u32 = 0x09;
/** The Node has encountered disallowed physical tampering. */
        pub const TamperDetected: u32 = 0x0A;
    }
    pub mod InterfaceTypeEnum {
/** Indicates an interface of an unspecified type. */
        pub const Unspecified: u32 = 0x00;
/** Indicates a Wi-Fi interface. */
        pub const WiFi: u32 = 0x01;
/** Indicates a Ethernet interface. */
        pub const Ethernet: u32 = 0x02;
/** Indicates a Cellular interface. */
        pub const Cellular: u32 = 0x03;
/** Indicates a Thread interface. */
        pub const Thread: u32 = 0x04;
    }
    pub mod NetworkFaultEnum {
/** The Node has encountered an unspecified fault. */
        pub const Unspecified: u32 = 0x00;
/** The Node has encountered a network fault as a result of a hardware failure. */
        pub const HardwareFailure: u32 = 0x01;
/** The Node has encountered a network fault as a result of a jammed network. */
        pub const NetworkJammed: u32 = 0x02;
/** The Node has encountered a network fault as a result of a failure to establish a connection. */
        pub const ConnectionFailed: u32 = 0x03;
    }
    pub mod RadioFaultEnum {
/** The Node has encountered an unspecified radio fault. */
        pub const Unspecified: u32 = 0x00;
/** The Node has encountered a fault with its Wi-Fi radio. */
        pub const WiFiFault: u32 = 0x01;
/** The Node has encountered a fault with its cellular radio. */
        pub const CellularFault: u32 = 0x02;
/** The Node has encountered a fault with its 802.15.4 radio. */
        pub const ThreadFault: u32 = 0x03;
/** The Node has encountered a fault with its NFC radio. */
        pub const NFCFault: u32 = 0x04;
/** The Node has encountered a fault with its BLE radio. */
        pub const BLEFault: u32 = 0x05;
/** The Node has encountered a fault with its Ethernet controller. */
        pub const EthernetFault: u32 = 0x06;
    }
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod FormaldehydeConcentrationMeasurement {
    pub mod LevelValueEnum {
/** The level is Unknown */
        pub const Unknown: u32 = 0x00;
/** The level is considered Low */
        pub const Low: u32 = 0x01;
/** The level is considered Medium */
        pub const Medium: u32 = 0x02;
/** The level is considered High */
        pub const High: u32 = 0x03;
/** The level is considered Critical */
        pub const Critical: u32 = 0x04;
    }
    pub mod MeasurementMediumEnum {
/** The measurement is being made in Air */
        pub const Air: u32 = 0x00;
/** The measurement is being made in Water */
        pub const Water: u32 = 0x01;
/** The measurement is being made in Soil */
        pub const Soil: u32 = 0x02;
    }
    pub mod MeasurementUnitEnum {
/** Parts per Million (10) */
        pub const PPM: u32 = 0x00;
/** Parts per Billion (10) */
        pub const PPB: u32 = 0x01;
/** Parts per Trillion (10) */
        pub const PPT: u32 = 0x02;
/** Milligram per m */
        pub const MGM3: u32 = 0x03;
/** Microgram per m */
        pub const UGM3: u32 = 0x04;
/** Nanogram per m */
        pub const NGM3: u32 = 0x05;
/** Particles per m */
        pub const PM3: u32 = 0x06;
/** Becquerel per m */
        pub const BQM3: u32 = 0x07;
    }
}
/** Allows servers to ensure that listed clients are notified when a server is available for communication. */
pub mod ICDManagement {
    pub mod ClientTypeEnum {
/** The client is typically resident, always-on, fixed infrastructure in the home. */
        pub const Permanent: u32 = 0x00;
/** The client is mobile or non-resident or not always-on and may not always be available in the home. */
        pub const Ephemeral: u32 = 0x01;
    }
    pub mod OperatingModeEnum {
/** ICD is operating as a Short Idle Time ICD. */
        pub const SIT: u32 = 0x00;
/** ICD is operating as a Long Idle Time ICD. */
        pub const LIT: u32 = 0x01;
    }
    pub mod UserActiveModeTriggerBitmap {
/** Power Cycle to transition the device to ActiveMode */
        pub const PowerCycle: u32 = 0x01;
/** Settings menu on the device informs how to transition the device to ActiveMode */
        pub const SettingsMenu: u32 = 0x02;
/** Custom Instruction on how to transition the device to ActiveMode */
        pub const CustomInstruction: u32 = 0x04;
/** Device Manual informs how to transition the device to ActiveMode */
        pub const DeviceManual: u32 = 0x08;
/** Actuate Sensor to transition the device to ActiveMode */
        pub const ActuateSensor: u32 = 0x10;
/** Actuate Sensor for N seconds to transition the device to ActiveMode */
        pub const ActuateSensorSeconds: u32 = 0x20;
/** Actuate Sensor N times to transition the device to ActiveMode */
        pub const ActuateSensorTimes: u32 = 0x40;
/** Actuate Sensor until light blinks to transition the device to ActiveMode */
        pub const ActuateSensorLightsBlink: u32 = 0x80;
/** Press Reset Button to transition the device to ActiveMode */
        pub const ResetButton: u32 = 0x100;
/** Press Reset Button until light blinks to transition the device to ActiveMode */
        pub const ResetButtonLightsBlink: u32 = 0x200;
/** Press Reset Button for N seconds to transition the device to ActiveMode */
        pub const ResetButtonSeconds: u32 = 0x400;
/** Press Reset Button N times to transition the device to ActiveMode */
        pub const ResetButtonTimes: u32 = 0x800;
/** Press Setup Button to transition the device to ActiveMode */
        pub const SetupButton: u32 = 0x1000;
/** Press Setup Button for N seconds to transition the device to ActiveMode */
        pub const SetupButtonSeconds: u32 = 0x2000;
/** Press Setup Button until light blinks to transition the device to ActiveMode */
        pub const SetupButtonLightsBlink: u32 = 0x4000;
/** Press Setup Button N times to transition the device to ActiveMode */
        pub const SetupButtonTimes: u32 = 0x8000;
/** Press the N Button to transition the device to ActiveMode */
        pub const AppDefinedButton: u32 = 0x10000;
    }
}
/** Functionality to configure, enable, disable network credentials and access on a Matter device. */
pub mod NetworkCommissioning {
    pub mod NetworkCommissioningStatusEnum {
/** OK, no error */
        pub const Success: u32 = 0x00;
/** Value Outside Range */
        pub const OutOfRange: u32 = 0x01;
/** A collection would exceed its size limit */
        pub const BoundsExceeded: u32 = 0x02;
/** The NetworkID is not among the collection of added networks */
        pub const NetworkIDNotFound: u32 = 0x03;
/** The NetworkID is already among the collection of added networks */
        pub const DuplicateNetworkID: u32 = 0x04;
/** Cannot find AP: SSID Not found */
        pub const NetworkNotFound: u32 = 0x05;
/** Cannot find AP: Mismatch on band/channels/regulatory domain / 2.4GHz vs 5GHz */
        pub const RegulatoryError: u32 = 0x06;
/** Cannot associate due to authentication failure */
        pub const AuthFailure: u32 = 0x07;
/** Cannot associate due to unsupported security mode */
        pub const UnsupportedSecurity: u32 = 0x08;
/** Other association failure */
        pub const OtherConnectionFailure: u32 = 0x09;
/** Failure to generate an IPv6 address */
        pub const IPV6Failed: u32 = 0x0A;
/** Failure to bind Wi-Fi +<->+ IP interfaces */
        pub const IPBindFailed: u32 = 0x0B;
/** Unknown error */
        pub const UnknownError: u32 = 0x0C;
    }
    pub mod WiFiBandEnum {
/** 2.4GHz - 2.401GHz to 2.495GHz (802.11b/g/n/ax) */
        pub const _2G4: u32 = 0x00;
/** 3.65GHz - 3.655GHz to 3.695GHz (802.11y) */
        pub const _3G65: u32 = 0x01;
/** 5GHz - 5.150GHz to 5.895GHz (802.11a/n/ac/ax) */
        pub const _5G: u32 = 0x02;
/** 6GHz - 5.925GHz to 7.125GHz (802.11ax / Wi-Fi 6E) */
        pub const _6G: u32 = 0x03;
/** 60GHz - 57.24GHz to 70.20GHz (802.11ad/ay) */
        pub const _60G: u32 = 0x04;
/** Sub-1GHz - 755MHz to 931MHz (802.11ah) */
        pub const _1G: u32 = 0x05;
    }
    pub mod ThreadCapabilitiesBitmap {
/** Thread Border Router functionality is present */
        pub const IsBorderRouterCapable: u32 = 0x01;
/** Router mode is supported (interface could be in router or REED mode) */
        pub const IsRouterCapable: u32 = 0x02;
/** Sleepy end-device mode is supported */
        pub const IsSleepyEndDeviceCapable: u32 = 0x04;
/** Device is a full Thread device (opposite of Minimal Thread Device) */
        pub const IsFullThreadDevice: u32 = 0x08;
/** Synchronized sleepy end-device mode is supported */
        pub const IsSynchronizedSleepyEndDeviceCapable: u32 = 0x10;
    }
    pub mod WiFiSecurityBitmap {
/** Supports unencrypted Wi-Fi */
        pub const Unencrypted: u32 = 0x01;
/** Supports Wi-Fi using WEP security */
        pub const WEP: u32 = 0x02;
/** Supports Wi-Fi using WPA-Personal security */
        pub const WPAPERSONAL: u32 = 0x04;
/** Supports Wi-Fi using WPA2-Personal security */
        pub const WPA2PERSONAL: u32 = 0x08;
/** Supports Wi-Fi using WPA3-Personal security */
        pub const WPA3PERSONAL: u32 = 0x10;
    }
}
/** Accurate time is required for a number of reasons, including scheduling, display and validating security materials. */
pub mod TimeSynchronization {
    pub mod GranularityEnum {
/** This indicates that the node is not currently synchronized with a UTC Time source and its clock is based on the Last Known Good UTC Time only. */
        pub const NoTimeGranularity: u32 = 0x00;
/** This indicates the node was synchronized to an upstream source in the past, but sufficient clock drift has occurred such that the clock error is now > 5 seconds. */
        pub const MinutesGranularity: u32 = 0x01;
/** This indicates the node is synchronized to an upstream source using a low resolution protocol. UTC Time is accurate to ± 5 seconds. */
        pub const SecondsGranularity: u32 = 0x02;
/** This indicates the node is synchronized to an upstream source using high resolution time-synchronization protocol such as NTP, or has built-in GNSS with some amount of jitter applying its GNSS timestamp. UTC Time is accurate to ± 50 ms. */
        pub const MillisecondsGranularity: u32 = 0x03;
/** This indicates the node is synchronized to an upstream source using a highly precise time-synchronization protocol such as PTP, or has built-in GNSS. UTC time is accurate to ± 10 μs. */
        pub const MicrosecondsGranularity: u32 = 0x04;
    }
    pub mod StatusCodeEnum {
/** Node rejected the attempt to set the UTC time */
        pub const TimeNotAccepted: u32 = 0x02;
    }
    pub mod TimeSourceEnum {
/** Node is not currently synchronized with a UTC Time source. */
        pub const None: u32 = 0x00;
/** Node uses an unlisted time source. */
        pub const Unknown: u32 = 0x01;
/** Node received time from a client using the SetUTCTime Command. */
        pub const Admin: u32 = 0x02;
/** Synchronized time by querying the Time Synchronization cluster of another Node. */
        pub const NodeTimeCluster: u32 = 0x03;
/** SNTP from a server not in the Matter network. NTS is not used. */
        pub const NonMatterSNTP: u32 = 0x04;
/** NTP from servers not in the Matter network. None of the servers used NTS. */
        pub const NonMatterNTP: u32 = 0x05;
/** SNTP from a server within the Matter network. NTS is not used. */
        pub const MatterSNTP: u32 = 0x06;
/** NTP from servers within the Matter network. None of the servers used NTS. */
        pub const MatterNTP: u32 = 0x07;
/** NTP from multiple servers in the Matter network and external. None of the servers used NTS. */
        pub const MixedNTP: u32 = 0x08;
/** SNTP from a server not in the Matter network. NTS is used. */
        pub const NonMatterSNTPNTS: u32 = 0x09;
/** NTP from servers not in the Matter network. NTS is used on at least one server. */
        pub const NonMatterNTPNTS: u32 = 0x0A;
/** SNTP from a server within the Matter network. NTS is used. */
        pub const MatterSNTPNTS: u32 = 0x0B;
/** NTP from a server within the Matter network. NTS is used on at least one server. */
        pub const MatterNTPNTS: u32 = 0x0C;
/** NTP from multiple servers in the Matter network and external. NTS is used on at least one server. */
        pub const MixedNTPNTS: u32 = 0x0D;
/** Time synchronization comes from a vendor cloud-based source (e.g. "Date" header in authenticated HTTPS connection). */
        pub const CloudSource: u32 = 0x0E;
/** Time synchronization comes from PTP. */
        pub const PTP: u32 = 0x0F;
/** Time synchronization comes from a GNSS source. */
        pub const GNSS: u32 = 0x10;
    }
    pub mod TimeZoneDatabaseEnum {
/** Node has a full list of the available time zones */
        pub const Full: u32 = 0x00;
/** Node has a partial list of the available time zones */
        pub const Partial: u32 = 0x01;
/** Node does not have a time zone database */
        pub const None: u32 = 0x02;
    }
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod RVCRunMode {
    pub mod ModeTag {
        pub const Auto: u32 = 0x00;
        pub const Quick: u32 = 0x01;
        pub const Quiet: u32 = 0x02;
        pub const LowNoise: u32 = 0x03;
        pub const LowEnergy: u32 = 0x04;
        pub const Vacation: u32 = 0x05;
        pub const Min: u32 = 0x06;
        pub const Max: u32 = 0x07;
        pub const Night: u32 = 0x08;
        pub const Day: u32 = 0x09;
        pub const Idle: u32 = 0x4000;
        pub const Cleaning: u32 = 0x4001;
        pub const Mapping: u32 = 0x4002;
    }
    pub mod StatusCodeEnum {
        pub const Stuck: u32 = 0x41;
        pub const DustBinMissing: u32 = 0x42;
        pub const DustBinFull: u32 = 0x43;
        pub const WaterTankEmpty: u32 = 0x44;
        pub const WaterTankMissing: u32 = 0x45;
        pub const WaterTankLidOpen: u32 = 0x46;
        pub const MopCleaningPadMissing: u32 = 0x47;
        pub const BatteryLow: u32 = 0x48;
    }
}
/** The Commodity Price Cluster provides the mechanism for communicating Gas, Energy, or Water pricing information within the premises. */
pub mod CommodityPrice {
    pub mod CommodityPriceDetailBitmap {
/** A textual description of a price; e.g. the name of a rate plan. */
        pub const Description: u32 = 0x01;
/** A breakdown of the component parts of a price; e.g. generation, delivery, etc. */
        pub const Components: u32 = 0x02;
    }
}
/** This cluster provides an interface for launching content on a media player device such as a TV or Speaker. */
pub mod ApplicationLauncher {
    pub mod StatusEnum {
/** Command succeeded */
        pub const Success: u32 = 0x00;
/** Requested app is not available */
        pub const AppNotAvailable: u32 = 0x01;
/** Video platform unable to honor command */
        pub const SystemBusy: u32 = 0x02;
/** User approval for app download is pending */
        pub const PendingUserApproval: u32 = 0x03;
/** Downloading the requested app */
        pub const Downloading: u32 = 0x04;
/** Installing the requested app */
        pub const Installing: u32 = 0x05;
    }
}
/** The Thread Network Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems */
pub mod ThreadNetworkDiagnostics {
    pub mod ConnectionStatusEnum {
/** Node is connected */
        pub const Connected: u32 = 0x00;
/** Node is not connected */
        pub const NotConnected: u32 = 0x01;
    }
    pub mod NetworkFaultEnum {
/** Indicates an unspecified fault. */
        pub const Unspecified: u32 = 0x00;
/** Indicates the Thread link is down. */
        pub const LinkDown: u32 = 0x01;
/** Indicates there has been Thread hardware failure. */
        pub const HardwareFailure: u32 = 0x02;
/** Indicates the Thread network is jammed. */
        pub const NetworkJammed: u32 = 0x03;
    }
    pub mod RoutingRoleEnum {
/** Unspecified routing role. */
        pub const Unspecified: u32 = 0x00;
/** The Node does not currently have a role as a result of the Thread interface not currently being configured or operational. */
        pub const Unassigned: u32 = 0x01;
/** The Node acts as a Sleepy End Device with RX-off-when-idle sleepy radio behavior. */
        pub const SleepyEndDevice: u32 = 0x02;
/** The Node acts as an End Device without RX-off-when-idle sleepy radio behavior. */
        pub const EndDevice: u32 = 0x03;
/** The Node acts as an Router Eligible End Device. */
        pub const REED: u32 = 0x04;
/** The Node acts as a Router Device. */
        pub const Router: u32 = 0x05;
/** The Node acts as a Leader Device. */
        pub const Leader: u32 = 0x06;
    }
}
/** This cluster provides a standardized way for a Node (typically a Bridge, but could be any Node) to expose action information. */
pub mod Actions {
    pub mod ActionErrorEnum {
/** Other reason not listed in the row(s) below */
        pub const Unknown: u32 = 0x00;
/** The action was interrupted by another command or interaction */
        pub const Interrupted: u32 = 0x01;
    }
    pub mod ActionStateEnum {
/** The action is not active */
        pub const Inactive: u32 = 0x00;
/** The action is active */
        pub const Active: u32 = 0x01;
/** The action has been paused */
        pub const Paused: u32 = 0x02;
/** The action has been disabled */
        pub const Disabled: u32 = 0x03;
    }
    pub mod ActionTypeEnum {
/** Use this only when none of the other values applies */
        pub const Other: u32 = 0x00;
/** Bring the endpoints into a certain state */
        pub const Scene: u32 = 0x01;
/** A sequence of states with a certain time pattern */
        pub const Sequence: u32 = 0x02;
/** Control an automation (e.g. motion sensor controlling lights) */
        pub const Automation: u32 = 0x03;
/** Sequence that will run when something doesn't happen */
        pub const Exception: u32 = 0x04;
/** Use the endpoints to send a message to user */
        pub const Notification: u32 = 0x05;
/** Higher priority notification */
        pub const Alarm: u32 = 0x06;
    }
    pub mod EndpointListTypeEnum {
/** Another group of endpoints */
        pub const Other: u32 = 0x00;
/** User-configured group of endpoints where an endpoint can be in only one room */
        pub const Room: u32 = 0x01;
/** User-configured group of endpoints where an endpoint can be in any number of zones */
        pub const Zone: u32 = 0x02;
    }
    pub mod CommandBits {
/** Indicate support for InstantAction command */
        pub const InstantAction: u32 = 0x01;
/** Indicate support for InstantActionWithTransition command */
        pub const InstantActionWithTransition: u32 = 0x02;
/** Indicate support for StartAction command */
        pub const StartAction: u32 = 0x04;
/** Indicate support for StartActionWithDuration command */
        pub const StartActionWithDuration: u32 = 0x08;
/** Indicate support for StopAction command */
        pub const StopAction: u32 = 0x10;
/** Indicate support for PauseAction command */
        pub const PauseAction: u32 = 0x20;
/** Indicate support for PauseActionWithDuration command */
        pub const PauseActionWithDuration: u32 = 0x40;
/** Indicate support for ResumeAction command */
        pub const ResumeAction: u32 = 0x80;
/** Indicate support for EnableAction command */
        pub const EnableAction: u32 = 0x100;
/** Indicate support for EnableActionWithDuration command */
        pub const EnableActionWithDuration: u32 = 0x200;
/** Indicate support for DisableAction command */
        pub const DisableAction: u32 = 0x400;
/** Indicate support for DisableActionWithDuration command */
        pub const DisableActionWithDuration: u32 = 0x800;
    }
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod PM25ConcentrationMeasurement {
    pub mod LevelValueEnum {
/** The level is Unknown */
        pub const Unknown: u32 = 0x00;
/** The level is considered Low */
        pub const Low: u32 = 0x01;
/** The level is considered Medium */
        pub const Medium: u32 = 0x02;
/** The level is considered High */
        pub const High: u32 = 0x03;
/** The level is considered Critical */
        pub const Critical: u32 = 0x04;
    }
    pub mod MeasurementMediumEnum {
/** The measurement is being made in Air */
        pub const Air: u32 = 0x00;
/** The measurement is being made in Water */
        pub const Water: u32 = 0x01;
/** The measurement is being made in Soil */
        pub const Soil: u32 = 0x02;
    }
    pub mod MeasurementUnitEnum {
/** Parts per Million (10) */
        pub const PPM: u32 = 0x00;
/** Parts per Billion (10) */
        pub const PPB: u32 = 0x01;
/** Parts per Trillion (10) */
        pub const PPT: u32 = 0x02;
/** Milligram per m */
        pub const MGM3: u32 = 0x03;
/** Microgram per m */
        pub const UGM3: u32 = 0x04;
/** Nanogram per m */
        pub const NGM3: u32 = 0x05;
/** Particles per m */
        pub const PM3: u32 = 0x06;
/** Becquerel per m */
        pub const BQM3: u32 = 0x07;
    }
}
/** The cluster provides commands for retrieving unstructured diagnostic logs from a Node that may be used to aid in diagnostics. */
pub mod DiagnosticLogs {
    pub mod IntentEnum {
/** Logs to be used for end-user support */
        pub const EndUserSupport: u32 = 0x00;
/** Logs to be used for network diagnostics */
        pub const NetworkDiag: u32 = 0x01;
/** Obtain crash logs from the Node */
        pub const CrashLogs: u32 = 0x02;
    }
    pub mod StatusEnum {
/** Successful transfer of logs */
        pub const Success: u32 = 0x00;
/** All logs have been transferred */
        pub const Exhausted: u32 = 0x01;
/** No logs of the requested type available */
        pub const NoLogs: u32 = 0x02;
/** Unable to handle request, retry later */
        pub const Busy: u32 = 0x03;
/** The request is denied, no logs being transferred */
        pub const Denied: u32 = 0x04;
    }
    pub mod TransferProtocolEnum {
/** Logs to be returned as a response */
        pub const ResponsePayload: u32 = 0x00;
/** Logs to be returned using BDX */
        pub const BDX: u32 = 0x01;
    }
}
/** The Group Key Management Cluster is the mechanism by which group keys are managed. */
pub mod GroupKeyManagement {
    pub mod GroupKeyMulticastPolicyEnum {
/** Indicates filtering of multicast messages for a specific Group ID */
        pub const PerGroupID: u32 = 0x00;
/** Indicates not filtering of multicast messages */
        pub const AllNodes: u32 = 0x01;
    }
    pub mod GroupKeySecurityPolicyEnum {
/** Message counter synchronization using trust-first */
        pub const TrustFirst: u32 = 0x00;
/** Message counter synchronization using cache-and-sync */
        pub const CacheAndSync: u32 = 0x01;
    }
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod CarbonMonoxideConcentrationMeasurement {
    pub mod LevelValueEnum {
/** The level is Unknown */
        pub const Unknown: u32 = 0x00;
/** The level is considered Low */
        pub const Low: u32 = 0x01;
/** The level is considered Medium */
        pub const Medium: u32 = 0x02;
/** The level is considered High */
        pub const High: u32 = 0x03;
/** The level is considered Critical */
        pub const Critical: u32 = 0x04;
    }
    pub mod MeasurementMediumEnum {
/** The measurement is being made in Air */
        pub const Air: u32 = 0x00;
/** The measurement is being made in Water */
        pub const Water: u32 = 0x01;
/** The measurement is being made in Soil */
        pub const Soil: u32 = 0x02;
    }
    pub mod MeasurementUnitEnum {
/** Parts per Million (10) */
        pub const PPM: u32 = 0x00;
/** Parts per Billion (10) */
        pub const PPB: u32 = 0x01;
/** Parts per Trillion (10) */
        pub const PPT: u32 = 0x02;
/** Milligram per m */
        pub const MGM3: u32 = 0x03;
/** Microgram per m */
        pub const UGM3: u32 = 0x04;
/** Nanogram per m */
        pub const NGM3: u32 = 0x05;
/** Particles per m */
        pub const PM3: u32 = 0x06;
/** Becquerel per m */
        pub const BQM3: u32 = 0x07;
    }
}
/** This cluster provides information about an application running on a TV or media player device which is represented as an endpoint. */
pub mod ApplicationBasic {
    pub mod ApplicationStatusEnum {
/** Application is not running. */
        pub const Stopped: u32 = 0x00;
/** Application is running, is visible to the user, and is the active target for input. */
        pub const ActiveVisibleFocus: u32 = 0x01;
/** Application is running but not visible to the user. */
        pub const ActiveHidden: u32 = 0x02;
/** Application is running and visible, but is not the active target for input. */
        pub const ActiveVisibleNotFocus: u32 = 0x03;
    }
}
/** Attributes and commands for controlling devices that can be set to a level between fully 'On' and fully 'Off.' */
pub mod LevelControl {
    pub mod MoveModeEnum {
/** Increase the level */
        pub const Up: u32 = 0x00;
/** Decrease the level */
        pub const Down: u32 = 0x01;
    }
    pub mod StepModeEnum {
/** Step upwards */
        pub const Up: u32 = 0x00;
/** Step downwards */
        pub const Down: u32 = 0x01;
    }
    pub mod OptionsBitmap {
/** Dependency on On/Off cluster */
        pub const ExecuteIfOff: u32 = 0x01;
/** Dependency on Color Control cluster */
        pub const CoupleColorTempToLevel: u32 = 0x02;
    }
}
/** Electric Vehicle Supply Equipment (EVSE) is equipment used to charge an Electric Vehicle (EV) or Plug-In Hybrid Electric Vehicle. This cluster provides an interface to the functionality of Electric Vehicle Supply Equipment (EVSE) management. */
pub mod EnergyEVSE {
    pub mod EnergyTransferStoppedReasonEnum {
/** The EV decided to stop */
        pub const EVStopped: u32 = 0x00;
/** The EVSE decided to stop */
        pub const EVSEStopped: u32 = 0x01;
/** An other unknown reason */
        pub const Other: u32 = 0x02;
    }
    pub mod FaultStateEnum {
/** The EVSE is not in an error state. */
        pub const NoError: u32 = 0x00;
/** The EVSE is unable to obtain electrical measurements. */
        pub const MeterFailure: u32 = 0x01;
/** The EVSE input voltage level is too high. */
        pub const OverVoltage: u32 = 0x02;
/** The EVSE input voltage level is too low. */
        pub const UnderVoltage: u32 = 0x03;
/** The EVSE detected charging current higher than allowed by charger. */
        pub const OverCurrent: u32 = 0x04;
/** The EVSE detected voltage on charging pins when the contactor is open. */
        pub const ContactWetFailure: u32 = 0x05;
/** The EVSE detected absence of voltage after enabling contactor. */
        pub const ContactDryFailure: u32 = 0x06;
/** The EVSE has an unbalanced current supply. */
        pub const GroundFault: u32 = 0x07;
/** The EVSE has detected a loss in power. */
        pub const PowerLoss: u32 = 0x08;
/** The EVSE has detected another power quality issue (e.g. phase imbalance). */
        pub const PowerQuality: u32 = 0x09;
/** The EVSE pilot signal amplitude short circuited to ground. */
        pub const PilotShortCircuit: u32 = 0x0A;
/** The emergency stop button was pressed. */
        pub const EmergencyStop: u32 = 0x0B;
/** The EVSE detected that the cable has been disconnected. */
        pub const EVDisconnected: u32 = 0x0C;
/** The EVSE could not determine proper power supply level. */
        pub const WrongPowerSupply: u32 = 0x0D;
/** The EVSE detected Live and Neutral are swapped. */
        pub const LiveNeutralSwap: u32 = 0x0E;
/** The EVSE internal temperature is too high. */
        pub const OverTemperature: u32 = 0x0F;
/** Any other reason. */
        pub const Other: u32 = 0xFF;
    }
    pub mod StateEnum {
/** The EV is not plugged in. */
        pub const NotPluggedIn: u32 = 0x00;
/** The EV is plugged in, but not demanding current. */
        pub const PluggedInNoDemand: u32 = 0x01;
/** The EV is plugged in and is demanding current, but EVSE is not allowing current to flow. */
        pub const PluggedInDemand: u32 = 0x02;
/** The EV is plugged in, charging is in progress, and current is flowing */
        pub const PluggedInCharging: u32 = 0x03;
/** The EV is plugged in, discharging is in progress, and current is flowing */
        pub const PluggedInDischarging: u32 = 0x04;
/** The EVSE is transitioning from any plugged-in state to NotPluggedIn */
        pub const SessionEnding: u32 = 0x05;
/** There is a fault, further details in the FaultState attribute */
        pub const Fault: u32 = 0x06;
    }
    pub mod SupplyStateEnum {
/** The EV is not currently allowed to charge or discharge */
        pub const Disabled: u32 = 0x00;
/** The EV is currently allowed to charge */
        pub const ChargingEnabled: u32 = 0x01;
/** The EV is currently allowed to discharge */
        pub const DischargingEnabled: u32 = 0x02;
/** The EV is not currently allowed to charge or discharge due to an error. The error must be cleared before operation can continue. */
        pub const DisabledError: u32 = 0x03;
/** The EV is not currently allowed to charge or discharge due to self-diagnostics mode. */
        pub const DisabledDiagnostics: u32 = 0x04;
/** The EV is currently allowed to charge and discharge */
        pub const Enabled: u32 = 0x05;
    }
    pub mod TargetDayOfWeekBitmap {
/** Sunday */
        pub const Sunday: u32 = 0x01;
/** Monday */
        pub const Monday: u32 = 0x02;
/** Tuesday */
        pub const Tuesday: u32 = 0x04;
/** Wednesday */
        pub const Wednesday: u32 = 0x08;
/** Thursday */
        pub const Thursday: u32 = 0x10;
/** Friday */
        pub const Friday: u32 = 0x20;
/** Saturday */
        pub const Saturday: u32 = 0x40;
    }
}
/** This cluster provides an interface for sending targeted commands to an Observer of a Content App on a Video Player device such as a Streaming Media Player, Smart TV or Smart Screen. The cluster server for Content App Observer is implemented by an endpoint that communicates with a Content App, such as a Casting Video Client. The cluster client for Content App Observer is implemented by a Content App endpoint. A Content App is informed of the NodeId of an Observer when a binding is set on the Content App. The Content App can then send the ContentAppMessage to the Observer (server cluster), and the Observer responds with a ContentAppMessageResponse. */
pub mod ContentAppObserver {
    pub mod StatusEnum {
/** Command succeeded */
        pub const Success: u32 = 0x00;
/** Data field in command was not understood by the Observer */
        pub const UnexpectedData: u32 = 0x01;
    }
}
/** This Cluster serves two purposes towards a Node communicating with a Bridge: indicate that the functionality on
 * the Endpoint where it is placed (and its Parts) is bridged from a non-CHIP technology; and provide a centralized
 * collection of attributes that the Node MAY collect to aid in conveying information regarding the Bridged Device to a user,
 * such as the vendor name, the model name, or user-assigned name. */
pub mod BridgedDeviceBasicInformation {
    pub mod ColorEnum {
/** Approximately RGB #000000. */
        pub const Black: u32 = 0x00;
/** Approximately RGB #000080. */
        pub const Navy: u32 = 0x01;
/** Approximately RGB #008000. */
        pub const Green: u32 = 0x02;
/** Approximately RGB #008080. */
        pub const Teal: u32 = 0x03;
/** Approximately RGB #800000. */
        pub const Maroon: u32 = 0x04;
/** Approximately RGB #800080. */
        pub const Purple: u32 = 0x05;
/** Approximately RGB #808000. */
        pub const Olive: u32 = 0x06;
/** Approximately RGB #808080. */
        pub const Gray: u32 = 0x07;
/** Approximately RGB #0000FF. */
        pub const Blue: u32 = 0x08;
/** Approximately RGB #00FF00. */
        pub const Lime: u32 = 0x09;
/** Approximately RGB #00FFFF. */
        pub const Aqua: u32 = 0x0A;
/** Approximately RGB #FF0000. */
        pub const Red: u32 = 0x0B;
/** Approximately RGB #FF00FF. */
        pub const Fuchsia: u32 = 0x0C;
/** Approximately RGB #FFFF00. */
        pub const Yellow: u32 = 0x0D;
/** Approximately RGB #FFFFFF. */
        pub const White: u32 = 0x0E;
/** Typical hardware "Nickel" color. */
        pub const Nickel: u32 = 0x0F;
/** Typical hardware "Chrome" color. */
        pub const Chrome: u32 = 0x10;
/** Typical hardware "Brass" color. */
        pub const Brass: u32 = 0x11;
/** Typical hardware "Copper" color. */
        pub const Copper: u32 = 0x12;
/** Typical hardware "Silver" color. */
        pub const Silver: u32 = 0x13;
/** Typical hardware "Gold" color. */
        pub const Gold: u32 = 0x14;
    }
    pub mod ProductFinishEnum {
/** Product has some other finish not listed below. */
        pub const Other: u32 = 0x00;
/** Product has a matte finish. */
        pub const Matte: u32 = 0x01;
/** Product has a satin finish. */
        pub const Satin: u32 = 0x02;
/** Product has a polished or shiny finish. */
        pub const Polished: u32 = 0x03;
/** Product has a rugged finish. */
        pub const Rugged: u32 = 0x04;
/** Product has a fabric finish. */
        pub const Fabric: u32 = 0x05;
    }
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod DishwasherMode {
    pub mod ModeTag {
        pub const Auto: u32 = 0x00;
        pub const Quick: u32 = 0x01;
        pub const Quiet: u32 = 0x02;
        pub const LowNoise: u32 = 0x03;
        pub const LowEnergy: u32 = 0x04;
        pub const Vacation: u32 = 0x05;
        pub const Min: u32 = 0x06;
        pub const Max: u32 = 0x07;
        pub const Night: u32 = 0x08;
        pub const Day: u32 = 0x09;
        pub const Normal: u32 = 0x4000;
        pub const Heavy: u32 = 0x4001;
        pub const Light: u32 = 0x4002;
    }
}
/** Commands to trigger a Node to allow a new Administrator to commission it. */
pub mod AdministratorCommissioning {
    pub mod CommissioningWindowStatusEnum {
/** Commissioning window not open */
        pub const WindowNotOpen: u32 = 0x00;
/** An Enhanced Commissioning Method window is open */
        pub const EnhancedWindowOpen: u32 = 0x01;
/** A Basic Commissioning Method window is open */
        pub const BasicWindowOpen: u32 = 0x02;
    }
    pub mod StatusCodeEnum {
/** Could not be completed because another commissioning is in progress */
        pub const Busy: u32 = 0x02;
/** Provided PAKE parameters were incorrectly formatted or otherwise invalid */
        pub const PAKEParameterError: u32 = 0x03;
/** No commissioning window was currently open */
        pub const WindowNotOpen: u32 = 0x04;
    }
}
/** This cluster provides an interface to manage regions of interest, or Zones, which can be either manufacturer or user defined. */
pub mod ZoneManagement {
    pub mod ZoneEventStoppedReasonEnum {
/** Indicates that whatever triggered the Zone event has stopped being detected. */
        pub const ActionStopped: u32 = 0x00;
/** Indicates that the max duration for detecting triggering activity has been reached. */
        pub const Timeout: u32 = 0x01;
    }
    pub mod ZoneEventTriggeredReasonEnum {
/** Zone event triggered because motion is detected */
        pub const Motion: u32 = 0x00;
    }
    pub mod ZoneSourceEnum {
/** Indicates a Manufacturer defined Zone. */
        pub const Mfg: u32 = 0x00;
/** Indicates a User defined Zone. */
        pub const User: u32 = 0x01;
    }
    pub mod ZoneTypeEnum {
/** Indicates a Two Dimensional Cartesian Zone */
        pub const TwoDCARTZone: u32 = 0x00;
    }
    pub mod ZoneUseEnum {
/** Indicates Zone is intended to detect Motion */
        pub const Motion: u32 = 0x00;
/** Indicates Zone is intended to protect privacy */
        pub const Privacy: u32 = 0x01;
/** Indicates Zone provides a focus area */
        pub const Focus: u32 = 0x02;
    }
}
/** The Joint Fabric Datastore Cluster is a cluster that provides a mechanism for the Joint Fabric Administrators to manage the set of Nodes, Groups, and Group membership among Nodes in the Joint Fabric. */
pub mod JointFabricDatastore {
    pub mod DatastoreAccessControlEntryAuthModeEnum {
/** Passcode authenticated session */
        pub const PASE: u32 = 0x01;
/** Certificate authenticated session */
        pub const CASE: u32 = 0x02;
/** Group authenticated session */
        pub const Group: u32 = 0x03;
    }
    pub mod DatastoreAccessControlEntryPrivilegeEnum {
/** Can read and observe all (except Access Control Cluster) */
        pub const View: u32 = 0x01;
        pub const ProxyView: u32 = 0x02;
/** View privileges, and can perform the primary function of this Node (except Access Control Cluster) */
        pub const Operate: u32 = 0x03;
/** Operate privileges, and can modify persistent configuration of this Node (except Access Control Cluster) */
        pub const Manage: u32 = 0x04;
/** Manage privileges, and can observe and modify the Access Control Cluster */
        pub const Administer: u32 = 0x05;
    }
    pub mod DatastoreGroupKeyMulticastPolicyEnum {
/** Indicates filtering of multicast messages for a specific Group ID */
        pub const PerGroupID: u32 = 0x00;
/** Indicates not filtering of multicast messages */
        pub const AllNodes: u32 = 0x01;
    }
    pub mod DatastoreGroupKeySecurityPolicyEnum {
/** Message counter synchronization using trust-first */
        pub const TrustFirst: u32 = 0x00;
    }
    pub mod DatastoreStateEnum {
/** Target device operation is pending */
        pub const Pending: u32 = 0x00;
/** Target device operation has been committed */
        pub const Committed: u32 = 0x01;
/** Target device delete operation is pending */
        pub const DeletePending: u32 = 0x02;
/** Target device operation has failed */
        pub const CommitFailed: u32 = 0x03;
    }
}
/** This cluster supports remotely monitoring and, where supported, changing the operational state of any device where a state machine is a part of the operation. */
pub mod OperationalState {
    pub mod ErrorStateEnum {
/** The device is not in an error state */
        pub const NoError: u32 = 0x00;
/** The device is unable to start or resume operation */
        pub const UnableToStartOrResume: u32 = 0x01;
/** The device was unable to complete the current operation */
        pub const UnableToCompleteOperation: u32 = 0x02;
/** The device cannot process the command in its current state */
        pub const CommandInvalidInState: u32 = 0x03;
    }
    pub mod OperationalStateEnum {
/** The device is stopped */
        pub const Stopped: u32 = 0x00;
/** The device is operating */
        pub const Running: u32 = 0x01;
/** The device is paused during an operation */
        pub const Paused: u32 = 0x02;
/** The device is in an error state */
        pub const Error: u32 = 0x03;
    }
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod MicrowaveOvenMode {
    pub mod ModeTag {
        pub const Auto: u32 = 0x00;
        pub const Quick: u32 = 0x01;
        pub const Quiet: u32 = 0x02;
        pub const LowNoise: u32 = 0x03;
        pub const LowEnergy: u32 = 0x04;
        pub const Vacation: u32 = 0x05;
        pub const Min: u32 = 0x06;
        pub const Max: u32 = 0x07;
        pub const Night: u32 = 0x08;
        pub const Day: u32 = 0x09;
        pub const Normal: u32 = 0x4000;
        pub const Defrost: u32 = 0x4001;
    }
}
/** This cluster provides a way to access options associated with the operation of
 * a laundry dryer device type. */
pub mod LaundryDryerControls {
    pub mod DrynessLevelEnum {
/** Provides a low dryness level for the selected mode */
        pub const Low: u32 = 0x00;
/** Provides the normal level of dryness for the selected mode */
        pub const Normal: u32 = 0x01;
/** Provides an extra dryness level for the selected mode */
        pub const Extra: u32 = 0x02;
/** Provides the max dryness level for the selected mode */
        pub const Max: u32 = 0x03;
    }
}
/** Supports the ability for clients to request the commissioning of themselves or other nodes onto a fabric which the cluster server can commission onto. */
pub mod CommissionerControl {
    pub mod SupportedDeviceCategoryBitmap {
/** Aggregators which support Fabric Synchronization may be commissioned. */
        pub const FabricSynchronization: u32 = 0x01;
    }
}
/** This cluster implements the upload of Audio and Video streams from the Push AV Stream Transport Cluster using suitable push-based transports. */
pub mod PushAVStreamTransport {
    pub mod CMAFInterfaceEnum {
/** CMAF Interface-1 Mode */
        pub const Interface1: u32 = 0x00;
/** CMAF Interface-2 Mode with DASH Support */
        pub const Interface2DASH: u32 = 0x01;
/** CMAF Interface-2 Mode with HLS Support */
        pub const Interface2HLS: u32 = 0x02;
    }
    pub mod ContainerFormatEnum {
/** CMAF container format */
        pub const CMAF: u32 = 0x00;
    }
    pub mod IngestMethodsEnum {
/** CMAF ingestion format */
        pub const CMAFIngest: u32 = 0x00;
    }
    pub mod StatusCodeEnum {
/** The specified TLSEndpointID cannot be found. */
        pub const InvalidTLSEndpoint: u32 = 0x02;
/** The specified VideoStreamID or AudioStreamID cannot be found. */
        pub const InvalidStream: u32 = 0x03;
/** The specified URL is invalid. */
        pub const InvalidURL: u32 = 0x04;
/** A specified ZoneID was invalid. */
        pub const InvalidZone: u32 = 0x05;
/** The specified combination of Ingestion method and Container format is not supported. */
        pub const InvalidCombination: u32 = 0x06;
/** The trigger type is invalid for this command. */
        pub const InvalidTriggerType: u32 = 0x07;
/** The Stream Transport Status is invalid for this command. */
        pub const InvalidTransportStatus: u32 = 0x08;
/** The requested Container options are not supported with the streams indicated. */
        pub const InvalidOptions: u32 = 0x09;
/** The requested StreamUsage is not allowed. */
        pub const InvalidStreamUsage: u32 = 0x0A;
/** Time sync has not occurred yet. */
        pub const InvalidTime: u32 = 0x0B;
/** The requested pre roll length is not compatible with the streams key frame interval. */
        pub const InvalidPreRollLength: u32 = 0x0C;
/** The requested Streams info contained duplicate entries. */
        pub const DuplicateStreamValues: u32 = 0x0D;
    }
    pub mod TransportStatusEnum {
/** Push Transport can transport AV Streams */
        pub const Active: u32 = 0x00;
/** Push Transport cannot transport AV Streams */
        pub const Inactive: u32 = 0x01;
    }
    pub mod TransportTriggerTypeEnum {
/** Triggered only via a command invocation */
        pub const Command: u32 = 0x00;
/** Triggered via motion detection or command */
        pub const Motion: u32 = 0x01;
/** Triggered always when transport status is Active */
        pub const Continuous: u32 = 0x02;
    }
    pub mod TriggerActivationReasonEnum {
/** Trigger has been activated by user action */
        pub const UserInitiated: u32 = 0x00;
/** Trigger has been activated by automation */
        pub const Automation: u32 = 0x01;
/** Trigger has been activated for emergency reasons */
        pub const Emergency: u32 = 0x02;
/** Trigger has been activated by a doorbell press */
        pub const DoorbellPressed: u32 = 0x03;
    }
}
/** Nodes should be expected to be deployed to any and all regions of the world. These global regions
 * may have differing preferences for how dates and times are conveyed. As such, Nodes that visually
 * or audibly convey time information need a mechanism by which they can be configured to use a
 * user’s preferred format. */
pub mod TimeFormatLocalization {
    pub mod CalendarTypeEnum {
/** Dates conveyed using the Buddhist calendar */
        pub const Buddhist: u32 = 0x00;
/** Dates conveyed using the Chinese calendar */
        pub const Chinese: u32 = 0x01;
/** Dates conveyed using the Coptic calendar */
        pub const Coptic: u32 = 0x02;
/** Dates conveyed using the Ethiopian calendar */
        pub const Ethiopian: u32 = 0x03;
/** Dates conveyed using the Gregorian calendar */
        pub const Gregorian: u32 = 0x04;
/** Dates conveyed using the Hebrew calendar */
        pub const Hebrew: u32 = 0x05;
/** Dates conveyed using the Indian calendar */
        pub const Indian: u32 = 0x06;
/** Dates conveyed using the Islamic calendar */
        pub const Islamic: u32 = 0x07;
/** Dates conveyed using the Japanese calendar */
        pub const Japanese: u32 = 0x08;
/** Dates conveyed using the Korean calendar */
        pub const Korean: u32 = 0x09;
/** Dates conveyed using the Persian calendar */
        pub const Persian: u32 = 0x0A;
/** Dates conveyed using the Taiwanese calendar */
        pub const Taiwanese: u32 = 0x0B;
/** calendar implied from active locale */
        pub const UseActiveLocale: u32 = 0xFF;
    }
    pub mod HourFormatEnum {
/** Time conveyed with a 12-hour clock */
        pub const _12hr: u32 = 0x00;
/** Time conveyed with a 24-hour clock */
        pub const _24hr: u32 = 0x01;
/** Use active locale clock */
        pub const UseActiveLocale: u32 = 0xFF;
    }
}
/** This cluster provides an interface for controlling the Output on a media device such as a TV. */
pub mod AudioOutput {
    pub mod OutputTypeEnum {
/** HDMI */
        pub const HDMI: u32 = 0x00;
        pub const BT: u32 = 0x01;
        pub const Optical: u32 = 0x02;
        pub const Headphone: u32 = 0x03;
        pub const Internal: u32 = 0x04;
        pub const Other: u32 = 0x05;
    }
}
/** Attributes and commands for switching devices between 'On' and 'Off' states. */
pub mod OnOff {
    pub mod DelayedAllOffEffectVariantEnum {
/** Fade to off in 0.8 seconds */
        pub const DelayedOffFastFade: u32 = 0x00;
/** No fade */
        pub const NoFade: u32 = 0x01;
/** 50% dim down in 0.8 seconds then fade to off in 12 seconds */
        pub const DelayedOffSlowFade: u32 = 0x02;
    }
    pub mod DyingLightEffectVariantEnum {
/** 20% dim up in 0.5s then fade to off in 1 second */
        pub const DyingLightFadeOff: u32 = 0x00;
    }
    pub mod EffectIdentifierEnum {
/** Delayed All Off */
        pub const DelayedAllOff: u32 = 0x00;
/** Dying Light */
        pub const DyingLight: u32 = 0x01;
    }
    pub mod StartUpOnOffEnum {
/** Set the OnOff attribute to FALSE */
        pub const Off: u32 = 0x00;
/** Set the OnOff attribute to TRUE */
        pub const On: u32 = 0x01;
/** If the previous value of the OnOff attribute is equal to FALSE, set the OnOff attribute to TRUE. If the previous value of the OnOff attribute is equal to TRUE, set the OnOff attribute to FALSE (toggle). */
        pub const Toggle: u32 = 0x02;
    }
    pub mod OnOffControlBitmap {
/** Indicates a command is only accepted when in On state. */
        pub const AcceptOnlyWhenOn: u32 = 0x01;
    }
}
/** Attributes and commands for controlling the color properties of a color-capable light. */
pub mod ColorControl {
    pub mod ColorLoopActionEnum {
/** De-activate the color loop. */
        pub const Deactivate: u32 = 0x00;
/** Activate the color loop from the value in the ColorLoopStartEnhancedHue field. */
        pub const ActivateFromColorLoopStartEnhancedHue: u32 = 0x01;
/** Activate the color loop from the value of the EnhancedCurrentHue attribute. */
        pub const ActivateFromEnhancedCurrentHue: u32 = 0x02;
    }
    pub mod ColorLoopDirectionEnum {
/** Decrement the hue in the color loop. */
        pub const Decrement: u32 = 0x00;
/** Increment the hue in the color loop. */
        pub const Increment: u32 = 0x01;
    }
    pub mod ColorModeEnum {
/** The current hue and saturation attributes determine the color. */
        pub const CurrentHueAndCurrentSaturation: u32 = 0x00;
/** The current X and Y attributes determine the color. */
        pub const CurrentXAndCurrentY: u32 = 0x01;
/** The color temperature attribute determines the color. */
        pub const ColorTemperatureMireds: u32 = 0x02;
    }
    pub mod DirectionEnum {
/** Shortest distance */
        pub const Shortest: u32 = 0x00;
/** Longest distance */
        pub const Longest: u32 = 0x01;
/** Up */
        pub const Up: u32 = 0x02;
/** Down */
        pub const Down: u32 = 0x03;
    }
    pub mod DriftCompensationEnum {
/** There is no compensation. */
        pub const None: u32 = 0x00;
/** The compensation is based on other or unknown mechanism. */
        pub const OtherOrUnknown: u32 = 0x01;
/** The compensation is based on temperature monitoring. */
        pub const TemperatureMonitoring: u32 = 0x02;
/** The compensation is based on optical luminance monitoring and feedback. */
        pub const OpticalLuminanceMonitoringAndFeedback: u32 = 0x03;
/** The compensation is based on optical color monitoring and feedback. */
        pub const OpticalColorMonitoringAndFeedback: u32 = 0x04;
    }
    pub mod EnhancedColorModeEnum {
/** The current hue and saturation attributes determine the color. */
        pub const CurrentHueAndCurrentSaturation: u32 = 0x00;
/** The current X and Y attributes determine the color. */
        pub const CurrentXAndCurrentY: u32 = 0x01;
/** The color temperature attribute determines the color. */
        pub const ColorTemperatureMireds: u32 = 0x02;
/** The enhanced current hue and saturation attributes determine the color. */
        pub const EnhancedCurrentHueAndCurrentSaturation: u32 = 0x03;
    }
    pub mod MoveModeEnum {
/** Stop the movement */
        pub const Stop: u32 = 0x00;
/** Move in an upwards direction */
        pub const Up: u32 = 0x01;
/** Move in a downwards direction */
        pub const Down: u32 = 0x03;
    }
    pub mod StepModeEnum {
/** Step in an upwards direction */
        pub const Up: u32 = 0x01;
/** Step in a downwards direction */
        pub const Down: u32 = 0x03;
    }
    pub mod ColorCapabilitiesBitmap {
/** Supports color specification via hue/saturation. */
        pub const HueSaturation: u32 = 0x01;
/** Enhanced hue is supported. */
        pub const EnhancedHue: u32 = 0x02;
/** Color loop is supported. */
        pub const ColorLoop: u32 = 0x04;
/** Supports color specification via XY. */
        pub const XY: u32 = 0x08;
/** Supports color specification via color temperature. */
        pub const ColorTemperature: u32 = 0x10;
    }
    pub mod OptionsBitmap {
/** Dependency on On/Off cluster */
        pub const ExecuteIfOff: u32 = 0x01;
    }
    pub mod UpdateFlagsBitmap {
/** Device adheres to the associated action field. */
        pub const UpdateAction: u32 = 0x01;
/** Device updates the associated direction attribute. */
        pub const UpdateDirection: u32 = 0x02;
/** Device updates the associated time attribute. */
        pub const UpdateTime: u32 = 0x04;
/** Device updates the associated start hue attribute. */
        pub const UpdateStartHue: u32 = 0x08;
    }
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod PM10ConcentrationMeasurement {
    pub mod LevelValueEnum {
/** The level is Unknown */
        pub const Unknown: u32 = 0x00;
/** The level is considered Low */
        pub const Low: u32 = 0x01;
/** The level is considered Medium */
        pub const Medium: u32 = 0x02;
/** The level is considered High */
        pub const High: u32 = 0x03;
/** The level is considered Critical */
        pub const Critical: u32 = 0x04;
    }
    pub mod MeasurementMediumEnum {
/** The measurement is being made in Air */
        pub const Air: u32 = 0x00;
/** The measurement is being made in Water */
        pub const Water: u32 = 0x01;
/** The measurement is being made in Soil */
        pub const Soil: u32 = 0x02;
    }
    pub mod MeasurementUnitEnum {
/** Parts per Million (10) */
        pub const PPM: u32 = 0x00;
/** Parts per Billion (10) */
        pub const PPB: u32 = 0x01;
/** Parts per Trillion (10) */
        pub const PPT: u32 = 0x02;
/** Milligram per m */
        pub const MGM3: u32 = 0x03;
/** Microgram per m */
        pub const UGM3: u32 = 0x04;
/** Nanogram per m */
        pub const NGM3: u32 = 0x05;
/** Particles per m */
        pub const PM3: u32 = 0x06;
/** Becquerel per m */
        pub const BQM3: u32 = 0x07;
    }
}
/** Provides an interface for providing OTA software updates */
pub mod OTASoftwareUpdateProvider {
    pub mod ApplyUpdateActionEnum {
/** Apply the update. */
        pub const Proceed: u32 = 0x00;
/** Wait at least the given delay time. */
        pub const AwaitNextAction: u32 = 0x01;
/** The OTA Provider is conveying a desire to rescind a previously provided Software Image. */
        pub const Discontinue: u32 = 0x02;
    }
    pub mod DownloadProtocolEnum {
/** Indicates support for synchronous BDX. */
        pub const BDXSynchronous: u32 = 0x00;
/** Indicates support for asynchronous BDX. */
        pub const BDXAsynchronous: u32 = 0x01;
/** Indicates support for HTTPS. */
        pub const HTTPS: u32 = 0x02;
/** Indicates support for vendor specific protocol. */
        pub const VendorSpecific: u32 = 0x03;
    }
    pub mod StatusEnum {
/** Indicates that the OTA Provider has an update available. */
        pub const UpdateAvailable: u32 = 0x00;
/** Indicates OTA Provider may have an update, but it is not ready yet. */
        pub const Busy: u32 = 0x01;
/** Indicates that there is definitely no update currently available from the OTA Provider. */
        pub const NotAvailable: u32 = 0x02;
/** Indicates that the requested download protocol is not supported by the OTA Provider. */
        pub const DownloadProtocolNotSupported: u32 = 0x03;
    }
}
/** Attributes and commands for configuring the Dishwasher alarm. */
pub mod DishwasherAlarm {
    pub mod AlarmBitmap {
/** Water inflow is abnormal */
        pub const InflowError: u32 = 0x01;
/** Water draining is abnormal */
        pub const DrainError: u32 = 0x02;
/** Door or door lock is abnormal */
        pub const DoorError: u32 = 0x04;
/** Unable to reach normal temperature */
        pub const TempTooLow: u32 = 0x08;
/** Temperature is too high */
        pub const TempTooHigh: u32 = 0x10;
/** Water level is abnormal */
        pub const WaterLevelError: u32 = 0x20;
    }
}
/** This cluster provides an interface for observing and managing the state of smoke and CO alarms. */
pub mod SmokeCOAlarm {
    pub mod AlarmStateEnum {
/** Nominal state, the device is not alarming */
        pub const Normal: u32 = 0x00;
/** Warning state */
        pub const Warning: u32 = 0x01;
/** Critical state */
        pub const Critical: u32 = 0x02;
    }
    pub mod ContaminationStateEnum {
/** Nominal state, the sensor is not contaminated */
        pub const Normal: u32 = 0x00;
/** Low contamination */
        pub const Low: u32 = 0x01;
/** Warning state */
        pub const Warning: u32 = 0x02;
/** Critical state, will cause nuisance alarms */
        pub const Critical: u32 = 0x03;
    }
    pub mod EndOfServiceEnum {
/** Device has not expired */
        pub const Normal: u32 = 0x00;
/** Device has reached its end of service */
        pub const Expired: u32 = 0x01;
    }
    pub mod ExpressedStateEnum {
/** Nominal state, the device is not alarming */
        pub const Normal: u32 = 0x00;
/** Smoke Alarm state */
        pub const SmokeAlarm: u32 = 0x01;
/** CO Alarm state */
        pub const COAlarm: u32 = 0x02;
/** Battery Alert State */
        pub const BatteryAlert: u32 = 0x03;
/** Test in Progress */
        pub const Testing: u32 = 0x04;
/** Hardware Fault Alert State */
        pub const HardwareFault: u32 = 0x05;
/** End of Service Alert State */
        pub const EndOfService: u32 = 0x06;
/** Interconnected Smoke Alarm State */
        pub const InterconnectSmoke: u32 = 0x07;
/** Interconnected CO Alarm State */
        pub const InterconnectCO: u32 = 0x08;
    }
    pub mod MuteStateEnum {
/** Not Muted */
        pub const NotMuted: u32 = 0x00;
/** Muted */
        pub const Muted: u32 = 0x01;
    }
    pub mod SensitivityEnum {
/** High sensitivity */
        pub const High: u32 = 0x00;
/** Standard Sensitivity */
        pub const Standard: u32 = 0x01;
/** Low sensitivity */
        pub const Low: u32 = 0x02;
    }
}
/** This cluster provides an interface into controls associated with the operation of a device that provides pan, tilt, and zoom functions, either mechanically, or against a digital image. */
pub mod CameraAVSettingsUserLevelManagement {
    pub mod PhysicalMovementEnum {
/** The camera is idle. */
        pub const Idle: u32 = 0x00;
/** The camera is moving to a new value of Pan, Tilt, and/or Zoom. */
        pub const Moving: u32 = 0x01;
    }
}
/** This cluster provides an interface for passing messages to be presented by a device. */
pub mod Messages {
    pub mod FutureMessagePreferenceEnum {
/** Similar messages are allowed */
        pub const Allowed: u32 = 0x00;
/** Similar messages should be sent more often */
        pub const Increased: u32 = 0x01;
/** Similar messages should be sent less often */
        pub const Reduced: u32 = 0x02;
/** Similar messages should not be sent */
        pub const Disallowed: u32 = 0x03;
/** No further messages should be sent */
        pub const Banned: u32 = 0x04;
    }
    pub mod MessagePriorityEnum {
/** Message to be transferred with a low level of importance */
        pub const Low: u32 = 0x00;
/** Message to be transferred with a medium level of importance */
        pub const Medium: u32 = 0x01;
/** Message to be transferred with a high level of importance */
        pub const High: u32 = 0x02;
/** Message to be transferred with a critical level of importance */
        pub const Critical: u32 = 0x03;
    }
    pub mod MessageControlBitmap {
/** Message requires confirmation from user */
        pub const ConfirmationRequired: u32 = 0x01;
/** Message requires response from user */
        pub const ResponseRequired: u32 = 0x02;
/** Message supports reply message from user */
        pub const ReplyMessage: u32 = 0x04;
/** Message has already been confirmed */
        pub const MessageConfirmed: u32 = 0x08;
/** Message required PIN/password protection */
        pub const MessageProtected: u32 = 0x10;
    }
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod CarbonDioxideConcentrationMeasurement {
    pub mod LevelValueEnum {
/** The level is Unknown */
        pub const Unknown: u32 = 0x00;
/** The level is considered Low */
        pub const Low: u32 = 0x01;
/** The level is considered Medium */
        pub const Medium: u32 = 0x02;
/** The level is considered High */
        pub const High: u32 = 0x03;
/** The level is considered Critical */
        pub const Critical: u32 = 0x04;
    }
    pub mod MeasurementMediumEnum {
/** The measurement is being made in Air */
        pub const Air: u32 = 0x00;
/** The measurement is being made in Water */
        pub const Water: u32 = 0x01;
/** The measurement is being made in Soil */
        pub const Soil: u32 = 0x02;
    }
    pub mod MeasurementUnitEnum {
/** Parts per Million (10) */
        pub const PPM: u32 = 0x00;
/** Parts per Billion (10) */
        pub const PPB: u32 = 0x01;
/** Parts per Trillion (10) */
        pub const PPT: u32 = 0x02;
/** Milligram per m */
        pub const MGM3: u32 = 0x03;
/** Microgram per m */
        pub const UGM3: u32 = 0x04;
/** Nanogram per m */
        pub const NGM3: u32 = 0x05;
/** Particles per m */
        pub const PM3: u32 = 0x06;
/** Becquerel per m */
        pub const BQM3: u32 = 0x07;
    }
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod RVCCleanMode {
    pub mod ModeTag {
        pub const Auto: u32 = 0x00;
        pub const Quick: u32 = 0x01;
        pub const Quiet: u32 = 0x02;
        pub const LowNoise: u32 = 0x03;
        pub const LowEnergy: u32 = 0x04;
        pub const Vacation: u32 = 0x05;
        pub const Min: u32 = 0x06;
        pub const Max: u32 = 0x07;
        pub const Night: u32 = 0x08;
        pub const Day: u32 = 0x09;
        pub const DeepClean: u32 = 0x4000;
        pub const Vacuum: u32 = 0x4001;
        pub const Mop: u32 = 0x4002;
        pub const VacuumthenMop: u32 = 0x4003;
    }
    pub mod StatusCodeEnum {
        pub const CleaningInProgress: u32 = 0x40;
    }
}
/** This cluster provides a mechanism for querying data about electrical power as measured by the server. */
pub mod ElectricalPowerMeasurement {
    pub mod MeasurementTypeEnum {
        pub const Unspecified: u32 = 0x00;
/** Voltage in millivolts (mV) */
        pub const Voltage: u32 = 0x01;
/** Active current in milliamps (mA) */
        pub const ActiveCurrent: u32 = 0x02;
/** Reactive current in milliamps (mA) */
        pub const ReactiveCurrent: u32 = 0x03;
/** Apparent current in milliamps (mA) */
        pub const ApparentCurrent: u32 = 0x04;
/** Active power in milliwatts (mW) */
        pub const ActivePower: u32 = 0x05;
/** Reactive power in millivolt-amps reactive (mVAR) */
        pub const ReactivePower: u32 = 0x06;
/** Apparent power in millivolt-amps (mVA) */
        pub const ApparentPower: u32 = 0x07;
/** Root mean squared voltage in millivolts (mV) */
        pub const RMSVoltage: u32 = 0x08;
/** Root mean squared current in milliamps (mA) */
        pub const RMSCurrent: u32 = 0x09;
/** Root mean squared power in milliwatts (mW) */
        pub const RMSPower: u32 = 0x0A;
/** AC frequency in millihertz (mHz) */
        pub const Frequency: u32 = 0x0B;
/** Power Factor ratio in +/- 1/100ths of a percent. */
        pub const PowerFactor: u32 = 0x0C;
/** AC neutral current in milliamps (mA) */
        pub const NeutralCurrent: u32 = 0x0D;
/** Electrical energy in milliwatt-hours (mWh) */
        pub const ElectricalEnergy: u32 = 0x0E;
/** Reactive power in millivolt-amp-hours reactive (mVARh) */
        pub const ReactiveEnergy: u32 = 0x0F;
/** Apparent power in millivolt-amp-hours (mVAh) */
        pub const ApparentEnergy: u32 = 0x10;
    }
    pub mod PowerModeEnum {
        pub const Unknown: u32 = 0x00;
/** Direct current */
        pub const DC: u32 = 0x01;
/** Alternating current, either single-phase or polyphase */
        pub const AC: u32 = 0x02;
    }
}
/** Nodes should be expected to be deployed to any and all regions of the world. These global regions
 * may have differing preferences for the units in which values are conveyed in communication to a
 * user. As such, Nodes that visually or audibly convey measurable values to the user need a
 * mechanism by which they can be configured to use a user’s preferred unit. */
pub mod UnitLocalization {
    pub mod TempUnitEnum {
/** Temperature conveyed in Fahrenheit */
        pub const Fahrenheit: u32 = 0x00;
/** Temperature conveyed in Celsius */
        pub const Celsius: u32 = 0x01;
/** Temperature conveyed in Kelvin */
        pub const Kelvin: u32 = 0x02;
    }
}
/** This cluster is used to describe the configuration and capabilities of a physical power source that provides power to the Node. */
pub mod PowerSource {
    pub mod BatApprovedChemistryEnum {
/** Cell chemistry is unspecified or unknown */
        pub const Unspecified: u32 = 0x00;
/** Cell chemistry is alkaline */
        pub const Alkaline: u32 = 0x01;
/** Cell chemistry is lithium carbon fluoride */
        pub const LithiumCarbonFluoride: u32 = 0x02;
/** Cell chemistry is lithium chromium oxide */
        pub const LithiumChromiumOxide: u32 = 0x03;
/** Cell chemistry is lithium copper oxide */
        pub const LithiumCopperOxide: u32 = 0x04;
/** Cell chemistry is lithium iron disulfide */
        pub const LithiumIronDisulfide: u32 = 0x05;
/** Cell chemistry is lithium manganese dioxide */
        pub const LithiumManganeseDioxide: u32 = 0x06;
/** Cell chemistry is lithium thionyl chloride */
        pub const LithiumThionylChloride: u32 = 0x07;
/** Cell chemistry is magnesium */
        pub const Magnesium: u32 = 0x08;
/** Cell chemistry is mercury oxide */
        pub const MercuryOxide: u32 = 0x09;
/** Cell chemistry is nickel oxyhydride */
        pub const NickelOxyhydride: u32 = 0x0A;
/** Cell chemistry is silver oxide */
        pub const SilverOxide: u32 = 0x0B;
/** Cell chemistry is zinc air */
        pub const ZincAir: u32 = 0x0C;
/** Cell chemistry is zinc carbon */
        pub const ZincCarbon: u32 = 0x0D;
/** Cell chemistry is zinc chloride */
        pub const ZincChloride: u32 = 0x0E;
/** Cell chemistry is zinc manganese dioxide */
        pub const ZincManganeseDioxide: u32 = 0x0F;
/** Cell chemistry is lead acid */
        pub const LeadAcid: u32 = 0x10;
/** Cell chemistry is lithium cobalt oxide */
        pub const LithiumCobaltOxide: u32 = 0x11;
/** Cell chemistry is lithium ion */
        pub const LithiumIon: u32 = 0x12;
/** Cell chemistry is lithium ion polymer */
        pub const LithiumIonPolymer: u32 = 0x13;
/** Cell chemistry is lithium iron phosphate */
        pub const LithiumIronPhosphate: u32 = 0x14;
/** Cell chemistry is lithium sulfur */
        pub const LithiumSulfur: u32 = 0x15;
/** Cell chemistry is lithium titanate */
        pub const LithiumTitanate: u32 = 0x16;
/** Cell chemistry is nickel cadmium */
        pub const NickelCadmium: u32 = 0x17;
/** Cell chemistry is nickel hydrogen */
        pub const NickelHydrogen: u32 = 0x18;
/** Cell chemistry is nickel iron */
        pub const NickelIron: u32 = 0x19;
/** Cell chemistry is nickel metal hydride */
        pub const NickelMetalHydride: u32 = 0x1A;
/** Cell chemistry is nickel zinc */
        pub const NickelZinc: u32 = 0x1B;
/** Cell chemistry is silver zinc */
        pub const SilverZinc: u32 = 0x1C;
/** Cell chemistry is sodium ion */
        pub const SodiumIon: u32 = 0x1D;
/** Cell chemistry is sodium sulfur */
        pub const SodiumSulfur: u32 = 0x1E;
/** Cell chemistry is zinc bromide */
        pub const ZincBromide: u32 = 0x1F;
/** Cell chemistry is zinc cerium */
        pub const ZincCerium: u32 = 0x20;
    }
    pub mod BatChargeFaultEnum {
/** The Node detects an unspecified fault on this battery source. */
        pub const Unspecified: u32 = 0x00;
/** The Node detects the ambient temperature is above the nominal range for this battery source. */
        pub const AmbientTooHot: u32 = 0x01;
/** The Node detects the ambient temperature is below the nominal range for this battery source. */
        pub const AmbientTooCold: u32 = 0x02;
/** The Node detects the temperature of this battery source is above the nominal range. */
        pub const BatteryTooHot: u32 = 0x03;
/** The Node detects the temperature of this battery source is below the nominal range. */
        pub const BatteryTooCold: u32 = 0x04;
/** The Node detects this battery source is not present. */
        pub const BatteryAbsent: u32 = 0x05;
/** The Node detects this battery source is over voltage. */
        pub const BatteryOverVoltage: u32 = 0x06;
/** The Node detects this battery source is under voltage. */
        pub const BatteryUnderVoltage: u32 = 0x07;
/** The Node detects the charger for this battery source is over voltage. */
        pub const ChargerOverVoltage: u32 = 0x08;
/** The Node detects the charger for this battery source is under voltage. */
        pub const ChargerUnderVoltage: u32 = 0x09;
/** The Node detects a charging safety timeout for this battery source. */
        pub const SafetyTimeout: u32 = 0x0A;
    }
    pub mod BatChargeLevelEnum {
/** Charge level is nominal */
        pub const OK: u32 = 0x00;
/** Charge level is low, intervention may soon be required. */
        pub const Warning: u32 = 0x01;
/** Charge level is critical, immediate intervention is required */
        pub const Critical: u32 = 0x02;
    }
    pub mod BatChargeStateEnum {
/** Unable to determine the charging state */
        pub const Unknown: u32 = 0x00;
/** The battery is charging */
        pub const IsCharging: u32 = 0x01;
/** The battery is at full charge */
        pub const IsAtFullCharge: u32 = 0x02;
/** The battery is not charging */
        pub const IsNotCharging: u32 = 0x03;
    }
    pub mod BatCommonDesignationEnum {
/** Common type is unknown or unspecified */
        pub const Unspecified: u32 = 0x00;
/** Common type is as specified */
        pub const AAA: u32 = 0x01;
/** Common type is as specified */
        pub const AA: u32 = 0x02;
/** Common type is as specified */
        pub const C: u32 = 0x03;
/** Common type is as specified */
        pub const D: u32 = 0x04;
/** Common type is as specified */
        pub const _4v5: u32 = 0x05;
/** Common type is as specified */
        pub const _6v0: u32 = 0x06;
/** Common type is as specified */
        pub const _9v0: u32 = 0x07;
/** Common type is as specified */
        pub const _1_2AA: u32 = 0x08;
/** Common type is as specified */
        pub const AAAA: u32 = 0x09;
/** Common type is as specified */
        pub const A: u32 = 0x0A;
/** Common type is as specified */
        pub const B: u32 = 0x0B;
/** Common type is as specified */
        pub const F: u32 = 0x0C;
/** Common type is as specified */
        pub const N: u32 = 0x0D;
/** Common type is as specified */
        pub const No6: u32 = 0x0E;
/** Common type is as specified */
        pub const SubC: u32 = 0x0F;
/** Common type is as specified */
        pub const A23: u32 = 0x10;
/** Common type is as specified */
        pub const A27: u32 = 0x11;
/** Common type is as specified */
        pub const BA5800: u32 = 0x12;
/** Common type is as specified */
        pub const Duplex: u32 = 0x13;
/** Common type is as specified */
        pub const _4SR44: u32 = 0x14;
/** Common type is as specified */
        pub const _523: u32 = 0x15;
/** Common type is as specified */
        pub const _531: u32 = 0x16;
/** Common type is as specified */
        pub const _15v0: u32 = 0x17;
/** Common type is as specified */
        pub const _22v5: u32 = 0x18;
/** Common type is as specified */
        pub const _30v0: u32 = 0x19;
/** Common type is as specified */
        pub const _45v0: u32 = 0x1A;
/** Common type is as specified */
        pub const _67v5: u32 = 0x1B;
/** Common type is as specified */
        pub const J: u32 = 0x1C;
/** Common type is as specified */
        pub const CR123A: u32 = 0x1D;
/** Common type is as specified */
        pub const CR2: u32 = 0x1E;
/** Common type is as specified */
        pub const _2CR5: u32 = 0x1F;
/** Common type is as specified */
        pub const CR_P2: u32 = 0x20;
/** Common type is as specified */
        pub const CR_V3: u32 = 0x21;
/** Common type is as specified */
        pub const SR41: u32 = 0x22;
/** Common type is as specified */
        pub const SR43: u32 = 0x23;
/** Common type is as specified */
        pub const SR44: u32 = 0x24;
/** Common type is as specified */
        pub const SR45: u32 = 0x25;
/** Common type is as specified */
        pub const SR48: u32 = 0x26;
/** Common type is as specified */
        pub const SR54: u32 = 0x27;
/** Common type is as specified */
        pub const SR55: u32 = 0x28;
/** Common type is as specified */
        pub const SR57: u32 = 0x29;
/** Common type is as specified */
        pub const SR58: u32 = 0x2A;
/** Common type is as specified */
        pub const SR59: u32 = 0x2B;
/** Common type is as specified */
        pub const SR60: u32 = 0x2C;
/** Common type is as specified */
        pub const SR63: u32 = 0x2D;
/** Common type is as specified */
        pub const SR64: u32 = 0x2E;
/** Common type is as specified */
        pub const SR65: u32 = 0x2F;
/** Common type is as specified */
        pub const SR66: u32 = 0x30;
/** Common type is as specified */
        pub const SR67: u32 = 0x31;
/** Common type is as specified */
        pub const SR68: u32 = 0x32;
/** Common type is as specified */
        pub const SR69: u32 = 0x33;
/** Common type is as specified */
        pub const SR516: u32 = 0x34;
/** Common type is as specified */
        pub const SR731: u32 = 0x35;
/** Common type is as specified */
        pub const SR712: u32 = 0x36;
/** Common type is as specified */
        pub const LR932: u32 = 0x37;
/** Common type is as specified */
        pub const A5: u32 = 0x38;
/** Common type is as specified */
        pub const A10: u32 = 0x39;
/** Common type is as specified */
        pub const A13: u32 = 0x3A;
/** Common type is as specified */
        pub const A312: u32 = 0x3B;
/** Common type is as specified */
        pub const A675: u32 = 0x3C;
/** Common type is as specified */
        pub const AC41E: u32 = 0x3D;
/** Common type is as specified */
        pub const _10180: u32 = 0x3E;
/** Common type is as specified */
        pub const _10280: u32 = 0x3F;
/** Common type is as specified */
        pub const _10440: u32 = 0x40;
/** Common type is as specified */
        pub const _14250: u32 = 0x41;
/** Common type is as specified */
        pub const _14430: u32 = 0x42;
/** Common type is as specified */
        pub const _14500: u32 = 0x43;
/** Common type is as specified */
        pub const _14650: u32 = 0x44;
/** Common type is as specified */
        pub const _15270: u32 = 0x45;
/** Common type is as specified */
        pub const _16340: u32 = 0x46;
/** Common type is as specified */
        pub const RCR123A: u32 = 0x47;
/** Common type is as specified */
        pub const _17500: u32 = 0x48;
/** Common type is as specified */
        pub const _17670: u32 = 0x49;
/** Common type is as specified */
        pub const _18350: u32 = 0x4A;
/** Common type is as specified */
        pub const _18500: u32 = 0x4B;
/** Common type is as specified */
        pub const _18650: u32 = 0x4C;
/** Common type is as specified */
        pub const _19670: u32 = 0x4D;
/** Common type is as specified */
        pub const _25500: u32 = 0x4E;
/** Common type is as specified */
        pub const _26650: u32 = 0x4F;
/** Common type is as specified */
        pub const _32600: u32 = 0x50;
    }
    pub mod BatFaultEnum {
/** The Node detects an unspecified fault on this battery power source. */
        pub const Unspecified: u32 = 0x00;
/** The Node detects the temperature of this battery power source is above ideal operating conditions. */
        pub const OverTemp: u32 = 0x01;
/** The Node detects the temperature of this battery power source is below ideal operating conditions. */
        pub const UnderTemp: u32 = 0x02;
    }
    pub mod BatReplaceabilityEnum {
/** The replaceability is unspecified or unknown. */
        pub const Unspecified: u32 = 0x00;
/** The battery is not replaceable. */
        pub const NotReplaceable: u32 = 0x01;
/** The battery is replaceable by the user or customer. */
        pub const UserReplaceable: u32 = 0x02;
/** The battery is replaceable by an authorized factory technician. */
        pub const FactoryReplaceable: u32 = 0x03;
    }
    pub mod PowerSourceStatusEnum {
/** Indicate the source status is not specified */
        pub const Unspecified: u32 = 0x00;
/** Indicate the source is available and currently supplying power */
        pub const Active: u32 = 0x01;
/** Indicate the source is available, but is not currently supplying power */
        pub const Standby: u32 = 0x02;
/** Indicate the source is not currently available to supply power */
        pub const Unavailable: u32 = 0x03;
    }
    pub mod WiredCurrentTypeEnum {
/** Indicates AC current */
        pub const AC: u32 = 0x00;
/** Indicates DC current */
        pub const DC: u32 = 0x01;
    }
    pub mod WiredFaultEnum {
/** The Node detects an unspecified fault on this wired power source. */
        pub const Unspecified: u32 = 0x00;
/** The Node detects the supplied voltage is above maximum supported value for this wired power source. */
        pub const OverVoltage: u32 = 0x01;
/** The Node detects the supplied voltage is below maximum supported value for this wired power source. */
        pub const UnderVoltage: u32 = 0x02;
    }
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod OzoneConcentrationMeasurement {
    pub mod LevelValueEnum {
/** The level is Unknown */
        pub const Unknown: u32 = 0x00;
/** The level is considered Low */
        pub const Low: u32 = 0x01;
/** The level is considered Medium */
        pub const Medium: u32 = 0x02;
/** The level is considered High */
        pub const High: u32 = 0x03;
/** The level is considered Critical */
        pub const Critical: u32 = 0x04;
    }
    pub mod MeasurementMediumEnum {
/** The measurement is being made in Air */
        pub const Air: u32 = 0x00;
/** The measurement is being made in Water */
        pub const Water: u32 = 0x01;
/** The measurement is being made in Soil */
        pub const Soil: u32 = 0x02;
    }
    pub mod MeasurementUnitEnum {
/** Parts per Million (10) */
        pub const PPM: u32 = 0x00;
/** Parts per Billion (10) */
        pub const PPB: u32 = 0x01;
/** Parts per Trillion (10) */
        pub const PPT: u32 = 0x02;
/** Milligram per m */
        pub const MGM3: u32 = 0x03;
/** Microgram per m */
        pub const UGM3: u32 = 0x04;
/** Nanogram per m */
        pub const NGM3: u32 = 0x05;
/** Particles per m */
        pub const PM3: u32 = 0x06;
/** Becquerel per m */
        pub const BQM3: u32 = 0x07;
    }
}
/** Attributes and commands for configuring the measurement of illuminance, and reporting illuminance measurements. */
pub mod IlluminanceMeasurement {
    pub mod LightSensorTypeEnum {
/** Indicates photodiode sensor type */
        pub const Photodiode: u32 = 0x00;
/** Indicates CMOS sensor type */
        pub const CMOS: u32 = 0x01;
    }
}
/** The Electrical Grid Conditions Cluster provides the mechanism for communicating electricity grid carbon intensity to devices within the premises in units of Grams of CO2e per kWh. */
pub mod ElectricalGridConditions {
    pub mod ThreeLevelEnum {
/** Low */
        pub const Low: u32 = 0x00;
/** Medium */
        pub const Medium: u32 = 0x01;
/** High */
        pub const High: u32 = 0x02;
    }
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod NitrogenDioxideConcentrationMeasurement {
    pub mod LevelValueEnum {
/** The level is Unknown */
        pub const Unknown: u32 = 0x00;
/** The level is considered Low */
        pub const Low: u32 = 0x01;
/** The level is considered Medium */
        pub const Medium: u32 = 0x02;
/** The level is considered High */
        pub const High: u32 = 0x03;
/** The level is considered Critical */
        pub const Critical: u32 = 0x04;
    }
    pub mod MeasurementMediumEnum {
/** The measurement is being made in Air */
        pub const Air: u32 = 0x00;
/** The measurement is being made in Water */
        pub const Water: u32 = 0x01;
/** The measurement is being made in Soil */
        pub const Soil: u32 = 0x02;
    }
    pub mod MeasurementUnitEnum {
/** Parts per Million (10) */
        pub const PPM: u32 = 0x00;
/** Parts per Billion (10) */
        pub const PPB: u32 = 0x01;
/** Parts per Trillion (10) */
        pub const PPT: u32 = 0x02;
/** Milligram per m */
        pub const MGM3: u32 = 0x03;
/** Microgram per m */
        pub const UGM3: u32 = 0x04;
/** Nanogram per m */
        pub const NGM3: u32 = 0x05;
/** Particles per m */
        pub const PM3: u32 = 0x06;
/** Becquerel per m */
        pub const BQM3: u32 = 0x07;
    }
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod PM1ConcentrationMeasurement {
    pub mod LevelValueEnum {
/** The level is Unknown */
        pub const Unknown: u32 = 0x00;
/** The level is considered Low */
        pub const Low: u32 = 0x01;
/** The level is considered Medium */
        pub const Medium: u32 = 0x02;
/** The level is considered High */
        pub const High: u32 = 0x03;
/** The level is considered Critical */
        pub const Critical: u32 = 0x04;
    }
    pub mod MeasurementMediumEnum {
/** The measurement is being made in Air */
        pub const Air: u32 = 0x00;
/** The measurement is being made in Water */
        pub const Water: u32 = 0x01;
/** The measurement is being made in Soil */
        pub const Soil: u32 = 0x02;
    }
    pub mod MeasurementUnitEnum {
/** Parts per Million (10) */
        pub const PPM: u32 = 0x00;
/** Parts per Billion (10) */
        pub const PPB: u32 = 0x01;
/** Parts per Trillion (10) */
        pub const PPT: u32 = 0x02;
/** Milligram per m */
        pub const MGM3: u32 = 0x03;
/** Microgram per m */
        pub const UGM3: u32 = 0x04;
/** Nanogram per m */
        pub const NGM3: u32 = 0x05;
/** Particles per m */
        pub const PM3: u32 = 0x06;
/** Becquerel per m */
        pub const BQM3: u32 = 0x07;
    }
}
/** This cluster provides attributes and events for determining basic information about Nodes, which supports both
 * Commissioning and operational determination of Node characteristics, such as Vendor ID, Product ID and serial number,
 * which apply to the whole Node. Also allows setting user device information such as location. */
pub mod BasicInformation {
    pub mod ColorEnum {
/** Approximately RGB #000000. */
        pub const Black: u32 = 0x00;
/** Approximately RGB #000080. */
        pub const Navy: u32 = 0x01;
/** Approximately RGB #008000. */
        pub const Green: u32 = 0x02;
/** Approximately RGB #008080. */
        pub const Teal: u32 = 0x03;
/** Approximately RGB #800000. */
        pub const Maroon: u32 = 0x04;
/** Approximately RGB #800080. */
        pub const Purple: u32 = 0x05;
/** Approximately RGB #808000. */
        pub const Olive: u32 = 0x06;
/** Approximately RGB #808080. */
        pub const Gray: u32 = 0x07;
/** Approximately RGB #0000FF. */
        pub const Blue: u32 = 0x08;
/** Approximately RGB #00FF00. */
        pub const Lime: u32 = 0x09;
/** Approximately RGB #00FFFF. */
        pub const Aqua: u32 = 0x0A;
/** Approximately RGB #FF0000. */
        pub const Red: u32 = 0x0B;
/** Approximately RGB #FF00FF. */
        pub const Fuchsia: u32 = 0x0C;
/** Approximately RGB #FFFF00. */
        pub const Yellow: u32 = 0x0D;
/** Approximately RGB #FFFFFF. */
        pub const White: u32 = 0x0E;
/** Typical hardware "Nickel" color. */
        pub const Nickel: u32 = 0x0F;
/** Typical hardware "Chrome" color. */
        pub const Chrome: u32 = 0x10;
/** Typical hardware "Brass" color. */
        pub const Brass: u32 = 0x11;
/** Typical hardware "Copper" color. */
        pub const Copper: u32 = 0x12;
/** Typical hardware "Silver" color. */
        pub const Silver: u32 = 0x13;
/** Typical hardware "Gold" color. */
        pub const Gold: u32 = 0x14;
    }
    pub mod ProductFinishEnum {
/** Product has some other finish not listed below. */
        pub const Other: u32 = 0x00;
/** Product has a matte finish. */
        pub const Matte: u32 = 0x01;
/** Product has a satin finish. */
        pub const Satin: u32 = 0x02;
/** Product has a polished or shiny finish. */
        pub const Polished: u32 = 0x03;
/** Product has a rugged finish. */
        pub const Rugged: u32 = 0x04;
/** Product has a fabric finish. */
        pub const Fabric: u32 = 0x05;
    }
}
/** This cluster provides an interface for controlling Media Playback (PLAY, PAUSE, etc) on a media device such as a TV or Speaker. */
pub mod MediaPlayback {
    pub mod CharacteristicEnum {
/** Textual information meant for display when no other text representation is selected. It is used to clarify dialogue, alternate languages, texted graphics or location/person IDs that are not otherwise covered in the dubbed/localized audio. */
        pub const ForcedSubtitles: u32 = 0x00;
/** Textual or audio media component containing a textual description (intended for audio synthesis) or an audio description describing a visual component */
        pub const DescribesVideo: u32 = 0x01;
/** Simplified or reduced captions as specified in [United States Code Title 47 CFR 79.103(c)(9)]. */
        pub const EasyToRead: u32 = 0x02;
/** A media characteristic that indicates that a track selection option includes frame-based content. */
        pub const FrameBased: u32 = 0x03;
/** Main media component(s) which is/are intended for presentation if no other information is provided */
        pub const MainProgram: u32 = 0x04;
/** A media characteristic that indicates that a track or media selection option contains original content. */
        pub const OriginalContent: u32 = 0x05;
/** A media characteristic that indicates that a track or media selection option contains a language translation and verbal interpretation of spoken dialog. */
        pub const VoiceOverTranslation: u32 = 0x06;
/** Textual media component containing transcriptions of spoken dialog and auditory cues such as sound effects and music for the hearing impaired. */
        pub const Caption: u32 = 0x07;
/** Textual transcriptions of spoken dialog. */
        pub const Subtitle: u32 = 0x08;
/** Textual media component containing transcriptions of spoken dialog and auditory cues such as sound effects and music for the hearing impaired. */
        pub const Alternate: u32 = 0x09;
/** Media content component that is supplementary to a media content component of a different media component type. */
        pub const Supplementary: u32 = 0x0A;
/** Experience that contains a commentary (e.g. director’s commentary) (typically audio) */
        pub const Commentary: u32 = 0x0B;
/** Experience that contains an element that is presented in a different language from the original (e.g. dubbed audio, translated captions) */
        pub const DubbedTranslation: u32 = 0x0C;
/** Textual or audio media component containing a textual description (intended for audio synthesis) or an audio description describing a visual component */
        pub const Description: u32 = 0x0D;
/** Media component containing information intended to be processed by application specific elements. */
        pub const Metadata: u32 = 0x0E;
/** Experience containing an element for improved intelligibility of the dialogue. */
        pub const EnhancedAudioIntelligibility: u32 = 0x0F;
/** Experience that provides information, about a current emergency, that is intended to enable the protection of life, health, safety, and property, and may also include critical details regarding the emergency and how to respond to the emergency. */
        pub const Emergency: u32 = 0x10;
/** Textual representation of a songs’ lyrics, usually in the same language as the associated song as specified in [SMPTE ST 2067-2]. */
        pub const Karaoke: u32 = 0x11;
    }
    pub mod PlaybackStateEnum {
/** Media is currently playing (includes FF and REW) */
        pub const Playing: u32 = 0x00;
/** Media is currently paused */
        pub const Paused: u32 = 0x01;
/** Media is not currently playing */
        pub const NotPlaying: u32 = 0x02;
/** Media is not currently buffering and playback will start when buffer has been filled */
        pub const Buffering: u32 = 0x03;
    }
    pub mod StatusEnum {
/** Succeeded */
        pub const Success: u32 = 0x00;
/** Requested playback command is invalid in the current playback state. */
        pub const InvalidStateForCommand: u32 = 0x01;
/** Requested playback command is not allowed in the current playback state. For example, attempting to fast-forward during a commercial might return NotAllowed. */
        pub const NotAllowed: u32 = 0x02;
/** This endpoint is not active for playback. */
        pub const NotActive: u32 = 0x03;
/** The FastForward or Rewind Command was issued but the media is already playing back at the fastest speed supported by the server in the respective direction. */
        pub const SpeedOutOfRange: u32 = 0x04;
/** The Seek Command was issued with a value of position outside of the allowed seek range of the media. */
        pub const SeekOutOfRange: u32 = 0x05;
    }
}
/** Provides an interface for controlling and adjusting automatic window coverings. */
pub mod WindowCovering {
    pub mod EndProductTypeEnum {
/** Simple Roller Shade */
        pub const RollerShade: u32 = 0x00;
/** Roman Shade */
        pub const RomanShade: u32 = 0x01;
/** Balloon Shade */
        pub const BalloonShade: u32 = 0x02;
/** Woven Wood */
        pub const WovenWood: u32 = 0x03;
/** Pleated Shade */
        pub const PleatedShade: u32 = 0x04;
/** Cellular Shade */
        pub const CellularShade: u32 = 0x05;
/** Layered Shade */
        pub const LayeredShade: u32 = 0x06;
/** Layered Shade 2D */
        pub const LayeredShade2D: u32 = 0x07;
/** Sheer Shade */
        pub const SheerShade: u32 = 0x08;
/** Tilt Only Interior Blind */
        pub const TiltOnlyInteriorBlind: u32 = 0x09;
/** Interior Blind */
        pub const InteriorBlind: u32 = 0x0A;
/** Vertical Blind, Strip Curtain */
        pub const VerticalBlindStripCurtain: u32 = 0x0B;
/** Interior Venetian Blind */
        pub const InteriorVenetianBlind: u32 = 0x0C;
/** Exterior Venetian Blind */
        pub const ExteriorVenetianBlind: u32 = 0x0D;
/** Lateral Left Curtain */
        pub const LateralLeftCurtain: u32 = 0x0E;
/** Lateral Right Curtain */
        pub const LateralRightCurtain: u32 = 0x0F;
/** Central Curtain */
        pub const CentralCurtain: u32 = 0x10;
/** Roller Shutter */
        pub const RollerShutter: u32 = 0x11;
/** Exterior Vertical Screen */
        pub const ExteriorVerticalScreen: u32 = 0x12;
/** Awning Terrace (Patio) */
        pub const AwningTerracePatio: u32 = 0x13;
/** Awning Vertical Screen */
        pub const AwningVerticalScreen: u32 = 0x14;
/** Tilt Only Pergola */
        pub const TiltOnlyPergola: u32 = 0x15;
/** Swinging Shutter */
        pub const SwingingShutter: u32 = 0x16;
/** Sliding Shutter */
        pub const SlidingShutter: u32 = 0x17;
/** Unknown */
        pub const Unknown: u32 = 0xFF;
    }
    pub mod TypeEnum {
/** RollerShade */
        pub const RollerShade: u32 = 0x00;
/** RollerShade - 2 Motor */
        pub const RollerShade2Motor: u32 = 0x01;
/** RollerShade - Exterior */
        pub const RollerShadeExterior: u32 = 0x02;
/** RollerShade - Exterior - 2 Motor */
        pub const RollerShadeExterior2Motor: u32 = 0x03;
/** Drapery (curtain) */
        pub const Drapery: u32 = 0x04;
/** Awning */
        pub const Awning: u32 = 0x05;
/** Shutter */
        pub const Shutter: u32 = 0x06;
/** Tilt Blind - Tilt Only */
        pub const TiltBlindTiltOnly: u32 = 0x07;
/** Tilt Blind - Lift & Tilt */
        pub const TiltBlindLiftAndTilt: u32 = 0x08;
/** Projector Screen */
        pub const ProjectorScreen: u32 = 0x09;
/** Unknown */
        pub const Unknown: u32 = 0xFF;
    }
    pub mod ConfigStatusBitmap {
/** Device is operational. */
        pub const Operational: u32 = 0x01;
        pub const OnlineReserved: u32 = 0x02;
/** The lift movement is reversed. */
        pub const LiftMovementReversed: u32 = 0x04;
/** Supports the PositionAwareLift feature (PA_LF). */
        pub const LiftPositionAware: u32 = 0x08;
/** Supports the PositionAwareTilt feature (PA_TL). */
        pub const TiltPositionAware: u32 = 0x10;
/** Uses an encoder for lift. */
        pub const LiftEncoderControlled: u32 = 0x20;
/** Uses an encoder for tilt. */
        pub const TiltEncoderControlled: u32 = 0x40;
    }
    pub mod ModeBitmap {
/** Reverse the lift direction. */
        pub const MotorDirectionReversed: u32 = 0x01;
/** Perform a calibration. */
        pub const CalibrationMode: u32 = 0x02;
/** Freeze all motions for maintenance. */
        pub const MaintenanceMode: u32 = 0x04;
/** Control the LEDs feedback. */
        pub const LedFeedback: u32 = 0x08;
    }
    pub mod OperationalStatusBitmap {
/** Global operational state. */
        pub const Global: u32 = 0x01;
/** Lift operational state. */
        pub const Lift: u32 = 0x01;
/** Tilt operational state. */
        pub const Tilt: u32 = 0x01;
    }
    pub mod SafetyStatusBitmap {
/** Movement commands are ignored (locked out). e.g. not granted authorization, outside some time/date range. */
        pub const RemoteLockout: u32 = 0x01;
/** Tampering detected on sensors or any other safety equipment. Ex: a device has been forcedly moved without its actuator(s). */
        pub const TamperDetection: u32 = 0x02;
/** Communication failure to sensors or other safety equipment. */
        pub const FailedCommunication: u32 = 0x04;
/** Device has failed to reach the desired position. e.g. with position aware device, time expired before TargetPosition is reached. */
        pub const PositionFailure: u32 = 0x08;
/** Motor(s) and/or electric circuit thermal protection activated. */
        pub const ThermalProtection: u32 = 0x10;
/** An obstacle is preventing actuator movement. */
        pub const ObstacleDetected: u32 = 0x20;
/** Device has power related issue or limitation e.g. device is running w/ the help of a backup battery or power might not be fully available at the moment. */
        pub const Power: u32 = 0x40;
/** Local safety sensor (not a direct obstacle) is preventing movements (e.g. Safety EU Standard EN60335). */
        pub const StopInput: u32 = 0x80;
/** Mechanical problem related to the motor(s) detected. */
        pub const MotorJammed: u32 = 0x100;
/** PCB, fuse and other electrics problems. */
        pub const HardwareFailure: u32 = 0x200;
/** Actuator is manually operated and is preventing actuator movement (e.g. actuator is disengaged/decoupled). */
        pub const ManualOperation: u32 = 0x400;
/** Protection is activated. */
        pub const Protection: u32 = 0x800;
    }
}
/** The Wi-Fi Network Diagnostics Cluster provides a means to acquire standardized diagnostics metrics that MAY be used by a Node to assist a user or Administrative Node in diagnosing potential problems. */
pub mod WiFiNetworkDiagnostics {
    pub mod AssociationFailureCauseEnum {
/** The reason for the failure is unknown. */
        pub const Unknown: u32 = 0x00;
/** An error occurred during association. */
        pub const AssociationFailed: u32 = 0x01;
/** An error occurred during authentication. */
        pub const AuthenticationFailed: u32 = 0x02;
/** The specified SSID could not be found. */
        pub const SsidNotFound: u32 = 0x03;
    }
    pub mod ConnectionStatusEnum {
/** Indicate the node is connected */
        pub const Connected: u32 = 0x00;
/** Indicate the node is not connected */
        pub const NotConnected: u32 = 0x01;
    }
    pub mod SecurityTypeEnum {
/** Indicate the usage of an unspecified Wi-Fi security type */
        pub const Unspecified: u32 = 0x00;
/** Indicate the usage of no Wi-Fi security */
        pub const None: u32 = 0x01;
/** Indicate the usage of WEP Wi-Fi security */
        pub const WEP: u32 = 0x02;
/** Indicate the usage of WPA Wi-Fi security */
        pub const WPA: u32 = 0x03;
/** Indicate the usage of WPA2 Wi-Fi security */
        pub const WPA2: u32 = 0x04;
/** Indicate the usage of WPA3 Wi-Fi security */
        pub const WPA3: u32 = 0x05;
    }
    pub mod WiFiVersionEnum {
/** Indicate the network interface is currently using IEEE 802.11a against the wireless access point. */
        pub const a: u32 = 0x00;
/** Indicate the network interface is currently using IEEE 802.11b against the wireless access point. */
        pub const b: u32 = 0x01;
/** Indicate the network interface is currently using IEEE 802.11g against the wireless access point. */
        pub const g: u32 = 0x02;
/** Indicate the network interface is currently using IEEE 802.11n against the wireless access point. */
        pub const n: u32 = 0x03;
/** Indicate the network interface is currently using IEEE 802.11ac against the wireless access point. */
        pub const ac: u32 = 0x04;
/** Indicate the network interface is currently using IEEE 802.11ax against the wireless access point. */
        pub const ax: u32 = 0x05;
/** Indicate the network interface is currently using IEEE 802.11ah against the wireless access point. */
        pub const ah: u32 = 0x06;
    }
}
/** Attributes for reporting air quality classification */
pub mod AirQuality {
    pub mod AirQualityEnum {
/** The air quality is unknown. */
        pub const Unknown: u32 = 0x00;
/** The air quality is good. */
        pub const Good: u32 = 0x01;
/** The air quality is fair. */
        pub const Fair: u32 = 0x02;
/** The air quality is moderate. */
        pub const Moderate: u32 = 0x03;
/** The air quality is poor. */
        pub const Poor: u32 = 0x04;
/** The air quality is very poor. */
        pub const VeryPoor: u32 = 0x05;
/** The air quality is extremely poor. */
        pub const ExtremelyPoor: u32 = 0x06;
    }
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod TotalVolatileOrganicCompoundsConcentrationMeasurement {
    pub mod LevelValueEnum {
/** The level is Unknown */
        pub const Unknown: u32 = 0x00;
/** The level is considered Low */
        pub const Low: u32 = 0x01;
/** The level is considered Medium */
        pub const Medium: u32 = 0x02;
/** The level is considered High */
        pub const High: u32 = 0x03;
/** The level is considered Critical */
        pub const Critical: u32 = 0x04;
    }
    pub mod MeasurementMediumEnum {
/** The measurement is being made in Air */
        pub const Air: u32 = 0x00;
/** The measurement is being made in Water */
        pub const Water: u32 = 0x01;
/** The measurement is being made in Soil */
        pub const Soil: u32 = 0x02;
    }
    pub mod MeasurementUnitEnum {
/** Parts per Million (10) */
        pub const PPM: u32 = 0x00;
/** Parts per Billion (10) */
        pub const PPB: u32 = 0x01;
/** Parts per Trillion (10) */
        pub const PPT: u32 = 0x02;
/** Milligram per m */
        pub const MGM3: u32 = 0x03;
/** Microgram per m */
        pub const UGM3: u32 = 0x04;
/** Nanogram per m */
        pub const NGM3: u32 = 0x05;
/** Particles per m */
        pub const PM3: u32 = 0x06;
/** Becquerel per m */
        pub const BQM3: u32 = 0x07;
    }
}
/** Provides an interface for downloading and applying OTA software updates */
pub mod OTASoftwareUpdateRequestor {
    pub mod AnnouncementReasonEnum {
/** An OTA Provider is announcing its presence. */
        pub const SimpleAnnouncement: u32 = 0x00;
/** An OTA Provider is announcing, either to a single Node or to a group of Nodes, that a new Software Image MAY be available. */
        pub const UpdateAvailable: u32 = 0x01;
/** An OTA Provider is announcing, either to a single Node or to a group of Nodes, that a new Software Image MAY be available, which contains an update that needs to be applied urgently. */
        pub const UrgentUpdateAvailable: u32 = 0x02;
    }
    pub mod ChangeReasonEnum {
/** The reason for a state change is unknown. */
        pub const Unknown: u32 = 0x00;
/** The reason for a state change is the success of a prior operation. */
        pub const Success: u32 = 0x01;
/** The reason for a state change is the failure of a prior operation. */
        pub const Failure: u32 = 0x02;
/** The reason for a state change is a time-out. */
        pub const TimeOut: u32 = 0x03;
/** The reason for a state change is a request by the OTA Provider to wait. */
        pub const DelayByProvider: u32 = 0x04;
    }
    pub mod UpdateStateEnum {
/** Current state is not yet determined. */
        pub const Unknown: u32 = 0x00;
/** Indicate a Node not yet in the process of software update. */
        pub const Idle: u32 = 0x01;
/** Indicate a Node in the process of querying an OTA Provider. */
        pub const Querying: u32 = 0x02;
/** Indicate a Node waiting after a Busy response. */
        pub const DelayedOnQuery: u32 = 0x03;
/** Indicate a Node currently in the process of downloading a software update. */
        pub const Downloading: u32 = 0x04;
/** Indicate a Node currently in the process of verifying and applying a software update. */
        pub const Applying: u32 = 0x05;
/** Indicate a Node waiting caused by AwaitNextAction response. */
        pub const DelayedOnApply: u32 = 0x06;
/** Indicate a Node in the process of recovering to a previous version. */
        pub const RollingBack: u32 = 0x07;
/** Indicate a Node is capable of user consent. */
        pub const DelayedOnUserConsent: u32 = 0x08;
    }
}
/** The Service Area cluster provides an interface for controlling the areas where a device should operate, and for querying the current area being serviced. */
pub mod ServiceArea {
    pub mod OperationalStatusEnum {
/** The device has not yet started operating at the given area, or has not finished operating at that area but it is not currently operating at the area */
        pub const Pending: u32 = 0x00;
/** The device is currently operating at the given area */
        pub const Operating: u32 = 0x01;
/** The device has skipped the given area, before or during operating at it, due to a SkipArea command, due an out of band command (e.g. from the vendor's application), due to a vendor specific reason, such as a time limit used by the device, or due the device ending operating unsuccessfully */
        pub const Skipped: u32 = 0x02;
/** The device has completed operating at the given area */
        pub const Completed: u32 = 0x03;
    }
    pub mod SelectAreasStatus {
/** Attempting to operate in the areas identified by the entries of the NewAreas field is allowed and possible. The SelectedAreas attribute is set to the value of the NewAreas field. */
        pub const Success: u32 = 0x00;
/** The value of at least one of the entries of the NewAreas field doesn't match any entries in the SupportedAreas attribute. */
        pub const UnsupportedArea: u32 = 0x01;
/** The received request cannot be handled due to the current mode of the device. */
        pub const InvalidInMode: u32 = 0x02;
/** The set of values is invalid. For example, areas on different floors, that a robot knows it can't reach on its own. */
        pub const InvalidSet: u32 = 0x03;
    }
    pub mod SkipAreaStatus {
/** Skipping the area is allowed and possible, or the device was operating at the last available area and has stopped. */
        pub const Success: u32 = 0x00;
/** The SelectedAreas attribute is empty. */
        pub const InvalidAreaList: u32 = 0x01;
/** The received request cannot be handled due to the current mode of the device. For example, the CurrentArea attribute is null or the device is not operating. */
        pub const InvalidInMode: u32 = 0x02;
/** The SkippedArea field doesn't match an entry in the SupportedAreas list. */
        pub const InvalidSkippedArea: u32 = 0x03;
    }
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod RefrigeratorAndTemperatureControlledCabinetMode {
    pub mod ModeTag {
        pub const Auto: u32 = 0x00;
        pub const Quick: u32 = 0x01;
        pub const Quiet: u32 = 0x02;
        pub const LowNoise: u32 = 0x03;
        pub const LowEnergy: u32 = 0x04;
        pub const Vacation: u32 = 0x05;
        pub const Min: u32 = 0x06;
        pub const Max: u32 = 0x07;
        pub const Night: u32 = 0x08;
        pub const Day: u32 = 0x09;
        pub const RapidCool: u32 = 0x4000;
        pub const RapidFreeze: u32 = 0x4001;
    }
}
/** The Access Control Cluster exposes a data model view of a
 * Node's Access Control List (ACL), which codifies the rules used to manage
 * and enforce Access Control for the Node's endpoints and their associated
 * cluster instances. */
pub mod AccessControl {
    pub mod AccessControlEntryAuthModeEnum {
/** Passcode authenticated session */
        pub const PASE: u32 = 0x01;
/** Certificate authenticated session */
        pub const CASE: u32 = 0x02;
/** Group authenticated session */
        pub const Group: u32 = 0x03;
    }
    pub mod AccessControlEntryPrivilegeEnum {
/** Can read and observe all (except Access Control Cluster) */
        pub const View: u32 = 0x01;
        pub const ProxyView: u32 = 0x02;
/** View privileges, and can perform the primary function of this Node (except Access Control Cluster) */
        pub const Operate: u32 = 0x03;
/** Operate privileges, and can modify persistent configuration of this Node (except Access Control Cluster) */
        pub const Manage: u32 = 0x04;
/** Manage privileges, and can observe and modify the Access Control Cluster */
        pub const Administer: u32 = 0x05;
    }
    pub mod AccessRestrictionTypeEnum {
/** Clients on this fabric are currently forbidden from reading and writing an attribute */
        pub const AttributeAccessForbidden: u32 = 0x00;
/** Clients on this fabric are currently forbidden from writing an attribute */
        pub const AttributeWriteForbidden: u32 = 0x01;
/** Clients on this fabric are currently forbidden from invoking a command */
        pub const CommandForbidden: u32 = 0x02;
/** Clients on this fabric are currently forbidden from reading an event */
        pub const EventForbidden: u32 = 0x03;
    }
    pub mod ChangeTypeEnum {
/** Entry or extension was changed */
        pub const Changed: u32 = 0x00;
/** Entry or extension was added */
        pub const Added: u32 = 0x01;
/** Entry or extension was removed */
        pub const Removed: u32 = 0x02;
    }
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod WaterHeaterMode {
    pub mod ModeTag {
        pub const Auto: u32 = 0x00;
        pub const Quick: u32 = 0x01;
        pub const Quiet: u32 = 0x02;
        pub const LowNoise: u32 = 0x03;
        pub const LowEnergy: u32 = 0x04;
        pub const Vacation: u32 = 0x05;
        pub const Min: u32 = 0x06;
        pub const Max: u32 = 0x07;
        pub const Night: u32 = 0x08;
        pub const Day: u32 = 0x09;
        pub const Off: u32 = 0x4000;
        pub const Manual: u32 = 0x4001;
        pub const Timed: u32 = 0x4002;
    }
}
/** This Cluster is used to provision TLS Endpoints with enough information to facilitate subsequent connection. */
pub mod TLSClientManagement {
    pub mod StatusCodeEnum {
/** The endpoint is already installed. */
        pub const EndpointAlreadyInstalled: u32 = 0x02;
/** No root certificate exists for this CAID. */
        pub const RootCertificateNotFound: u32 = 0x03;
/** No client certificate exists for this CCDID. */
        pub const ClientCertificateNotFound: u32 = 0x04;
/** The endpoint is in use and cannot be removed. */
        pub const EndpointInUse: u32 = 0x05;
/** Time sync has not yet occurred. */
        pub const InvalidTime: u32 = 0x06;
    }
}
/** This cluster provides a mechanism for querying data about the electrical energy imported or provided by the server. */
pub mod ElectricalEnergyMeasurement {
    pub mod MeasurementTypeEnum {
        pub const Unspecified: u32 = 0x00;
/** Voltage in millivolts (mV) */
        pub const Voltage: u32 = 0x01;
/** Active current in milliamps (mA) */
        pub const ActiveCurrent: u32 = 0x02;
/** Reactive current in milliamps (mA) */
        pub const ReactiveCurrent: u32 = 0x03;
/** Apparent current in milliamps (mA) */
        pub const ApparentCurrent: u32 = 0x04;
/** Active power in milliwatts (mW) */
        pub const ActivePower: u32 = 0x05;
/** Reactive power in millivolt-amps reactive (mVAR) */
        pub const ReactivePower: u32 = 0x06;
/** Apparent power in millivolt-amps (mVA) */
        pub const ApparentPower: u32 = 0x07;
/** Root mean squared voltage in millivolts (mV) */
        pub const RMSVoltage: u32 = 0x08;
/** Root mean squared current in milliamps (mA) */
        pub const RMSCurrent: u32 = 0x09;
/** Root mean squared power in milliwatts (mW) */
        pub const RMSPower: u32 = 0x0A;
/** AC frequency in millihertz (mHz) */
        pub const Frequency: u32 = 0x0B;
/** Power Factor ratio in +/- 1/100ths of a percent. */
        pub const PowerFactor: u32 = 0x0C;
/** AC neutral current in milliamps (mA) */
        pub const NeutralCurrent: u32 = 0x0D;
/** Electrical energy in milliwatt-hours (mWh) */
        pub const ElectricalEnergy: u32 = 0x0E;
/** Reactive power in millivolt-amp-hours reactive (mVARh) */
        pub const ReactiveEnergy: u32 = 0x0F;
/** Apparent power in millivolt-amp-hours (mVAh) */
        pub const ApparentEnergy: u32 = 0x10;
    }
}
/** This cluster provides an interface for controlling a Closure. */
pub mod ClosureControl {
    pub mod ClosureErrorEnum {
/** An obstacle is blocking the closure movement */
        pub const PhysicallyBlocked: u32 = 0x00;
/** The closure is unsafe to move, as determined by a sensor (e.g. photoelectric sensor) before attempting movement */
        pub const BlockedBySensor: u32 = 0x01;
/** A warning raised by the closure that indicates an over-temperature, e.g. due to excessive drive or stall current */
        pub const TemperatureLimited: u32 = 0x02;
/** Some malfunctions that are not easily recoverable are detected, or urgent servicing is needed */
        pub const MaintenanceRequired: u32 = 0x03;
/** An internal element is prohibiting motion, e.g. an integrated door within a bigger garage door is open and prevents motion */
        pub const InternalInterference: u32 = 0x04;
    }
    pub mod CurrentPositionEnum {
/** Fully closed state */
        pub const FullyClosed: u32 = 0x00;
/** Fully opened state */
        pub const FullyOpened: u32 = 0x01;
/** Partially opened state (closure is not fully opened or fully closed) */
        pub const PartiallyOpened: u32 = 0x02;
/** Closure is in the Pedestrian position */
        pub const OpenedForPedestrian: u32 = 0x03;
/** Closure is in the Ventilation position */
        pub const OpenedForVentilation: u32 = 0x04;
/** Closure is in its "Signature position" */
        pub const OpenedAtSignature: u32 = 0x05;
    }
    pub mod MainStateEnum {
/** Closure is stopped */
        pub const Stopped: u32 = 0x00;
/** Closure is actively moving */
        pub const Moving: u32 = 0x01;
/** Closure is waiting before a motion (e.g. pre-heat, pre-check) */
        pub const WaitingForMotion: u32 = 0x02;
/** Closure is in an error state */
        pub const Error: u32 = 0x03;
/** Closure is currently calibrating its Opened and Closed limits to determine effective physical range */
        pub const Calibrating: u32 = 0x04;
/** Some protective measures are activated to prevent damage to the closure. Commands MAY be rejected. */
        pub const Protected: u32 = 0x05;
/** Closure has a disengaged element preventing any actuator movements */
        pub const Disengaged: u32 = 0x06;
/** Movement commands are ignored since the closure is not operational and requires further setup and/or calibration */
        pub const SetupRequired: u32 = 0x07;
    }
    pub mod TargetPositionEnum {
/** Move to a fully closed state */
        pub const MoveToFullyClosed: u32 = 0x00;
/** Move to a fully open state */
        pub const MoveToFullyOpen: u32 = 0x01;
/** Move to the Pedestrian position */
        pub const MoveToPedestrianPosition: u32 = 0x02;
/** Move to the Ventilation position */
        pub const MoveToVentilationPosition: u32 = 0x03;
/** Move to the Signature position */
        pub const MoveToSignaturePosition: u32 = 0x04;
    }
    pub mod LatchControlModesBitmap {
/** Remote latching capability */
        pub const RemoteLatching: u32 = 0x01;
/** Remote unlatching capability */
        pub const RemoteUnlatching: u32 = 0x02;
    }
}
/** Attributes and commands for putting a device into Identification mode (e.g. flashing a light). */
pub mod Identify {
    pub mod EffectIdentifierEnum {
/** e.g., Light is turned on/off once. */
        pub const Blink: u32 = 0x00;
/** e.g., Light is turned on/off over 1 second and repeated 15 times. */
        pub const Breathe: u32 = 0x01;
/** e.g., Colored light turns green for 1 second; non-colored light flashes twice. */
        pub const Okay: u32 = 0x02;
/** e.g., Colored light turns orange for 8 seconds; non-colored light switches to the maximum brightness for 0.5s and then minimum brightness for 7.5s. */
        pub const ChannelChange: u32 = 0x0B;
/** Complete the current effect sequence before terminating. e.g., if in the middle of a breathe effect (as above), first complete the current 1s breathe effect and then terminate the effect. */
        pub const FinishEffect: u32 = 0xFE;
/** Terminate the effect as soon as possible. */
        pub const StopEffect: u32 = 0xFF;
    }
    pub mod EffectVariantEnum {
/** Indicates the default effect is used */
        pub const Default: u32 = 0x00;
    }
    pub mod IdentifyTypeEnum {
/** No presentation. */
        pub const None: u32 = 0x00;
/** Light output of a lighting product. */
        pub const LightOutput: u32 = 0x01;
/** Typically a small LED. */
        pub const VisibleIndicator: u32 = 0x02;
        pub const AudibleBeep: u32 = 0x03;
/** Presentation will be visible on display screen. */
        pub const Display: u32 = 0x04;
/** Presentation will be conveyed by actuator functionality such as through a window blind operation or in-wall relay. */
        pub const Actuator: u32 = 0x05;
    }
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod EnergyEVSEMode {
    pub mod ModeTag {
        pub const Auto: u32 = 0x00;
        pub const Quick: u32 = 0x01;
        pub const Quiet: u32 = 0x02;
        pub const LowNoise: u32 = 0x03;
        pub const LowEnergy: u32 = 0x04;
        pub const Vacation: u32 = 0x05;
        pub const Min: u32 = 0x06;
        pub const Max: u32 = 0x07;
        pub const Night: u32 = 0x08;
        pub const Day: u32 = 0x09;
        pub const Manual: u32 = 0x4000;
        pub const TimeOfUse: u32 = 0x4001;
        pub const SolarCharging: u32 = 0x4002;
        pub const V2X: u32 = 0x4003;
    }
}
/** This cluster is used to configure a boolean sensor. */
pub mod BooleanStateConfiguration {
    pub mod AlarmModeBitmap {
/** Visual alarming */
        pub const Visual: u32 = 0x01;
/** Audible alarming */
        pub const Audible: u32 = 0x02;
    }
    pub mod SensorFaultBitmap {
/** Unspecified fault detected */
        pub const GeneralFault: u32 = 0x01;
    }
}
/** Attributes for reporting carbon monoxide concentration measurements */
pub mod RadonConcentrationMeasurement {
    pub mod LevelValueEnum {
/** The level is Unknown */
        pub const Unknown: u32 = 0x00;
/** The level is considered Low */
        pub const Low: u32 = 0x01;
/** The level is considered Medium */
        pub const Medium: u32 = 0x02;
/** The level is considered High */
        pub const High: u32 = 0x03;
/** The level is considered Critical */
        pub const Critical: u32 = 0x04;
    }
    pub mod MeasurementMediumEnum {
/** The measurement is being made in Air */
        pub const Air: u32 = 0x00;
/** The measurement is being made in Water */
        pub const Water: u32 = 0x01;
/** The measurement is being made in Soil */
        pub const Soil: u32 = 0x02;
    }
    pub mod MeasurementUnitEnum {
/** Parts per Million (10) */
        pub const PPM: u32 = 0x00;
/** Parts per Billion (10) */
        pub const PPB: u32 = 0x01;
/** Parts per Trillion (10) */
        pub const PPT: u32 = 0x02;
/** Milligram per m */
        pub const MGM3: u32 = 0x03;
/** Microgram per m */
        pub const UGM3: u32 = 0x04;
/** Nanogram per m */
        pub const NGM3: u32 = 0x05;
/** Particles per m */
        pub const PM3: u32 = 0x06;
/** Becquerel per m */
        pub const BQM3: u32 = 0x07;
    }
}
/** This Meter Identification Cluster provides attributes for determining advanced information about utility metering device. */
pub mod MeterIdentification {
    pub mod MeterTypeEnum {
/** Utility Meter */
        pub const Utility: u32 = 0x00;
/** Private Meter */
        pub const Private: u32 = 0x01;
/** Generic Meter */
        pub const Generic: u32 = 0x02;
    }
}
/** This cluster provides an interface to specify preferences for how devices should consume energy. */
pub mod EnergyPreference {
    pub mod EnergyPriorityEnum {
/** User comfort */
        pub const Comfort: u32 = 0x00;
/** Speed of operation */
        pub const Speed: u32 = 0x01;
/** Amount of Energy consumed by the device */
        pub const Efficiency: u32 = 0x02;
/** Amount of water consumed by the device */
        pub const WaterConsumption: u32 = 0x03;
    }
}
/** Attributes and commands for scene configuration and manipulation. */
pub mod ScenesManagement {
    pub mod CopyModeBitmap {
/** Copy all scenes in the scene table */
        pub const CopyAllScenes: u32 = 0x01;
    }
}
/** Attributes and commands for monitoring HEPA filters in a device */
pub mod HEPAFilterMonitoring {
    pub mod ChangeIndicationEnum {
/** Resource is in good condition, no intervention required */
        pub const OK: u32 = 0x00;
/** Resource will be exhausted soon, intervention will shortly be required */
        pub const Warning: u32 = 0x01;
/** Resource is exhausted, immediate intervention is required */
        pub const Critical: u32 = 0x02;
    }
    pub mod DegradationDirectionEnum {
/** The degradation of the resource is indicated by an upwards moving/increasing value */
        pub const Up: u32 = 0x00;
/** The degradation of the resource is indicated by a downwards moving/decreasing value */
        pub const Down: u32 = 0x01;
    }
    pub mod ProductIdentifierTypeEnum {
/** 12-digit Universal Product Code */
        pub const UPC: u32 = 0x00;
/** 8-digit Global Trade Item Number */
        pub const GTIN8: u32 = 0x01;
/** 13-digit European Article Number */
        pub const EAN: u32 = 0x02;
/** 14-digit Global Trade Item Number */
        pub const GTIN14: u32 = 0x03;
/** Original Equipment Manufacturer part number */
        pub const OEM: u32 = 0x04;
    }
}
/** Attributes and commands for monitoring HEPA filters in a device */
pub mod ActivatedCarbonFilterMonitoring {
    pub mod ChangeIndicationEnum {
/** Resource is in good condition, no intervention required */
        pub const OK: u32 = 0x00;
/** Resource will be exhausted soon, intervention will shortly be required */
        pub const Warning: u32 = 0x01;
/** Resource is exhausted, immediate intervention is required */
        pub const Critical: u32 = 0x02;
    }
    pub mod DegradationDirectionEnum {
/** The degradation of the resource is indicated by an upwards moving/increasing value */
        pub const Up: u32 = 0x00;
/** The degradation of the resource is indicated by a downwards moving/decreasing value */
        pub const Down: u32 = 0x01;
    }
    pub mod ProductIdentifierTypeEnum {
/** 12-digit Universal Product Code */
        pub const UPC: u32 = 0x00;
/** 8-digit Global Trade Item Number */
        pub const GTIN8: u32 = 0x01;
/** 13-digit European Article Number */
        pub const EAN: u32 = 0x02;
/** 14-digit Global Trade Item Number */
        pub const GTIN14: u32 = 0x03;
/** Original Equipment Manufacturer part number */
        pub const OEM: u32 = 0x04;
    }
}
/** Attributes and commands for monitoring HEPA filters in a device */
pub mod WaterTankLevelMonitoring {
    pub mod ChangeIndicationEnum {
/** Resource is in good condition, no intervention required */
        pub const OK: u32 = 0x00;
/** Resource will be exhausted soon, intervention will shortly be required */
        pub const Warning: u32 = 0x01;
/** Resource is exhausted, immediate intervention is required */
        pub const Critical: u32 = 0x02;
    }
    pub mod DegradationDirectionEnum {
/** The degradation of the resource is indicated by an upwards moving/increasing value */
        pub const Up: u32 = 0x00;
/** The degradation of the resource is indicated by a downwards moving/decreasing value */
        pub const Down: u32 = 0x01;
    }
    pub mod ProductIdentifierTypeEnum {
/** 12-digit Universal Product Code */
        pub const UPC: u32 = 0x00;
/** 8-digit Global Trade Item Number */
        pub const GTIN8: u32 = 0x01;
/** 13-digit European Article Number */
        pub const EAN: u32 = 0x02;
/** 14-digit Global Trade Item Number */
        pub const GTIN14: u32 = 0x03;
/** Original Equipment Manufacturer part number */
        pub const OEM: u32 = 0x04;
    }
}
/** An interface for configuring and controlling pumps. */
pub mod PumpConfigurationandControl {
    pub mod ControlModeEnum {
/** The pump is running at a constant speed. */
        pub const ConstantSpeed: u32 = 0x00;
/** The pump will regulate its speed to maintain a constant differential pressure over its flanges. */
        pub const ConstantPressure: u32 = 0x01;
/** The pump will regulate its speed to maintain a constant differential pressure over its flanges. */
        pub const ProportionalPressure: u32 = 0x02;
/** The pump will regulate its speed to maintain a constant flow through the pump. */
        pub const ConstantFlow: u32 = 0x03;
/** The pump will regulate its speed to maintain a constant temperature. */
        pub const ConstantTemperature: u32 = 0x05;
/** The operation of the pump is automatically optimized to provide the most suitable performance with respect to comfort and energy savings. */
        pub const Automatic: u32 = 0x07;
    }
    pub mod OperationModeEnum {
/** The pump is controlled by a setpoint, as defined by a connected remote sensor or by the ControlMode attribute. */
        pub const Normal: u32 = 0x00;
/** This value sets the pump to run at the minimum possible speed it can without being stopped. */
        pub const Minimum: u32 = 0x01;
/** This value sets the pump to run at its maximum possible speed. */
        pub const Maximum: u32 = 0x02;
/** This value sets the pump to run with the local settings of the pump, regardless of what these are. */
        pub const Local: u32 = 0x03;
    }
    pub mod PumpStatusBitmap {
/** A fault related to the system or pump device is detected. */
        pub const DeviceFault: u32 = 0x01;
/** A fault related to the supply to the pump is detected. */
        pub const SupplyFault: u32 = 0x02;
/** Setpoint is too low to achieve. */
        pub const SpeedLow: u32 = 0x04;
/** Setpoint is too high to achieve. */
        pub const SpeedHigh: u32 = 0x08;
/** Device control is overridden by hardware, such as an external STOP button or via a local HMI. */
        pub const LocalOverride: u32 = 0x10;
/** Pump is currently running */
        pub const Running: u32 = 0x20;
/** A remote pressure sensor is used as the sensor for the regulation of the pump. */
        pub const RemotePressure: u32 = 0x40;
/** A remote flow sensor is used as the sensor for the regulation of the pump. */
        pub const RemoteFlow: u32 = 0x80;
/** A remote temperature sensor is used as the sensor for the regulation of the pump. */
        pub const RemoteTemperature: u32 = 0x100;
    }
}
/** This cluster is used to manage global aspects of the Commissioning flow. */
pub mod GeneralCommissioning {
    pub mod CommissioningErrorEnum {
/** No error */
        pub const OK: u32 = 0x00;
/** Attempting to set regulatory configuration to a region or indoor/outdoor mode for which the server does not have proper configuration. */
        pub const ValueOutsideRange: u32 = 0x01;
/** Executed CommissioningComplete outside CASE session. */
        pub const InvalidAuthentication: u32 = 0x02;
/** Executed CommissioningComplete when there was no active Fail-Safe context. */
        pub const NoFailSafe: u32 = 0x03;
/** Attempting to arm fail-safe or execute CommissioningComplete from a fabric different than the one associated with the current fail-safe context. */
        pub const BusyWithOtherAdmin: u32 = 0x04;
/** One or more required TC features from the Enhanced Setup Flow were not accepted. */
        pub const RequiredTCNotAccepted: u32 = 0x05;
/** TCAcknowledgementsNotReceived No or insufficient acknowledgements from the user for the TC features were received. */
        pub const TCAcknowledgementsNotReceived: u32 = 0x06;
/** TCMinVersionNotMet The version of the TC features acknowledged by the user did not meet the minimum required version. */
        pub const TCMinVersionNotMet: u32 = 0x07;
    }
    pub mod NetworkRecoveryReasonEnum {
/** Unspecified / unknown reason of network failure */
        pub const Unspecified: u32 = 0x00;
/** Credentials for the configured operational network are not valid */
        pub const Auth: u32 = 0x01;
/** Configured network cannot be found (e.g. the device cannot see the configured Wi-Fi SSID, Thread end-node is unable to find a parent router on the PAN) */
        pub const Visibility: u32 = 0x02;
    }
    pub mod RegulatoryLocationTypeEnum {
/** Indoor only */
        pub const Indoor: u32 = 0x00;
/** Outdoor only */
        pub const Outdoor: u32 = 0x01;
/** Indoor/Outdoor */
        pub const IndoorOutdoor: u32 = 0x02;
    }
}
/** This cluster is used to add or remove Operational Credentials on a Commissionee or Node, as well as manage the associated Fabrics. */
pub mod OperationalCredentials {
    pub mod CertificateChainTypeEnum {
/** Request the DER-encoded DAC certificate */
        pub const DACCertificate: u32 = 0x01;
/** Request the DER-encoded PAI certificate */
        pub const PAICertificate: u32 = 0x02;
    }
    pub mod NodeOperationalCertStatusEnum {
/** OK, no error */
        pub const OK: u32 = 0x00;
/** Public Key in the NOC does not match the public key in the NOCSR */
        pub const InvalidPublicKey: u32 = 0x01;
/** The Node Operational ID in the NOC is not formatted correctly. */
        pub const InvalidNodeOpId: u32 = 0x02;
/** Any other validation error in NOC chain */
        pub const InvalidNOC: u32 = 0x03;
/** No record of prior CSR for which this NOC could match */
        pub const MissingCsr: u32 = 0x04;
/** NOCs table full, cannot add another one */
        pub const TableFull: u32 = 0x05;
/** Invalid CaseAdminSubject field for an AddNOC command. */
        pub const InvalidAdminSubject: u32 = 0x06;
/** Reserved for future use */
        pub const ReservedForFutureUse: u32 = 0x07;
/** Reserved for future use */
        pub const ReservedForFutureUse_0x8: u32 = 0x08;
/** Trying to AddNOC instead of UpdateNOC against an existing Fabric. */
        pub const FabricConflict: u32 = 0x09;
/** Label already exists on another Fabric. */
        pub const LabelConflict: u32 = 0x0A;
/** FabricIndex argument is invalid. */
        pub const InvalidFabricIndex: u32 = 0x0B;
    }
}
/** This cluster provides an interface for UX navigation within a set of targets on a device or endpoint. */
pub mod TargetNavigator {
    pub mod StatusEnum {
/** Command succeeded */
        pub const Success: u32 = 0x00;
/** Requested target was not found in the TargetList */
        pub const TargetNotFound: u32 = 0x01;
/** Target request is not allowed in current state. */
        pub const NotAllowed: u32 = 0x02;
    }
}
/** An interface for controlling a fan in a heating/cooling system. */
pub mod FanControl {
    pub mod AirflowDirectionEnum {
/** Airflow is in the forward direction */
        pub const Forward: u32 = 0x00;
/** Airflow is in the reverse direction */
        pub const Reverse: u32 = 0x01;
    }
    pub mod FanModeEnum {
/** Fan is off */
        pub const Off: u32 = 0x00;
/** Fan using low speed */
        pub const Low: u32 = 0x01;
/** Fan using medium speed */
        pub const Medium: u32 = 0x02;
/** Fan using high speed */
        pub const High: u32 = 0x03;
        pub const On: u32 = 0x04;
/** Fan is using auto mode */
        pub const Auto: u32 = 0x05;
/** Fan is using smart mode */
        pub const Smart: u32 = 0x06;
    }
    pub mod FanModeSequenceEnum {
/** Fan is capable of off, low, medium and high modes */
        pub const OffLowMedHigh: u32 = 0x00;
/** Fan is capable of off, low and high modes */
        pub const OffLowHigh: u32 = 0x01;
/** Fan is capable of off, low, medium, high and auto modes */
        pub const OffLowMedHighAuto: u32 = 0x02;
/** Fan is capable of off, low, high and auto modes */
        pub const OffLowHighAuto: u32 = 0x03;
/** Fan is capable of off, high and auto modes */
        pub const OffHighAuto: u32 = 0x04;
/** Fan is capable of off and high modes */
        pub const OffHigh: u32 = 0x05;
    }
    pub mod StepDirectionEnum {
/** Step moves in increasing direction */
        pub const Increase: u32 = 0x00;
/** Step moves in decreasing direction */
        pub const Decrease: u32 = 0x01;
    }
    pub mod RockBitmap {
/** Indicate rock left to right */
        pub const RockLeftRight: u32 = 0x01;
/** Indicate rock up and down */
        pub const RockUpDown: u32 = 0x02;
/** Indicate rock around */
        pub const RockRound: u32 = 0x04;
    }
    pub mod WindBitmap {
/** Indicate sleep wind */
        pub const SleepWind: u32 = 0x01;
/** Indicate natural wind */
        pub const NaturalWind: u32 = 0x02;
    }
}
pub mod GlobalElements {
    pub mod AtomicRequestTypeEnum {
/** Begin an atomic write */
        pub const BeginWrite: u32 = 0x00;
/** Commit an atomic write */
        pub const CommitWrite: u32 = 0x01;
/** Rollback an atomic write, discarding any pending changes */
        pub const RollbackWrite: u32 = 0x02;
    }
    pub mod MeasurementTypeEnum {
        pub const Unspecified: u32 = 0x00;
/** Voltage in millivolts (mV) */
        pub const Voltage: u32 = 0x01;
/** Active current in milliamps (mA) */
        pub const ActiveCurrent: u32 = 0x02;
/** Reactive current in milliamps (mA) */
        pub const ReactiveCurrent: u32 = 0x03;
/** Apparent current in milliamps (mA) */
        pub const ApparentCurrent: u32 = 0x04;
/** Active power in milliwatts (mW) */
        pub const ActivePower: u32 = 0x05;
/** Reactive power in millivolt-amps reactive (mVAR) */
        pub const ReactivePower: u32 = 0x06;
/** Apparent power in millivolt-amps (mVA) */
        pub const ApparentPower: u32 = 0x07;
/** Root mean squared voltage in millivolts (mV) */
        pub const RMSVoltage: u32 = 0x08;
/** Root mean squared current in milliamps (mA) */
        pub const RMSCurrent: u32 = 0x09;
/** Root mean squared power in milliwatts (mW) */
        pub const RMSPower: u32 = 0x0A;
/** AC frequency in millihertz (mHz) */
        pub const Frequency: u32 = 0x0B;
/** Power Factor ratio in +/- 1/100ths of a percent. */
        pub const PowerFactor: u32 = 0x0C;
/** AC neutral current in milliamps (mA) */
        pub const NeutralCurrent: u32 = 0x0D;
/** Electrical energy in milliwatt-hours (mWh) */
        pub const ElectricalEnergy: u32 = 0x0E;
/** Reactive power in millivolt-amp-hours reactive (mVARh) */
        pub const ReactiveEnergy: u32 = 0x0F;
/** Apparent power in millivolt-amp-hours (mVAh) */
        pub const ApparentEnergy: u32 = 0x10;
/** Soil moisture in percent */
        pub const SoilMoisture: u32 = 0x11;
    }
    pub mod PowerThresholdSourceEnum {
/** The power threshold comes from a signed contract */
        pub const Contract: u32 = 0x00;
/** The power threshold comes from a legal regulator */
        pub const Regulator: u32 = 0x01;
/** The power threshold comes from a certified limits of the meter */
        pub const Equipment: u32 = 0x02;
    }
    pub mod SoftwareVersionCertificationStatusEnum {
/** dev-test */
        pub const devtest: u32 = 0x00;
/** provisional */
        pub const provisional: u32 = 0x01;
/** certified */
        pub const certified: u32 = 0x02;
/** revoked */
        pub const revoked: u32 = 0x03;
    }
    pub mod StreamUsageEnum {
/** Internal video stream. */
        pub const Internal: u32 = 0x00;
/** Stream for recording clips. */
        pub const Recording: u32 = 0x01;
/** Stream for analysis and entity detection. */
        pub const Analysis: u32 = 0x02;
/** Stream for liveview. */
        pub const LiveView: u32 = 0x03;
    }
    pub mod TariffPriceTypeEnum {
/** Standard tariff price */
        pub const Standard: u32 = 0x00;
/** Price during CPP events */
        pub const Critical: u32 = 0x01;
/** Price during VPP events */
        pub const Virtual: u32 = 0x02;
/** Price incentives */
        pub const Incentive: u32 = 0x03;
/** Price incentive signals */
        pub const IncentiveSignal: u32 = 0x04;
    }
    pub mod TariffUnitEnum {
/** Kilowatt Hours */
        pub const kWh: u32 = 0x00;
/** Kilovolt-amp Hours */
        pub const kVAh: u32 = 0x01;
    }
    pub mod ThreeLevelAutoEnum {
/** Automatic Level */
        pub const Auto: u32 = 0x00;
/** Low Level */
        pub const Low: u32 = 0x01;
/** Medium Level */
        pub const Medium: u32 = 0x02;
/** High Level */
        pub const High: u32 = 0x03;
    }
    pub mod WebRTCEndReasonEnum {
/** No media connection could be established to the other party */
        pub const ICEFailed: u32 = 0x00;
/** The call timed out whilst waiting for ICE candidate gathering to complete */
        pub const ICETimeout: u32 = 0x01;
/** The user chose to end the call */
        pub const UserHangup: u32 = 0x02;
/** The remote party is busy */
        pub const UserBusy: u32 = 0x03;
/** The call was replaced by another call */
        pub const Replaced: u32 = 0x04;
/** An error code when there is no local mic/camera to use. This may be because the hardware isn't plugged in, or the user has explicitly denied access */
        pub const NoUserMedia: u32 = 0x05;
/** The call timed out whilst waiting for the offer/answer step to complete */
        pub const InviteTimeout: u32 = 0x06;
/** The call was answered from a different device */
        pub const AnsweredElsewhere: u32 = 0x07;
/** The was unable to continue due to not enough resources or available streams */
        pub const OutOfResources: u32 = 0x08;
/** The call ended due to a media timeout */
        pub const MediaTimeout: u32 = 0x09;
/** The call ended due to hitting a low power condition */
        pub const LowPower: u32 = 0x0A;
/** The call ended due to the camera being set into a privacy mode. */
        pub const PrivacyMode: u32 = 0x0B;
/** Unknown or unspecified reason */
        pub const UnknownReason: u32 = 0x0C;
    }
    pub mod WildcardPathFlagsBitmap {
/** Skip the Root Node endpoint (endpoint 0) during wildcard expansion. */
        pub const WildcardSkipRootNode: u32 = 0x01;
/** Skip several large global attributes during wildcard expansion. */
        pub const WildcardSkipGlobalAttributes: u32 = 0x02;
/** Skip the AttributeList global attribute during wildcard expansion. */
        pub const WildcardSkipAttributeList: u32 = 0x04;
        pub const DoNotUse: u32 = 0x08;
/** Skip the AcceptedCommandList and GeneratedCommandList global attributes during wildcard expansion. */
        pub const WildcardSkipCommandLists: u32 = 0x10;
/** Skip any manufacturer-specific clusters or attributes during wildcard expansion. */
        pub const WildcardSkipCustomElements: u32 = 0x20;
/** Skip any Fixed (F) quality attributes during wildcard expansion. */
        pub const WildcardSkipFixedAttributes: u32 = 0x40;
/** Skip any Changes Omitted ++(C)++ quality attributes during wildcard expansion. */
        pub const WildcardSkipChangesOmittedAttributes: u32 = 0x80;
/** Skip all clusters with the Diagnostics (K) quality during wildcard expansion. */
        pub const WildcardSkipDiagnosticsClusters: u32 = 0x100;
    }
}
/** An interface to a generic way to secure a door */
pub mod DoorLock {
    pub mod AlarmCodeEnum {
/** Locking Mechanism Jammed */
        pub const LockJammed: u32 = 0x00;
/** Lock Reset to Factory Defaults */
        pub const LockFactoryReset: u32 = 0x01;
/** Lock Radio Power Cycled */
        pub const LockRadioPowerCycled: u32 = 0x03;
/** Tamper Alarm - wrong code entry limit */
        pub const WrongCodeEntryLimit: u32 = 0x04;
/** Tamper Alarm - front escutcheon removed from main */
        pub const FrontEsceutcheonRemoved: u32 = 0x05;
/** Forced Door Open under Door Locked Condition */
        pub const DoorForcedOpen: u32 = 0x06;
/** Door ajar */
        pub const DoorAjar: u32 = 0x07;
/** Force User SOS alarm */
        pub const ForcedUser: u32 = 0x08;
    }
    pub mod CredentialRuleEnum {
/** Only one credential is required for lock operation */
        pub const Single: u32 = 0x00;
/** Any two credentials are required for lock operation */
        pub const Dual: u32 = 0x01;
/** Any three credentials are required for lock operation */
        pub const Tri: u32 = 0x02;
    }
    pub mod CredentialTypeEnum {
/** Programming PIN code credential type */
        pub const ProgrammingPIN: u32 = 0x00;
/** PIN code credential type */
        pub const PIN: u32 = 0x01;
/** RFID identifier credential type */
        pub const RFID: u32 = 0x02;
/** Fingerprint identifier credential type */
        pub const Fingerprint: u32 = 0x03;
/** Finger vein identifier credential type */
        pub const FingerVein: u32 = 0x04;
/** Face identifier credential type */
        pub const Face: u32 = 0x05;
/** A Credential Issuer public key as defined in Aliro */
        pub const AliroCredentialIssuerKey: u32 = 0x06;
/** An Endpoint public key as defined in Aliro which can be evicted if space is needed for another endpoint key */
        pub const AliroEvictableEndpointKey: u32 = 0x07;
/** An Endpoint public key as defined in Aliro which cannot be evicted if space is needed for another endpoint key */
        pub const AliroNonEvictableEndpointKey: u32 = 0x08;
    }
    pub mod DataOperationTypeEnum {
/** Data is being added or was added */
        pub const Add: u32 = 0x00;
/** Data is being cleared or was cleared */
        pub const Clear: u32 = 0x01;
/** Data is being modified or was modified */
        pub const Modify: u32 = 0x02;
    }
    pub mod DoorStateEnum {
/** Door state is open */
        pub const DoorOpen: u32 = 0x00;
/** Door state is closed */
        pub const DoorClosed: u32 = 0x01;
/** Door state is jammed */
        pub const DoorJammed: u32 = 0x02;
/** Door state is currently forced open */
        pub const DoorForcedOpen: u32 = 0x03;
/** Door state is invalid for unspecified reason */
        pub const DoorUnspecifiedError: u32 = 0x04;
/** Door state is ajar */
        pub const DoorAjar: u32 = 0x05;
    }
    pub mod EventTypeEnum {
/** Event type is operation */
        pub const Operation: u32 = 0x00;
/** Event type is programming */
        pub const Programming: u32 = 0x01;
/** Event type is alarm */
        pub const Alarm: u32 = 0x02;
    }
    pub mod LEDSettingEnum {
/** Never use LED for signalization */
        pub const NoLEDSignal: u32 = 0x00;
/** Use LED signalization except for access allowed events */
        pub const NoLEDSignalAccessAllowed: u32 = 0x01;
/** Use LED signalization for all events */
        pub const LEDSignalAll: u32 = 0x02;
    }
    pub mod LockDataTypeEnum {
/** Unspecified or manufacturer specific lock user data added, cleared, or modified. */
        pub const Unspecified: u32 = 0x00;
/** Lock programming PIN code was added, cleared, or modified. */
        pub const ProgrammingCode: u32 = 0x01;
/** Lock user index was added, cleared, or modified. */
        pub const UserIndex: u32 = 0x02;
/** Lock user week day schedule was added, cleared, or modified. */
        pub const WeekDaySchedule: u32 = 0x03;
/** Lock user year day schedule was added, cleared, or modified. */
        pub const YearDaySchedule: u32 = 0x04;
/** Lock holiday schedule was added, cleared, or modified. */
        pub const HolidaySchedule: u32 = 0x05;
/** Lock user PIN code was added, cleared, or modified. */
        pub const PIN: u32 = 0x06;
/** Lock user RFID code was added, cleared, or modified. */
        pub const RFID: u32 = 0x07;
/** Lock user fingerprint was added, cleared, or modified. */
        pub const Fingerprint: u32 = 0x08;
/** Lock user finger-vein information was added, cleared, or modified. */
        pub const FingerVein: u32 = 0x09;
/** Lock user face information was added, cleared, or modified. */
        pub const Face: u32 = 0x0A;
/** An Aliro credential issuer key credential was added, cleared, or modified. */
        pub const AliroCredentialIssuerKey: u32 = 0x0B;
/** An Aliro endpoint key credential which can be evicted credential was added, cleared, or modified. */
        pub const AliroEvictableEndpointKey: u32 = 0x0C;
/** An Aliro endpoint key credential which cannot be evicted was added, cleared, or modified. */
        pub const AliroNonEvictableEndpointKey: u32 = 0x0D;
    }
    pub mod LockOperationTypeEnum {
/** Lock operation */
        pub const Lock: u32 = 0x00;
/** Unlock operation */
        pub const Unlock: u32 = 0x01;
/** Triggered by keypad entry for user with User Type set to Non Access User */
        pub const NonAccessUserEvent: u32 = 0x02;
/** Triggered by using a user with UserType set to Forced User */
        pub const ForcedUserEvent: u32 = 0x03;
/** Unlatch operation */
        pub const Unlatch: u32 = 0x04;
    }
    pub mod LockStateEnum {
/** Lock state is not fully locked */
        pub const NotFullyLocked: u32 = 0x00;
/** Lock state is fully locked */
        pub const Locked: u32 = 0x01;
/** Lock state is fully unlocked */
        pub const Unlocked: u32 = 0x02;
/** Lock state is fully unlocked and the latch is pulled */
        pub const Unlatched: u32 = 0x03;
    }
    pub mod LockTypeEnum {
/** Physical lock type is dead bolt */
        pub const DeadBolt: u32 = 0x00;
/** Physical lock type is magnetic */
        pub const Magnetic: u32 = 0x01;
/** Physical lock type is other */
        pub const Other: u32 = 0x02;
/** Physical lock type is mortise */
        pub const Mortise: u32 = 0x03;
/** Physical lock type is rim */
        pub const Rim: u32 = 0x04;
/** Physical lock type is latch bolt */
        pub const LatchBolt: u32 = 0x05;
/** Physical lock type is cylindrical lock */
        pub const CylindricalLock: u32 = 0x06;
/** Physical lock type is tubular lock */
        pub const TubularLock: u32 = 0x07;
/** Physical lock type is interconnected lock */
        pub const InterconnectedLock: u32 = 0x08;
/** Physical lock type is dead latch */
        pub const DeadLatch: u32 = 0x09;
/** Physical lock type is door furniture */
        pub const DoorFurniture: u32 = 0x0A;
/** Physical lock type is euro cylinder */
        pub const Eurocylinder: u32 = 0x0B;
    }
    pub mod OperatingModeEnum {
        pub const Normal: u32 = 0x00;
        pub const Vacation: u32 = 0x01;
        pub const Privacy: u32 = 0x02;
        pub const NoRemoteLockUnlock: u32 = 0x03;
        pub const Passage: u32 = 0x04;
    }
    pub mod OperationErrorEnum {
/** Lock/unlock error caused by unknown or unspecified source */
        pub const Unspecified: u32 = 0x00;
/** Lock/unlock error caused by invalid PIN, RFID, fingerprint or other credential */
        pub const InvalidCredential: u32 = 0x01;
/** Lock/unlock error caused by disabled USER or credential */
        pub const DisabledUserDenied: u32 = 0x02;
/** Lock/unlock error caused by schedule restriction */
        pub const Restricted: u32 = 0x03;
/** Lock/unlock error caused by insufficient battery power left to safely actuate the lock */
        pub const InsufficientBattery: u32 = 0x04;
    }
    pub mod OperationSourceEnum {
/** Lock/unlock operation came from unspecified source */
        pub const Unspecified: u32 = 0x00;
/** Lock/unlock operation came from manual operation (key, thumbturn, handle, etc). */
        pub const Manual: u32 = 0x01;
/** Lock/unlock operation came from proprietary remote source (e.g. vendor app/cloud) */
        pub const ProprietaryRemote: u32 = 0x02;
/** Lock/unlock operation came from keypad */
        pub const Keypad: u32 = 0x03;
/** Lock/unlock operation came from lock automatically (e.g. relock timer) */
        pub const Auto: u32 = 0x04;
/** Lock/unlock operation came from lock button (e.g. one touch or button) */
        pub const Button: u32 = 0x05;
/** Lock/unlock operation came from lock due to a schedule */
        pub const Schedule: u32 = 0x06;
/** Lock/unlock operation came from remote node */
        pub const Remote: u32 = 0x07;
/** Lock/unlock operation came from RFID card */
        pub const RFID: u32 = 0x08;
/** Lock/unlock operation came from biometric source (e.g. face, fingerprint/fingervein) */
        pub const Biometric: u32 = 0x09;
/** Lock/unlock operation came from an interaction defined in Aliro, or user change operation was a step-up credential provisioning as defined in Aliro */
        pub const Aliro: u32 = 0x0A;
    }
    pub mod SoundVolumeEnum {
/** Silent Mode */
        pub const Silent: u32 = 0x00;
/** Low Volume */
        pub const Low: u32 = 0x01;
/** High Volume */
        pub const High: u32 = 0x02;
/** Medium Volume */
        pub const Medium: u32 = 0x03;
    }
    pub mod StatusCodeEnum {
/** Entry would cause a duplicate credential/ID. */
        pub const DUPLICATE: u32 = 0x02;
/** Entry would replace an occupied slot. */
        pub const OCCUPIED: u32 = 0x03;
    }
    pub mod UserStatusEnum {
/** The user ID is available */
        pub const Available: u32 = 0x00;
/** The user ID is occupied and enabled */
        pub const OccupiedEnabled: u32 = 0x01;
/** The user ID is occupied and disabled */
        pub const OccupiedDisabled: u32 = 0x03;
    }
    pub mod UserTypeEnum {
/** The user ID type is unrestricted */
        pub const UnrestrictedUser: u32 = 0x00;
/** The user ID type is schedule */
        pub const YearDayScheduleUser: u32 = 0x01;
/** The user ID type is schedule */
        pub const WeekDayScheduleUser: u32 = 0x02;
/** The user ID type is programming */
        pub const ProgrammingUser: u32 = 0x03;
/** The user ID type is non access */
        pub const NonAccessUser: u32 = 0x04;
/** The user ID type is forced */
        pub const ForcedUser: u32 = 0x05;
/** The user ID type is disposable */
        pub const DisposableUser: u32 = 0x06;
/** The user ID type is expiring */
        pub const ExpiringUser: u32 = 0x07;
/** The user ID type is schedule restricted */
        pub const ScheduleRestrictedUser: u32 = 0x08;
/** The user ID type is remote only */
        pub const RemoteOnlyUser: u32 = 0x09;
    }
    pub mod AlarmMaskBitmap {
/** Locking Mechanism Jammed */
        pub const LockJammed: u32 = 0x01;
/** Lock Reset to Factory Defaults */
        pub const LockFactoryReset: u32 = 0x02;
/** RF Module Power Cycled */
        pub const LockRadioPowerCycled: u32 = 0x08;
/** Tamper Alarm - wrong code entry limit */
        pub const WrongCodeEntryLimit: u32 = 0x10;
/** Tamper Alarm - front escutcheon removed from main */
        pub const FrontEscutcheonRemoved: u32 = 0x20;
/** Forced Door Open under Door Locked Condition */
        pub const DoorForcedOpen: u32 = 0x40;
    }
    pub mod ConfigurationRegisterBitmap {
/** The state of local programming functionality */
        pub const LocalProgramming: u32 = 0x01;
/** The state of the keypad interface */
        pub const KeypadInterface: u32 = 0x02;
/** The state of the remote interface */
        pub const RemoteInterface: u32 = 0x04;
/** Sound volume is set to Silent value */
        pub const SoundVolume: u32 = 0x20;
/** Auto relock time it set to 0 */
        pub const AutoRelockTime: u32 = 0x40;
/** LEDs is disabled */
        pub const LEDSettings: u32 = 0x80;
    }
    pub mod CredentialRulesBitmap {
/** Only one credential is required for lock operation */
        pub const Single: u32 = 0x01;
/** Any two credentials are required for lock operation */
        pub const Dual: u32 = 0x02;
/** Any three credentials are required for lock operation */
        pub const Tri: u32 = 0x04;
    }
    pub mod DaysMaskBitmap {
/** Schedule is applied on Sunday */
        pub const Sunday: u32 = 0x01;
/** Schedule is applied on Monday */
        pub const Monday: u32 = 0x02;
/** Schedule is applied on Tuesday */
        pub const Tuesday: u32 = 0x04;
/** Schedule is applied on Wednesday */
        pub const Wednesday: u32 = 0x08;
/** Schedule is applied on Thursday */
        pub const Thursday: u32 = 0x10;
/** Schedule is applied on Friday */
        pub const Friday: u32 = 0x20;
/** Schedule is applied on Saturday */
        pub const Saturday: u32 = 0x40;
    }
    pub mod LocalProgrammingFeaturesBitmap {
/** The state of the ability to add users, credentials or schedules on the device */
        pub const AddUsersCredentialsSchedules: u32 = 0x01;
/** The state of the ability to modify users, credentials or schedules on the device */
        pub const ModifyUsersCredentialsSchedules: u32 = 0x02;
/** The state of the ability to clear users, credentials or schedules on the device */
        pub const ClearUsersCredentialsSchedules: u32 = 0x04;
/** The state of the ability to adjust settings on the device */
        pub const AdjustSettings: u32 = 0x08;
    }
    pub mod OperatingModesBitmap {
/** Normal operation mode */
        pub const Normal: u32 = 0x01;
/** Vacation operation mode */
        pub const Vacation: u32 = 0x02;
/** Privacy operation mode */
        pub const Privacy: u32 = 0x04;
/** No remote lock and unlock operation mode */
        pub const NoRemoteLockUnlock: u32 = 0x08;
/** Passage operation mode */
        pub const Passage: u32 = 0x10;
    }
}
/** The Camera AV Stream Management cluster is used to allow clients to manage, control, and configure various audio, video, and snapshot streams on a camera. */
pub mod CameraAVStreamManagement {
    pub mod AudioCodecEnum {
/** Open source IETF standard codec. */
        pub const OPUS: u32 = 0x00;
/** Advanced Audio Coding codec-Low Complexity */
        pub const AACLC: u32 = 0x01;
    }
    pub mod ImageCodecEnum {
/** JPEG image codec. */
        pub const JPEG: u32 = 0x00;
/** HEIC image codec. */
        pub const HEIC: u32 = 0x01;
    }
    pub mod TriStateAutoEnum {
/** Off */
        pub const Off: u32 = 0x00;
/** On */
        pub const On: u32 = 0x01;
/** Automatic Operation */
        pub const Auto: u32 = 0x02;
    }
    pub mod TwoWayTalkSupportTypeEnum {
/** Two-way Talk support is absent. */
        pub const NotSupported: u32 = 0x00;
/** Audio in one direction at a time. */
        pub const HalfDuplex: u32 = 0x01;
/** Audio in both directions simultaneously. */
        pub const FullDuplex: u32 = 0x02;
    }
    pub mod VideoCodecEnum {
/** Advanced Video Coding (H.264) codec. */
        pub const H264: u32 = 0x00;
/** High efficiency Video Coding (H.265) codec. */
        pub const HEVC: u32 = 0x01;
/** Versatile Video Coding (H.266) codec. */
        pub const VVC: u32 = 0x02;
/** AOMedia Video 1 codec. */
        pub const AV1: u32 = 0x03;
    }
}
/** An instance of the Joint Fabric Administrator Cluster only applies to Joint Fabric Administrator nodes fulfilling the role of Anchor CA. */
pub mod JointFabricAdministrator {
    pub mod ICACResponseStatusEnum {
/** No error */
        pub const OK: u32 = 0x00;
/** Public Key in the ICAC is invalid */
        pub const InvalidPublicKey: u32 = 0x01;
/** ICAC chain validation failed / ICAC DN Encoding rules verification failed */
        pub const InvalidICAC: u32 = 0x02;
    }
    pub mod StatusCodeEnum {
/** Could not be completed because another commissioning is in progress */
        pub const Busy: u32 = 0x02;
/** Provided PAKE parameters were incorrectly formatted or otherwise invalid */
        pub const PAKEParameterError: u32 = 0x03;
/** No commissioning window was currently open */
        pub const WindowNotOpen: u32 = 0x04;
/** ICACCSRRequest command has been invoked by a peer against which Fabric Table VID Verification hasn't been executed */
        pub const VIDNotVerified: u32 = 0x05;
/** OpenJointCommissioningWindow command has been invoked but the AdministratorFabricIndex field has the value of null */
        pub const InvalidAdministratorFabricIndex: u32 = 0x06;
    }
    pub mod TransferAnchorResponseStatusEnum {
/** No error */
        pub const OK: u32 = 0x00;
/** Anchor Transfer was not started due to on-going Datastore operations */
        pub const TransferAnchorStatusDatastoreBusy: u32 = 0x01;
/** User has not consented for Anchor Transfer */
        pub const TransferAnchorStatusNoUserConsent: u32 = 0x02;
    }
}
/** This cluster supports remotely monitoring and, where supported, changing the operational state of a Robotic Vacuum. */
pub mod RVCOperationalState {
    pub mod ErrorStateEnum {
/** The device is not in an error state */
        pub const NoError: u32 = 0x00;
/** The device is unable to start or resume operation */
        pub const UnableToStartOrResume: u32 = 0x01;
/** The device was unable to complete the current operation */
        pub const UnableToCompleteOperation: u32 = 0x02;
/** The device cannot process the command in its current state */
        pub const CommandInvalidInState: u32 = 0x03;
/** The device has failed to find or reach the charging dock */
        pub const FailedToFindChargingDock: u32 = 0x40;
/** The device is stuck and requires manual intervention */
        pub const Stuck: u32 = 0x41;
/** The device has detected that its dust bin is missing */
        pub const DustBinMissing: u32 = 0x42;
/** The device has detected that its dust bin is full */
        pub const DustBinFull: u32 = 0x43;
/** The device has detected that its clean water tank is empty */
        pub const WaterTankEmpty: u32 = 0x44;
/** The device has detected that its clean water tank is missing */
        pub const WaterTankMissing: u32 = 0x45;
/** The device has detected that its water tank lid is open */
        pub const WaterTankLidOpen: u32 = 0x46;
/** The device has detected that its cleaning pad is missing */
        pub const MopCleaningPadMissing: u32 = 0x47;
/** The device is unable to start or to continue operating due to a low battery */
        pub const LowBattery: u32 = 0x48;
/** The device is unable to move to an area where it was asked to operate, such as by setting the ServiceArea cluster's SelectedAreas attribute, due to an obstruction. For example, the obstruction might be a closed door or objects blocking the mapped path. */
        pub const CannotReachTargetArea: u32 = 0x49;
/** The device has detected that its dirty water tank is full */
        pub const DirtyWaterTankFull: u32 = 0x4A;
/** The device has detected that its dirty water tank is missing */
        pub const DirtyWaterTankMissing: u32 = 0x4B;
/** The device has detected that one or more wheels are jammed by an object */
        pub const WheelsJammed: u32 = 0x4C;
/** The device has detected that its brush is jammed by an object */
        pub const BrushJammed: u32 = 0x4D;
/** The device has detected that one of its sensors, such as LiDAR, infrared, or camera is obscured and needs to be cleaned */
        pub const NavigationSensorObscured: u32 = 0x4E;
    }
    pub mod OperationalStateEnum {
/** The device is stopped */
        pub const Stopped: u32 = 0x00;
/** The device is operating */
        pub const Running: u32 = 0x01;
/** The device is paused during an operation */
        pub const Paused: u32 = 0x02;
/** The device is in an error state */
        pub const Error: u32 = 0x03;
/** The device is en route to the charging dock */
        pub const SeekingCharger: u32 = 0x40;
/** The device is charging */
        pub const Charging: u32 = 0x41;
/** The device is on the dock, not charging */
        pub const Docked: u32 = 0x42;
/** The device is automatically emptying its own dust bin, such as to a dock */
        pub const EmptyingDustBin: u32 = 0x43;
/** The device is automatically cleaning its own mopping device, such as on a dock */
        pub const CleaningMop: u32 = 0x44;
/** The device is automatically filling its own clean water tank for use when mopping, such as from a dock */
        pub const FillingWaterTank: u32 = 0x45;
/** The device is processing acquired data to update its maps */
        pub const UpdatingMaps: u32 = 0x46;
    }
}
/** This cluster supports remotely monitoring and controlling the different types of functionality available to a washing device, such as a washing machine. */
pub mod LaundryWasherControls {
    pub mod NumberOfRinsesEnum {
/** This laundry washer mode does not perform rinse cycles */
        pub const None: u32 = 0x00;
/** This laundry washer mode performs normal rinse cycles determined by the manufacturer */
        pub const Normal: u32 = 0x01;
/** This laundry washer mode performs an extra rinse cycle */
        pub const Extra: u32 = 0x02;
/** This laundry washer mode performs the maximum number of rinse cycles determined by the manufacturer */
        pub const Max: u32 = 0x03;
    }
}
/** This cluster provides an interface for controlling a device like a TV using action commands such as UP, DOWN, and SELECT. */
pub mod KeypadInput {
    pub mod CecKeyCodeEnum {
        pub const Select: u32 = 0x00;
        pub const Up: u32 = 0x01;
        pub const Down: u32 = 0x02;
        pub const Left: u32 = 0x03;
        pub const Right: u32 = 0x04;
        pub const RightUp: u32 = 0x05;
        pub const RightDown: u32 = 0x06;
        pub const LeftUp: u32 = 0x07;
        pub const LeftDown: u32 = 0x08;
        pub const RootMenu: u32 = 0x09;
        pub const SetupMenu: u32 = 0x0A;
        pub const ContentsMenu: u32 = 0x0B;
        pub const FavoriteMenu: u32 = 0x0C;
        pub const Exit: u32 = 0x0D;
        pub const MediaTopMenu: u32 = 0x10;
        pub const MediaContextSensitiveMenu: u32 = 0x11;
        pub const NumberEntryMode: u32 = 0x1D;
        pub const Number11: u32 = 0x1E;
        pub const Number12: u32 = 0x1F;
        pub const Number0OrNumber10: u32 = 0x20;
        pub const Numbers1: u32 = 0x21;
        pub const Numbers2: u32 = 0x22;
        pub const Numbers3: u32 = 0x23;
        pub const Numbers4: u32 = 0x24;
        pub const Numbers5: u32 = 0x25;
        pub const Numbers6: u32 = 0x26;
        pub const Numbers7: u32 = 0x27;
        pub const Numbers8: u32 = 0x28;
        pub const Numbers9: u32 = 0x29;
        pub const Dot: u32 = 0x2A;
        pub const Enter: u32 = 0x2B;
        pub const Clear: u32 = 0x2C;
        pub const NextFavorite: u32 = 0x2F;
        pub const ChannelUp: u32 = 0x30;
        pub const ChannelDown: u32 = 0x31;
        pub const PreviousChannel: u32 = 0x32;
        pub const SoundSelect: u32 = 0x33;
        pub const InputSelect: u32 = 0x34;
        pub const DisplayInformation: u32 = 0x35;
        pub const Help: u32 = 0x36;
        pub const PageUp: u32 = 0x37;
        pub const PageDown: u32 = 0x38;
        pub const Power: u32 = 0x40;
        pub const VolumeUp: u32 = 0x41;
        pub const VolumeDown: u32 = 0x42;
        pub const Mute: u32 = 0x43;
        pub const Play: u32 = 0x44;
        pub const Stop: u32 = 0x45;
        pub const Pause: u32 = 0x46;
        pub const Record: u32 = 0x47;
        pub const Rewind: u32 = 0x48;
        pub const FastForward: u32 = 0x49;
        pub const Eject: u32 = 0x4A;
        pub const Forward: u32 = 0x4B;
        pub const Backward: u32 = 0x4C;
        pub const StopRecord: u32 = 0x4D;
        pub const PauseRecord: u32 = 0x4E;
        pub const Reserved: u32 = 0x4F;
        pub const Angle: u32 = 0x50;
        pub const SubPicture: u32 = 0x51;
        pub const VideoOnDemand: u32 = 0x52;
        pub const ElectronicProgramGuide: u32 = 0x53;
        pub const TimerProgramming: u32 = 0x54;
        pub const InitialConfiguration: u32 = 0x55;
        pub const SelectBroadcastType: u32 = 0x56;
        pub const SelectSoundPresentation: u32 = 0x57;
        pub const PlayFunction: u32 = 0x60;
        pub const PausePlayFunction: u32 = 0x61;
        pub const RecordFunction: u32 = 0x62;
        pub const PauseRecordFunction: u32 = 0x63;
        pub const StopFunction: u32 = 0x64;
        pub const MuteFunction: u32 = 0x65;
        pub const RestoreVolumeFunction: u32 = 0x66;
        pub const TuneFunction: u32 = 0x67;
        pub const SelectMediaFunction: u32 = 0x68;
        pub const SelectAvInputFunction: u32 = 0x69;
        pub const SelectAudioInputFunction: u32 = 0x6A;
        pub const PowerToggleFunction: u32 = 0x6B;
        pub const PowerOffFunction: u32 = 0x6C;
        pub const PowerOnFunction: u32 = 0x6D;
        pub const F1Blue: u32 = 0x71;
        pub const F2Red: u32 = 0x72;
        pub const F3Green: u32 = 0x73;
        pub const F4Yellow: u32 = 0x74;
        pub const F5: u32 = 0x75;
        pub const Data: u32 = 0x76;
    }
    pub mod StatusEnum {
/** Succeeded */
        pub const Success: u32 = 0x00;
/** Key code is not supported. */
        pub const UnsupportedKey: u32 = 0x01;
/** Requested key code is invalid in the context of the responder's current state. */
        pub const InvalidKeyInCurrentState: u32 = 0x02;
    }
}
/** Attributes and commands for group configuration and manipulation. */
pub mod Groups {
    pub mod NameSupportBitmap {
/** The ability to store a name for a group. */
        pub const GroupNames: u32 = 0x80;
    }
}
/** This cluster provides an interface to reflect and control a closure's range of movement, usually involving a panel, by using 6-axis framework. */
pub mod ClosureDimension {
    pub mod ClosureUnitEnum {
/** Millimeter used as unit */
        pub const Millimeter: u32 = 0x00;
/** Degree used as unit */
        pub const Degree: u32 = 0x01;
    }
    pub mod ModulationTypeEnum {
/** Orientation of the slats */
        pub const SlatsOrientation: u32 = 0x00;
/** Aperture of the slats */
        pub const SlatsOpenwork: u32 = 0x01;
/** Alignment of blind stripes (Zebra) */
        pub const StripesAlignment: u32 = 0x02;
/** Opacity of a surface */
        pub const Opacity: u32 = 0x03;
/** Ventilation control */
        pub const Ventilation: u32 = 0x04;
    }
    pub mod OverflowEnum {
/** No overflow */
        pub const NoOverflow: u32 = 0x00;
/** Inside overflow */
        pub const Inside: u32 = 0x01;
/** Outside overflow */
        pub const Outside: u32 = 0x02;
/** Top inside overflow */
        pub const TopInside: u32 = 0x03;
/** Top outside overflow */
        pub const TopOutside: u32 = 0x04;
/** Bottom inside overflow */
        pub const BottomInside: u32 = 0x05;
/** Bottom outside overflow */
        pub const BottomOutside: u32 = 0x06;
/** Left inside overflow */
        pub const LeftInside: u32 = 0x07;
/** Left outside overflow */
        pub const LeftOutside: u32 = 0x08;
/** Right inside overflow */
        pub const RightInside: u32 = 0x09;
/** Right outside overflow */
        pub const RightOutside: u32 = 0x0A;
    }
    pub mod RotationAxisEnum {
/** The panel rotates around a vertical axis located on the left side of the panel */
        pub const Left: u32 = 0x00;
/** The panel rotates around a vertical axis located in the center of the panel */
        pub const CenteredVertical: u32 = 0x01;
/** The panels rotates around vertical axes located on the left and right sides of the panel */
        pub const LeftAndRight: u32 = 0x02;
/** The panel rotates around a vertical axis located on the right side of the panel */
        pub const Right: u32 = 0x03;
/** The panel rotates around a horizontal axis located on the top of the panel */
        pub const Top: u32 = 0x04;
/** The panel rotates around a horizontal axis located in the center of the panel */
        pub const CenteredHorizontal: u32 = 0x05;
/** The panels rotates around horizontal axes located on the top and bottom of the panel */
        pub const TopAndBottom: u32 = 0x06;
/** The panel rotates around a horizontal axis located on the bottom of the panel */
        pub const Bottom: u32 = 0x07;
/** The barrier tilts around an axis located at the left end of the barrier */
        pub const LeftBarrier: u32 = 0x08;
/** The dual barriers tilt around axes located at each side of the composite barrier */
        pub const LeftAndRightBarriers: u32 = 0x09;
/** The barrier tilts around an axis located at the right end of the barrier */
        pub const RightBarrier: u32 = 0x0A;
    }
    pub mod StepDirectionEnum {
/** Decrease towards 0.00% */
        pub const Decrease: u32 = 0x00;
/** Increase towards 100.00% */
        pub const Increase: u32 = 0x01;
    }
    pub mod TranslationDirectionEnum {
/** Downward translation */
        pub const Downward: u32 = 0x00;
/** Upward translation */
        pub const Upward: u32 = 0x01;
/** Vertical mask translation */
        pub const VerticalMask: u32 = 0x02;
/** Vertical symmetry translation */
        pub const VerticalSymmetry: u32 = 0x03;
/** Leftward translation */
        pub const Leftward: u32 = 0x04;
/** Rightward translation */
        pub const Rightward: u32 = 0x05;
/** Horizontal mask translation */
        pub const HorizontalMask: u32 = 0x06;
/** Horizontal symmetry translation */
        pub const HorizontalSymmetry: u32 = 0x07;
/** Forward translation */
        pub const Forward: u32 = 0x08;
/** Backward translation */
        pub const Backward: u32 = 0x09;
/** Depth mask translation */
        pub const DepthMask: u32 = 0x0A;
/** Depth symmetry translation */
        pub const DepthSymmetry: u32 = 0x0B;
    }
    pub mod LatchControlModesBitmap {
/** Remote latching capability */
        pub const RemoteLatching: u32 = 0x01;
/** Remote unlatching capability */
        pub const RemoteUnlatching: u32 = 0x02;
    }
}
/** Attributes and commands for configuring the Refrigerator alarm. */
pub mod RefrigeratorAlarm {
    pub mod AlarmBitmap {
/** The cabinet's door has been open for a vendor defined amount of time. */
        pub const DoorOpen: u32 = 0x01;
    }
}
/** An interface for configuring the user interface of a thermostat (which may be remote from the thermostat). */
pub mod ThermostatUserInterfaceConfiguration {
    pub mod KeypadLockoutEnum {
/** All functionality available to the user */
        pub const NoLockout: u32 = 0x00;
/** Level 1 reduced functionality */
        pub const Lockout1: u32 = 0x01;
/** Level 2 reduced functionality */
        pub const Lockout2: u32 = 0x02;
/** Level 3 reduced functionality */
        pub const Lockout3: u32 = 0x03;
/** Level 4 reduced functionality */
        pub const Lockout4: u32 = 0x04;
/** Least functionality available to the user */
        pub const Lockout5: u32 = 0x05;
    }
    pub mod ScheduleProgrammingVisibilityEnum {
/** Local schedule programming functionality is enabled at the thermostat */
        pub const ScheduleProgrammingPermitted: u32 = 0x00;
/** Local schedule programming functionality is disabled at the thermostat */
        pub const ScheduleProgrammingDenied: u32 = 0x01;
    }
    pub mod TemperatureDisplayModeEnum {
/** Temperature displayed in °C */
        pub const Celsius: u32 = 0x00;
/** Temperature displayed in °F */
        pub const Fahrenheit: u32 = 0x01;
    }
}
/** This cluster provides an interface for controlling the Input Selector on a media device such as a TV. */
pub mod MediaInput {
    pub mod InputTypeEnum {
/** Indicates content not coming from a physical input. */
        pub const Internal: u32 = 0x00;
        pub const Aux: u32 = 0x01;
        pub const Coax: u32 = 0x02;
        pub const Composite: u32 = 0x03;
        pub const HDMI: u32 = 0x04;
        pub const Input: u32 = 0x05;
        pub const Line: u32 = 0x06;
        pub const Optical: u32 = 0x07;
        pub const Video: u32 = 0x08;
        pub const SCART: u32 = 0x09;
        pub const USB: u32 = 0x0A;
        pub const Other: u32 = 0x0B;
    }
}
/** The server cluster provides an interface to occupancy sensing functionality based on one or more sensing modalities, including configuration and provision of notifications of occupancy status. */
pub mod OccupancySensing {
    pub mod OccupancySensorTypeEnum {
/** Indicates a passive infrared sensor. */
        pub const PIR: u32 = 0x00;
/** Indicates a ultrasonic sensor. */
        pub const Ultrasonic: u32 = 0x01;
/** Indicates a passive infrared and ultrasonic sensor. */
        pub const PIRAndUltrasonic: u32 = 0x02;
/** Indicates a physical contact sensor. */
        pub const PhysicalContact: u32 = 0x03;
    }
    pub mod OccupancyBitmap {
/** Indicates the sensed occupancy state */
        pub const Occupied: u32 = 0x01;
    }
    pub mod OccupancySensorTypeBitmap {
/** Indicates a passive infrared sensor. */
        pub const PIR: u32 = 0x01;
/** Indicates a ultrasonic sensor. */
        pub const Ultrasonic: u32 = 0x02;
/** Indicates a physical contact sensor. */
        pub const PhysicalContact: u32 = 0x04;
    }
}
/** The CommodityTariffCluster provides the mechanism for communicating Commodity Tariff information within the premises. */
pub mod CommodityTariff {
    pub mod AuxiliaryLoadSettingEnum {
/** The switch should be in the OFF state */
        pub const Off: u32 = 0x00;
/** The switch should be in the ON state */
        pub const On: u32 = 0x01;
/** No state is required */
        pub const None: u32 = 0x02;
    }
    pub mod BlockModeEnum {
/** Tariff has no usage blocks */
        pub const NoBlock: u32 = 0x00;
/** Usage is metered in combined blocks */
        pub const Combined: u32 = 0x01;
/** Usage is metered separately by tariff component */
        pub const Individual: u32 = 0x02;
    }
    pub mod DayEntryRandomizationTypeEnum {
/** No randomization applied */
        pub const None: u32 = 0x00;
/** An unchanging offset */
        pub const Fixed: u32 = 0x01;
/** A random value */
        pub const Random: u32 = 0x02;
/** A random positive value */
        pub const RandomPositive: u32 = 0x03;
/** A random negative value */
        pub const RandomNegative: u32 = 0x04;
    }
    pub mod DayTypeEnum {
/** Standard */
        pub const Standard: u32 = 0x00;
/** Holiday */
        pub const Holiday: u32 = 0x01;
/** Dynamic Pricing */
        pub const Dynamic: u32 = 0x02;
/** Individual Events */
        pub const Event: u32 = 0x03;
    }
    pub mod PeakPeriodSeverityEnum {
/** Unused */
        pub const Unused: u32 = 0x00;
/** Low */
        pub const Low: u32 = 0x01;
/** Medium */
        pub const Medium: u32 = 0x02;
/** High */
        pub const High: u32 = 0x03;
    }
    pub mod DayPatternDayOfWeekBitmap {
/** Sunday */
        pub const Sunday: u32 = 0x01;
/** Monday */
        pub const Monday: u32 = 0x02;
/** Tuesday */
        pub const Tuesday: u32 = 0x04;
/** Wednesday */
        pub const Wednesday: u32 = 0x08;
/** Thursday */
        pub const Thursday: u32 = 0x10;
/** Friday */
        pub const Friday: u32 = 0x20;
/** Saturday */
        pub const Saturday: u32 = 0x40;
    }
}
/** An interface for configuring and controlling the functionality of a thermostat. */
pub mod Thermostat {
    pub mod ACCapacityFormatEnum {
/** British Thermal Unit per Hour */
        pub const BTUh: u32 = 0x00;
    }
    pub mod ACCompressorTypeEnum {
/** Unknown compressor type */
        pub const Unknown: u32 = 0x00;
/** Max working ambient 43 °C */
        pub const T1: u32 = 0x01;
/** Max working ambient 35 °C */
        pub const T2: u32 = 0x02;
/** Max working ambient 52 °C */
        pub const T3: u32 = 0x03;
    }
    pub mod ACLouverPositionEnum {
/** Fully Closed */
        pub const Closed: u32 = 0x01;
/** Fully Open */
        pub const Open: u32 = 0x02;
/** Quarter Open */
        pub const Quarter: u32 = 0x03;
/** Half Open */
        pub const Half: u32 = 0x04;
/** Three Quarters Open */
        pub const ThreeQuarters: u32 = 0x05;
    }
    pub mod ACRefrigerantTypeEnum {
/** Unknown Refrigerant Type */
        pub const Unknown: u32 = 0x00;
/** R22 Refrigerant */
        pub const R22: u32 = 0x01;
/** R410a Refrigerant */
        pub const R410a: u32 = 0x02;
/** R407c Refrigerant */
        pub const R407c: u32 = 0x03;
    }
    pub mod ACTypeEnum {
/** Unknown AC Type */
        pub const Unknown: u32 = 0x00;
/** Cooling and Fixed Speed */
        pub const CoolingFixed: u32 = 0x01;
/** Heat Pump and Fixed Speed */
        pub const HeatPumpFixed: u32 = 0x02;
/** Cooling and Inverter */
        pub const CoolingInverter: u32 = 0x03;
/** Heat Pump and Inverter */
        pub const HeatPumpInverter: u32 = 0x04;
    }
    pub mod ControlSequenceOfOperationEnum {
/** Heat and Emergency are not possible */
        pub const CoolingOnly: u32 = 0x00;
/** Heat and Emergency are not possible */
        pub const CoolingWithReheat: u32 = 0x01;
/** Cool and precooling (see Terms) are not possible */
        pub const HeatingOnly: u32 = 0x02;
/** Cool and precooling are not possible */
        pub const HeatingWithReheat: u32 = 0x03;
/** All modes are possible */
        pub const CoolingAndHeating: u32 = 0x04;
/** All modes are possible */
        pub const CoolingAndHeatingWithReheat: u32 = 0x05;
    }
    pub mod PresetScenarioEnum {
/** The thermostat-controlled area is occupied */
        pub const Occupied: u32 = 0x01;
/** The thermostat-controlled area is unoccupied */
        pub const Unoccupied: u32 = 0x02;
/** Users are likely to be sleeping */
        pub const Sleep: u32 = 0x03;
/** Users are likely to be waking up */
        pub const Wake: u32 = 0x04;
/** Users are on vacation */
        pub const Vacation: u32 = 0x05;
/** Users are likely to be going to sleep */
        pub const GoingToSleep: u32 = 0x06;
/** Custom presets */
        pub const UserDefined: u32 = 0xFE;
    }
    pub mod SetpointChangeSourceEnum {
/** Manual, user-initiated setpoint change via the thermostat */
        pub const Manual: u32 = 0x00;
/** Schedule/internal programming-initiated setpoint change */
        pub const Schedule: u32 = 0x01;
/** Externally-initiated setpoint change (e.g., DRLC cluster command, attribute write) */
        pub const External: u32 = 0x02;
    }
    pub mod SetpointRaiseLowerModeEnum {
/** Adjust Heat Setpoint */
        pub const Heat: u32 = 0x00;
/** Adjust Cool Setpoint */
        pub const Cool: u32 = 0x01;
/** Adjust Heat Setpoint and Cool Setpoint */
        pub const Both: u32 = 0x02;
    }
    pub mod StartOfWeekEnum {
        pub const Sunday: u32 = 0x00;
        pub const Monday: u32 = 0x01;
        pub const Tuesday: u32 = 0x02;
        pub const Wednesday: u32 = 0x03;
        pub const Thursday: u32 = 0x04;
        pub const Friday: u32 = 0x05;
        pub const Saturday: u32 = 0x06;
    }
    pub mod SystemModeEnum {
/** The Thermostat does not generate demand for Cooling or Heating */
        pub const Off: u32 = 0x00;
/** Demand is generated for either Cooling or Heating, as required */
        pub const Auto: u32 = 0x01;
/** Demand is only generated for Cooling */
        pub const Cool: u32 = 0x03;
/** Demand is only generated for Heating */
        pub const Heat: u32 = 0x04;
/** 2nd stage heating is in use to achieve desired temperature */
        pub const EmergencyHeat: u32 = 0x05;
/** (see Terms) */
        pub const Precooling: u32 = 0x06;
        pub const FanOnly: u32 = 0x07;
        pub const Dry: u32 = 0x08;
        pub const Sleep: u32 = 0x09;
    }
    pub mod TemperatureSetpointHoldEnum {
/** Follow scheduling program */
        pub const SetpointHoldOff: u32 = 0x00;
/** Maintain current setpoint, regardless of schedule transitions */
        pub const SetpointHoldOn: u32 = 0x01;
    }
    pub mod ThermostatRunningModeEnum {
/** The Thermostat does not generate demand for Cooling or Heating */
        pub const Off: u32 = 0x00;
/** Demand is only generated for Cooling */
        pub const Cool: u32 = 0x03;
/** Demand is only generated for Heating */
        pub const Heat: u32 = 0x04;
    }
    pub mod ACErrorCodeBitmap {
/** Compressor Failure or Refrigerant Leakage */
        pub const CompressorFail: u32 = 0x01;
/** Room Temperature Sensor Failure */
        pub const RoomSensorFail: u32 = 0x02;
/** Outdoor Temperature Sensor Failure */
        pub const OutdoorSensorFail: u32 = 0x04;
/** Indoor Coil Temperature Sensor Failure */
        pub const CoilSensorFail: u32 = 0x08;
/** Fan Failure */
        pub const FanFail: u32 = 0x10;
    }
    pub mod OccupancyBitmap {
/** Indicates the occupancy state */
        pub const Occupied: u32 = 0x01;
    }
    pub mod PresetTypeFeaturesBitmap {
/** Preset may be automatically activated by the thermostat */
        pub const Automatic: u32 = 0x01;
/** Preset supports user-provided names */
        pub const SupportsNames: u32 = 0x02;
    }
    pub mod ProgrammingOperationModeBitmap {
/** Schedule programming mode. This enables any programmed weekly schedule configurations. */
        pub const ScheduleActive: u32 = 0x01;
/** Auto/recovery mode */
        pub const AutoRecovery: u32 = 0x02;
/** Economy/EnergyStar mode */
        pub const Economy: u32 = 0x04;
    }
    pub mod RelayStateBitmap {
/** Heat Stage On */
        pub const Heat: u32 = 0x01;
/** Cool Stage On */
        pub const Cool: u32 = 0x02;
/** Fan Stage On */
        pub const Fan: u32 = 0x04;
/** Heat 2nd Stage On */
        pub const HeatStage2: u32 = 0x08;
/** Cool 2nd Stage On */
        pub const CoolStage2: u32 = 0x10;
/** Fan 2nd Stage On */
        pub const FanStage2: u32 = 0x20;
/** Fan 3rd Stage On */
        pub const FanStage3: u32 = 0x40;
    }
    pub mod RemoteSensingBitmap {
/** Calculated Local Temperature is derived from a remote node */
        pub const LocalTemperature: u32 = 0x01;
/** OutdoorTemperature is derived from a remote node */
        pub const OutdoorTemperature: u32 = 0x02;
/** Occupancy is derived from a remote node */
        pub const Occupancy: u32 = 0x04;
    }
    pub mod ScheduleDayOfWeekBitmap {
/** Sunday */
        pub const Sunday: u32 = 0x01;
/** Monday */
        pub const Monday: u32 = 0x02;
/** Tuesday */
        pub const Tuesday: u32 = 0x04;
/** Wednesday */
        pub const Wednesday: u32 = 0x08;
/** Thursday */
        pub const Thursday: u32 = 0x10;
/** Friday */
        pub const Friday: u32 = 0x20;
/** Saturday */
        pub const Saturday: u32 = 0x40;
/** Away or Vacation */
        pub const Away: u32 = 0x80;
    }
    pub mod ScheduleModeBitmap {
/** Adjust Heat Setpoint */
        pub const HeatSetpointPresent: u32 = 0x01;
/** Adjust Cool Setpoint */
        pub const CoolSetpointPresent: u32 = 0x02;
    }
    pub mod ScheduleTypeFeaturesBitmap {
/** Supports presets */
        pub const SupportsPresets: u32 = 0x01;
/** Supports setpoints */
        pub const SupportsSetpoints: u32 = 0x02;
/** Supports user-provided names */
        pub const SupportsNames: u32 = 0x04;
/** Supports transitioning to SystemModeOff */
        pub const SupportsOff: u32 = 0x08;
    }
}
/** This cluster provides an interface for controlling the current Channel on a device. */
pub mod Channel {
    pub mod ChannelTypeEnum {
/** The channel is sourced from a satellite provider. */
        pub const Satellite: u32 = 0x00;
/** The channel is sourced from a cable provider. */
        pub const Cable: u32 = 0x01;
/** The channel is sourced from a terrestrial provider. */
        pub const Terrestrial: u32 = 0x02;
/** The channel is sourced from an OTT provider. */
        pub const OTT: u32 = 0x03;
    }
    pub mod LineupInfoTypeEnum {
/** Multi System Operator */
        pub const MSO: u32 = 0x00;
    }
    pub mod StatusEnum {
/** Command succeeded */
        pub const Success: u32 = 0x00;
/** More than one equal match for the ChannelInfoStruct passed in. */
        pub const MultipleMatches: u32 = 0x01;
/** No matches for the ChannelInfoStruct passed in. */
        pub const NoMatches: u32 = 0x02;
    }
    pub mod RecordingFlagBitmap {
/** The program is scheduled for recording. */
        pub const Scheduled: u32 = 0x01;
/** The program series is scheduled for recording. */
        pub const RecordSeries: u32 = 0x02;
/** The program is recorded and available to be played. */
        pub const Recorded: u32 = 0x04;
    }
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod OvenMode {
    pub mod ModeTag {
        pub const Auto: u32 = 0x00;
        pub const Quick: u32 = 0x01;
        pub const Quiet: u32 = 0x02;
        pub const LowNoise: u32 = 0x03;
        pub const LowEnergy: u32 = 0x04;
        pub const Vacation: u32 = 0x05;
        pub const Min: u32 = 0x06;
        pub const Max: u32 = 0x07;
        pub const Night: u32 = 0x08;
        pub const Day: u32 = 0x09;
        pub const Bake: u32 = 0x4000;
        pub const Convection: u32 = 0x4001;
        pub const Grill: u32 = 0x4002;
        pub const Roast: u32 = 0x4003;
        pub const Clean: u32 = 0x4004;
        pub const ConvectionBake: u32 = 0x4005;
        pub const ConvectionRoast: u32 = 0x4006;
        pub const Warming: u32 = 0x4007;
        pub const Proofing: u32 = 0x4008;
        pub const Steam: u32 = 0x4009;
        pub const AirFry: u32 = 0x400A;
        pub const AirSousVide: u32 = 0x400B;
        pub const FrozenFood: u32 = 0x400C;
    }
}
/** This cluster allows a client to manage the power draw of a device. An example of such a client could be an Energy Management System (EMS) which controls an Energy Smart Appliance (ESA). */
pub mod DeviceEnergyManagement {
    pub mod AdjustmentCauseEnum {
/** The adjustment is to optimize the local energy usage */
        pub const LocalOptimization: u32 = 0x00;
/** The adjustment is to optimize the grid energy usage */
        pub const GridOptimization: u32 = 0x01;
    }
    pub mod CauseEnum {
/** The ESA completed the power adjustment as requested */
        pub const NormalCompletion: u32 = 0x00;
/** The ESA was set to offline */
        pub const Offline: u32 = 0x01;
/** The ESA has developed a fault could not complete the adjustment */
        pub const Fault: u32 = 0x02;
/** The user has disabled the ESA's flexibility capability */
        pub const UserOptOut: u32 = 0x03;
/** The adjustment was cancelled by a client */
        pub const Cancelled: u32 = 0x04;
    }
    pub mod CostTypeEnum {
/** Financial cost */
        pub const Financial: u32 = 0x00;
/** Grid CO2e grams cost */
        pub const GHGEmissions: u32 = 0x01;
/** Consumer comfort impact cost */
        pub const Comfort: u32 = 0x02;
/** Temperature impact cost */
        pub const Temperature: u32 = 0x03;
    }
    pub mod ESAStateEnum {
/** The ESA is not available to the EMS (e.g. start-up, maintenance mode) */
        pub const Offline: u32 = 0x00;
/** The ESA is working normally and can be controlled by the EMS */
        pub const Online: u32 = 0x01;
/** The ESA has developed a fault and cannot provide service */
        pub const Fault: u32 = 0x02;
/** The ESA is in the middle of a power adjustment event */
        pub const PowerAdjustActive: u32 = 0x03;
/** The ESA is currently paused by a client using the PauseRequest command */
        pub const Paused: u32 = 0x04;
    }
    pub mod ESATypeEnum {
/** EV Supply Equipment */
        pub const EVSE: u32 = 0x00;
/** Space heating appliance */
        pub const SpaceHeating: u32 = 0x01;
/** Water heating appliance */
        pub const WaterHeating: u32 = 0x02;
/** Space cooling appliance */
        pub const SpaceCooling: u32 = 0x03;
/** Space heating and cooling appliance */
        pub const SpaceHeatingCooling: u32 = 0x04;
/** Battery Electric Storage System */
        pub const BatteryStorage: u32 = 0x05;
/** Solar PV inverter */
        pub const SolarPV: u32 = 0x06;
/** Fridge / Freezer */
        pub const FridgeFreezer: u32 = 0x07;
/** Washing Machine */
        pub const WashingMachine: u32 = 0x08;
/** Dishwasher */
        pub const Dishwasher: u32 = 0x09;
/** Cooking appliance */
        pub const Cooking: u32 = 0x0A;
/** Home water pump (e.g. drinking well) */
        pub const HomeWaterPump: u32 = 0x0B;
/** Irrigation water pump */
        pub const IrrigationWaterPump: u32 = 0x0C;
/** Pool pump */
        pub const PoolPump: u32 = 0x0D;
/** Other appliance type */
        pub const Other: u32 = 0xFF;
    }
    pub mod ForecastUpdateReasonEnum {
/** The update was due to internal ESA device optimization */
        pub const InternalOptimization: u32 = 0x00;
/** The update was due to local EMS optimization */
        pub const LocalOptimization: u32 = 0x01;
/** The update was due to grid optimization */
        pub const GridOptimization: u32 = 0x02;
    }
    pub mod OptOutStateEnum {
/** The user has not opted out of either local or grid optimizations */
        pub const NoOptOut: u32 = 0x00;
/** The user has opted out of local EMS optimizations only */
        pub const LocalOptOut: u32 = 0x01;
/** The user has opted out of grid EMS optimizations only */
        pub const GridOptOut: u32 = 0x02;
/** The user has opted out of all external optimizations */
        pub const OptOut: u32 = 0x03;
    }
    pub mod PowerAdjustReasonEnum {
/** There is no Power Adjustment active */
        pub const NoAdjustment: u32 = 0x00;
/** There is PowerAdjustment active due to local EMS optimization */
        pub const LocalOptimizationAdjustment: u32 = 0x01;
/** There is PowerAdjustment active due to grid optimization */
        pub const GridOptimizationAdjustment: u32 = 0x02;
    }
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod DeviceEnergyManagementMode {
    pub mod ModeTag {
        pub const Auto: u32 = 0x00;
        pub const Quick: u32 = 0x01;
        pub const Quiet: u32 = 0x02;
        pub const LowNoise: u32 = 0x03;
        pub const LowEnergy: u32 = 0x04;
        pub const Vacation: u32 = 0x05;
        pub const Min: u32 = 0x06;
        pub const Max: u32 = 0x07;
        pub const Night: u32 = 0x08;
        pub const Day: u32 = 0x09;
        pub const NoOptimization: u32 = 0x4000;
        pub const DeviceOptimization: u32 = 0x4001;
        pub const LocalOptimization: u32 = 0x4002;
        pub const GridOptimization: u32 = 0x4003;
    }
}
/** Attributes and commands for selecting a mode from a list of supported options. */
pub mod LaundryWasherMode {
    pub mod ModeTag {
        pub const Auto: u32 = 0x00;
        pub const Quick: u32 = 0x01;
        pub const Quiet: u32 = 0x02;
        pub const LowNoise: u32 = 0x03;
        pub const LowEnergy: u32 = 0x04;
        pub const Vacation: u32 = 0x05;
        pub const Min: u32 = 0x06;
        pub const Max: u32 = 0x07;
        pub const Night: u32 = 0x08;
        pub const Day: u32 = 0x09;
        pub const Normal: u32 = 0x4000;
        pub const Delicate: u32 = 0x4001;
        pub const Heavy: u32 = 0x4002;
        pub const Whites: u32 = 0x4003;
    }
}
/** This cluster is used to configure a valve. */
pub mod ValveConfigurationandControl {
    pub mod StatusCodeEnum {
/** The requested action could not be performed due to a fault on the valve. */
        pub const FailureDueToFault: u32 = 0x02;
    }
    pub mod ValveStateEnum {
/** Valve is in closed position */
        pub const Closed: u32 = 0x00;
/** Valve is in open position */
        pub const Open: u32 = 0x01;
/** Valve is transitioning between closed and open positions or between levels */
        pub const Transitioning: u32 = 0x02;
    }
    pub mod ValveFaultBitmap {
/** Unspecified fault detected */
        pub const GeneralFault: u32 = 0x01;
/** Valve is blocked */
        pub const Blocked: u32 = 0x02;
/** Valve has detected a leak */
        pub const Leaking: u32 = 0x04;
/** No valve is connected to controller */
        pub const NotConnected: u32 = 0x08;
/** Short circuit is detected */
        pub const ShortCircuit: u32 = 0x10;
/** The available current has been exceeded */
        pub const CurrentExceeded: u32 = 0x20;
    }
}
/** This cluster supports remotely monitoring and, where supported, changing the operational state of an Oven. */
pub mod OvenCavityOperationalState {
    pub mod ErrorStateEnum {
/** The device is not in an error state */
        pub const NoError: u32 = 0x00;
/** The device is unable to start or resume operation */
        pub const UnableToStartOrResume: u32 = 0x01;
/** The device was unable to complete the current operation */
        pub const UnableToCompleteOperation: u32 = 0x02;
/** The device cannot process the command in its current state */
        pub const CommandInvalidInState: u32 = 0x03;
    }
    pub mod OperationalStateEnum {
/** The device is stopped */
        pub const Stopped: u32 = 0x00;
/** The device is operating */
        pub const Running: u32 = 0x01;
/** The device is paused during an operation */
        pub const Paused: u32 = 0x02;
/** The device is in an error state */
        pub const Error: u32 = 0x03;
    }
}
