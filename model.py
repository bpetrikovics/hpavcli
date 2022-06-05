import struct
from dataclasses import dataclass
from enum import Enum
from struct import unpack
from typing import List


class HPAVVersion(Enum):
    HPAV1_1 = 0
    HPAV2_0 = 1


class EtherType(Enum):
    HPAV = bytes([0x88, 0xe1])
    GIGLE = bytes([0x89, 0x12])


class OUI(Enum):
    QUALCOMM = bytes([0x00, 0xb0, 0x52])
    BROADCOM = bytes([0x00, 0x1f, 0x84])


class MMType(Enum):
    Uninitialized = None
    CC_CCO_APPOINT = 0x0000
    CC_BACKUP_APPOINT = 0x0004
    CC_LINK_INFO = 0x0008
    CC_HANDOVER_REQ = 0x000c
    CC_HANDOVER_INFO = 0x0010
    CC_DISCOVER_LIST = 0x0014
    CC_LINK_NEW = 0x0018
    CC_LINK_MOD = 0x001c
    CC_LINK_SQZ = 0x0020
    CC_LINK_REL = 0x0024
    CC_DETECT_REPORT = 0x0028
    CC_WHO_RU = 0x002c
    CC_ASSOC = 0x0030
    CC_LEAVE = 0x0034
    CC_SET_TAI_MAP = 0x0038
    CC_RELAY = 0x003c
    CC_BEACON_RELIABILITY = 0x0040
    CC_ALLOC_MOVE = 0x0044
    CC_ACCESS_NEW = 0x0048
    CC_ACCESS_REL = 0x004c
    CC_DCPPC = 0x0050
    CC_HP1_DET = 0x0054
    CC_BLE_UPDATE = 0x0058
    CC_BCAST_REPEAT = 0x005c
    CC_MH_LINK_NEW = 0x0060
    CC_ISP_DetectionReport = 0x0064
    CC_ISP_StartReSync = 0x0068
    CC_ISP_FinishReSync = 0x006c
    CC_ISP_ReSyncDetected = 0x0070
    CC_ISP_ReSyncTransmit = 0x0074
    CC_POWERSAVE = 0x0078
    CC_POWERSAVE_EXIT = 0x007c
    CC_POWERSAVE_LIST = 0x0080
    CC_STOP_POWERSAVE = 0x0084

    CP_PROXY_APPOINT = 0x2000
    PH_PROXY_APPOINT = 0x2004
    CP_PROXY_WAKE = 0x2008

    NN_INL = 0x4000
    NN_NEW_NET = 0x4004
    NN_ADD_ALLOC = 0x4008
    NN_REL_ALLOC = 0x400c
    NN_REL_NET = 0x4010

    CM_UNASSOCIATED_STA = 0x6000
    CM_ENCRYPTED_PAYLOAD = 0x6004
    CM_SET_KEY = 0x6008
    CM_GET_KEY = 0x600c
    CM_SC_JOIN = 0x6010
    CM_CHAN_EST = 0x6014
    CM_TM_UPDATE = 0x6018
    CM_AMP_MAP = 0x601c
    CM_BRG_INFO = 0x6020
    CM_CONN_NEW = 0x6024
    CMC_ONN_REL = 0x6028
    CM_CONN_MOD = 0x602c
    CM_CONN_INFO = 0x6030
    CM_STA_CAP = 0x6034
    CM_NW_INFO = 0x6038
    CM_GET_BEACON = 0x603c
    CM_HFID = 0x6040
    CM_MME_ERROR = 0x6044
    CM_NW_STATS = 0x6048
    CM_LINK_STATS = 0x604c
    CM_ROUTE_INFO = 0x6050
    CM_UNREACHABLE = 0x6054
    CM_MH_CONN_NEW = 0x6058
    CM_EXTENDEDTONEMASK = 0x605c
    CM_STA_IDENTIFY = 0x6060
    CM_TRIGGER_ATTEN_CHR = 0x6064
    CM_START_ATTEN_CHAR = 0x6068
    CM_ATTEN_CHAR = 0x606c

    BROADCOM_RESTART = 0xa020
    BROADCOM_NETWORK_INFO = 0xa028
    BROADCOM_FACTORY_RESET = 0xa054
    BROADCOM_GET_HFID = 0xa05c
    BROADCOM_SET_HFID = 0xa058
    BROADCOM_DISCOVER = 0xa070


class MMSubtype(Enum):
    """ Least significant 2 bits of the MMType describes the subtype of the request """
    REQ = 0
    CNF = 1
    IND = 2
    RSP = 4


class MMError(Enum):
    MME_UNSUPPORTED = 0
    MME_FIELDS_INVALID = 1


class HPAVHFIDRequest(Enum):
    GET_MANUFACTURER_HFID = 0x00
    GET_USER_HFID = 0x01
    GET_NETWORK_HFID = 0x02
    SET_USER_HFID = 0x03
    SET_NETWORK_HFID = 0x04


class HPAVStationRole(Enum):
    STA = 0
    PROXY_COORDINATOR = 1
    CCO = 2


class NetworkKind(Enum):
    IN_HOME_NETWORK = 0
    ACCESS_NETWORK = 1


class HPAVCCOCoordinatingStatus(Enum):
    UNKNOWN = 0
    NON_COORDINATING_NETWORK = 1
    COORDINATING_GROUP_STATUS_UNKNOWN = 2
    COORDINATING_NETWORK_IN_SAME_GROUP_WITH_CCO = 3
    COORDINATING_NETWORK_NOT_IN_SAME_GROUP_WITH_CCO = 4


# Below are Broadcom specific, TBD to organize them
class BroadcomHFIDRequest(Enum):
    GET_MANUFACTURER_HFID = 0x1b
    GET_USER_HFID = 0x25


class BroadcomNetworkInfoRequest(Enum):
    GET_NETWORK_MEMBER = 0x00
    GET_NETWORK_ANY = 0x01


class BroadcomStationRole(Enum):
    UNASSOC_STA = 0
    UNASSOC_CCO = 1
    STA = 2
    CCO = 3
    BACKUP_CCO = 4


class BroadcomPowerlineStatus(Enum):
    JOINED = 0
    NOT_JOINED_HAVE_NMK = 1
    NOT_JOINED_NO_NMK = 2


class MacAddress:
    def __init__(self, address: str):
        """ Accept either ABCABCABCABC or AB:CA:BC:AB"CA"BC format """
        if address.find(':') != -1:
            address_bytes = address.split(':')
            if len(address_bytes) != 6:
                raise ValueError(f"MAC address format error: {address}")
            for element in address_bytes:
                if len(element) > 2:
                    raise ValueError(f"MAC address format error: {address}")
            self.address = address.replace(":", "").lower()
        else:
            if len(address) != 12:
                raise ValueError(f"MAC address format error: {address}")
            self.address = address.lower()

    def __eq__(self, other):
        return self.address == other.address

    def __repr__(self):
        return f"<MacAddress({self.pretty})>"

    def as_bytes(self) -> bytes:
        return bytes.fromhex(self.address.replace(":", ""))

    @property
    def pretty(self) -> str:
        return ':'.join([self.address[i:i + 2] for i in range(0, len(self.address), 2)])

    @classmethod
    def from_bytes(cls, address_bytes: bytes):
        return cls(address_bytes.hex())


class EthernetPacket:
    def __init__(self, dest: MacAddress, source: MacAddress, ethertype: bytes, payload: bytes):
        self.dest = dest
        self.source = source
        self.ethertype = ethertype
        self.payload = payload

    @property
    def payload(self):
        return self._payload

    @payload.setter
    def payload(self, payload):
        self._payload = payload

    def __repr__(self):
        return f"<EthernetPacket src={self.source}, dest={self.dest}, ethertype=0x{self.ethertype.hex()}>"

    def as_bytes(self):
        return self.dest.as_bytes() + self.source.as_bytes() + self.ethertype + self.payload

    @classmethod
    def from_bytes(cls, raw_packet: bytes):
        dest = raw_packet[0:6].hex()
        src = raw_packet[6:12].hex()
        ethertype = raw_packet[12:14]
        payload = raw_packet[14:]

        return cls(MacAddress(dest), MacAddress(src), ethertype, payload)


class ManagementMessage(EthernetPacket):
    DEFAULT_MTYPE = EtherType.HPAV.value

    def __init__(self, dest: MacAddress, source: MacAddress, ethertype: bytes = None, payload: bytes = None):
        super().__init__(dest, source, ManagementMessage.DEFAULT_MTYPE if not ethertype else ethertype, payload)

        # Management Message Version
        self.mmv = 1
        # Management Message Type
        self.mmtype = None
        # Fragmentation Management Information
        self.fmi = 0
        # Fragmentation Message Sequence Number
        self.fmsn = 0
        # Management Message Entry Data
        self.mmentry = bytes()

        if payload:
            self.process_payload()
        else:
            self.payload = bytes()

    @property
    def mmv(self):
        return self._mmv

    @mmv.setter
    def mmv(self, mmv):
        self._mmv = mmv

    @property
    def mmtype(self):
        return self._mmtype

    @mmtype.setter
    def mmtype(self, mmtype):
        self._mmtype = mmtype

    @property
    def fmi(self):
        return self._fmi

    @fmi.setter
    def fmi(self, fmi):
        self._fmi = fmi

    @property
    def fmsn(self):
        return self._fmsn

    @fmsn.setter
    def fmsn(self, fmsn):
        self._fmsn = fmsn

    @property
    def subtype(self):
        """ The two LSB of the MMType tells is whether it's a request, response, indication or error """
        return self.mmtype & 0b11

    @property
    def mmbase(self):
        """ Masks the two LSBs of the MMType to give, so we can identify the base type regardless of it's a
        equest or response """
        return self.mmtype & 0b1111111111111100

    @property
    def payload(self) -> bytes:
        header = struct.pack("<BHBB", self.mmv, self.mmtype, self.fmi, self.fmsn)
        self.payload = header + self.mmentry

        # Add padding to minimal payload length
        return self._payload + bytes([0 for i in range(60 - len(self._payload))])

    @payload.setter
    def payload(self, payload):
        self._payload = payload

    def process_payload(self) -> None:
        """ Unpack payload/binary packet data into Management Message fields """
        """ Note to self: should this also be a BinaryData object? """
        self.mmv, self.mmtype, self.fmi, self.fmsn = unpack("=BHBB", self._payload[0:5])
        self.mmentry = self._payload[5:]

    def as_bytes(self):
        return self.dest.as_bytes() + \
               self.source.as_bytes() + \
               EtherType(self.ethertype).value + \
               self.payload

    def __repr__(self):
        return f"<ManagementMessage(mmv={self.mmv}, mmtype=0x{self.mmtype:04x} ({MMType(self.mmbase).name}.{MMSubtype(self.subtype).name}), fmi={self.fmi}, fmsn={self.fmsn}, mmentry={self.mmentry.hex() if self.mmentry else None})>"


@dataclass
class BinaryData:
    """ Quick and dirty way to deserialize raw binary data using a format string
        Inherit this, and specify an UNPACK_FORMAT string, then the corresponding data fields as
        dataclass member fields """

    UNPACK_FORMAT = ""

    @classmethod
    def from_bytes(cls, rawdata: bytes):
        unpacked = unpack(cls.UNPACK_FORMAT, rawdata)
        return cls(*unpacked)


@dataclass
class HPAVDiscoverStationInfo(BinaryData):
    """ Represents an STA in a CC_DISCOVER_LIST.CNF message"""

    # MAC address of the discovered STA
    macaddr: bytes
    # Terminal Equipment Identifier of the discovered STA
    tei: int
    # Whether the STA is associated with the same network (0=different network, 1=same network)
    samenetwork: bool
    # 4 LSB = Short Network identifier of the STA, 4 MSB = 0x0 for in-home, 0x01 for Access Network
    snid_access: int
    # Capabilities
    caps: int
    # Signal level, 0x00 = N/A, 0x01 to 0x0f = level indicator, the smaller the better >= 0x10 = reserved
    signal: int
    # Average BLE
    avgble: int

    UNPACK_FORMAT = "!6sBBBBBB"

    def __post_init__(self):
        self.macaddr = MacAddress(self.macaddr.hex())

    @property
    def snid(self):
        """ Extract SNID field from SNID/Access byte """
        return self.snid_access & 0b00001111

    @property
    def access(self):
        """ Extract Access field from SNID/Access byte """
        return NetworkKind(self.snid_access & 0b11110000)


@dataclass
class HPAVDiscoverNetworkInfo(BinaryData):
    """ Represents a network in a CC_DISCOVER_LIST.CNF message """

    # Network Identifier
    nid: str
    # 4x LSB = Snort Network Identifier. 4x MSB = 0x00 for in-home, 0x01 for access
    snid_access: int
    # Hybrid Mode
    hm: int
    # Number of Beacon Slots
    numslots: int
    # Coordinating Status of the CCO, see HPAVCCOCoordinatingStatus (int)
    coord_status: HPAVCCOCoordinatingStatus
    # Offset between Beacon Region of the discovered network and that of the STA's own network
    # Units are Allocation Units
    offset: int

    UNPACK_FORMAT = "!7sBBBBH"

    def __post_init__(self):
        pass

    @property
    def snid(self) -> int:
        """ Extract SNID field from SNID/Access byte """
        return self.snid_access & 0b00001111

    @property
    def access(self) -> NetworkKind:
        """ Extract Access field from SNID/Access byte """
        return NetworkKind(self.snid_access & 0b11110000)

    def __eq__(self, other):
        if other is None:
            return False
        if not hasattr(other, "nid"):
            return False

        return self.nid == other.nid

    def __hash__(self):
        return hash(self.nid)


@dataclass
class HPAVNetworkInformation(BinaryData):
    """ Represents network data in a  CM_NW_INFO.CNF message """

    # Network Identifier
    nid: str
    # Short Network Identifier (4 LSB only, rest is zero)
    snid: int
    # Terminal Equipment Identifier of the STA in the AVLN
    tei: int
    # Role of the Station in the AVLN
    role: HPAVStationRole
    # MAC of the CCo
    ccomac: MacAddress
    # Access or In-Home Network
    access: NetworkKind
    # Number of Neighbor Networks that are coordinating with the AVLN
    numnets: int
    # NOTE: In contrast to Broadcom netinfo block, this one does not have a status field

    UNPACK_FORMAT = "!7sBBB6sBB"

    def __post_init__(self):
        self.ccomac = MacAddress(self.ccomac.hex())

    def __eq__(self, other):
        if other is None:
            return False
        if not hasattr(other, "nid"):
            return False

        return self.nid == other.nid

    def __hash__(self):
        return hash(self.nid)


@dataclass
class BroadcomNetworkInformation(HPAVNetworkInformation):
    """ Represents a network information block in a BROADCOM_NETWORK_INFO.CNF message """

    # nid: str
    # snid: int
    # tei: int
    # role: BroadcomStationRole
    # ccomac: MacAddress
    # kind: NetworkKind (~ access)
    # numnets: int
    status: BroadcomPowerlineStatus

    UNPACK_FORMAT = "!7sBBB6sBBB"


@dataclass
class HPAVStationCapabilities(BinaryData):
    """ Represents STA capabilities in a CM_STA_CAP.CNF response """

    avversion: int
    mac: MacAddress
    oui: bytes
    autoconnect: int
    smoothing: int
    ccocap: int
    proxycap: int
    backupcco: int
    softhandover: int
    twosymfc: int
    maxflav: int
    hp11cap: int
    hp10iop: int
    regcap: int
    biburst: int
    implver: int

    UNPACK_FORMAT = "!B6s3sBBBBBBBHBBBBH"

    def __post_init__(self):
        self.mac = MacAddress(self.mac.hex())
        self.oui = OUI(self.oui)


@dataclass
class HPAVNetworkStats(BinaryData):
    """ Represents network stats data in a CM_NW_STATS.CNF response """

    macaddr: MacAddress
    txrate: int
    rxrate: int

    UNPACK_FORMAT = "<6sHH"

    def __post_init__(self):
        self.macaddr = MacAddress(self.macaddr.hex())


class PowerlineDevice:
    """ Represents all the information we know about a detected powerline device.
        Created by _hpav_discover using CC_DISCOVER_LIST queries, further vendor specific details then
        filled by _broadcom_discover
    """

    def __init__(self, address: MacAddress, oui: OUI = None):
        self.interface = None  # FIXME
        self.mac = address
        self.oui = oui
        self.hpav_version = None
        # FIXME. There should be a proper interface defined and this should be passed on via init, properly typed
        self.interface = None
        self.hfid = None
        self.sta_list = []
        self.net_list = []

    def __repr__(self):
        return f"<PowerlineDevice(iface={self.interface.interface_name}, " \
               f"av_version={HPAVVersion(self.hpav_version).name if self.hpav_version else 'N/A'}, " \
               f"address={self.mac.pretty}, oui={self.oui.name if self.oui else 'N/A'})>"

    def add_station(self, sta: HPAVDiscoverStationInfo) -> None:
        self.sta_list.append(sta)

    def add_network(self, net: HPAVDiscoverNetworkInfo or BroadcomNetworkInformation) -> None:
        self.net_list.append(net)

    def stations(self) -> List[HPAVDiscoverStationInfo]:
        return self.sta_list

    def networks(self) -> List[HPAVDiscoverNetworkInfo]:
        return self.net_list


class PowerlineNetwork:
    def __init__(self, network_id: str):
        self.nid = network_id
        self.stations = dict()
        self.cco = None

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, PowerlineNetwork):
            return False

        return self.nid == other.nid

    def __hash__(self):
        return hash(self.nid)

    def __repr__(self):
        return f"<PowerlineNetwork({self.nid})>"

    def add_station(self, station: PowerlineDevice):
        self.stations[station.mac.address] = station

    def get_station(self, station: PowerlineDevice):
        return self.stations.get(station.mac.address, None)
