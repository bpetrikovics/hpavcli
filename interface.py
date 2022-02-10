import socket
import time

import netifaces

from model import *

ETH_P_ALL = 3
DEVICE_TIMEOUT = 0.1


class PowerlineInterface:
    def __init__(self, interface_name: str, verbose: bool = False, timeout: float = DEVICE_TIMEOUT):
        """ Raises ValueError if interface was not found """

        self.interface_name = interface_name
        self.interface_mac = MacAddress(netifaces.ifaddresses(self.interface_name)[netifaces.AF_LINK][0]['addr'])
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.socket.bind((self.interface_name, 0))
        self.verbose = verbose
        self.timeout = timeout

        if self.verbose:
            print(f"Initialized powerline interface on {self.interface_name} ({self.interface_mac.pretty})")

    def __repr__(self):
        return f"<PowerlineInterface device={self.interface_name} mac={self.interface_mac.address.pretty}>"

    def _request(self, packet: ManagementMessage) -> List[ManagementMessage]:
        if self.verbose:
            print(f"{self.interface_name}\t>> [{packet.source.pretty} -> {packet.dest.pretty}] {packet}")
        self.socket.sendall(packet.as_bytes())

        received = list()
        start = time.time()
        previous_timeout = self.socket.gettimeout()

        while True:
            elapsed = time.time() - start
            if elapsed > self.timeout:
                break

            self.socket.settimeout(self.timeout - elapsed)
            try:
                message = self.socket.recv(4096)
            except socket.timeout as exc:
                break

            recv_packet = ManagementMessage.from_bytes(message)

            if recv_packet.ethertype != packet.ethertype:
                continue

            if recv_packet.dest != packet.source:
                if self.verbose:
                    print(f"Dropping packet as destination {recv_packet.dest.pretty} is incorrect")
                continue

            # If it was not sent to a broadcast address, also check the sender, which should match our original
            # destination MAC
            if packet.dest.address != "ffffffffffff":
                if recv_packet.source != packet.dest:
                    break

            if recv_packet.mmbase == MMType.CM_MME_ERROR.value and recv_packet.subtype == MMSubtype.IND.value:
                if self.verbose:
                    print(f"CM_MME_ERROR.IND: reason={MMError(recv_packet.mmentry[0]).name}")
                continue

            if recv_packet.mmbase == packet.mmbase:
                if self.verbose:
                    print(f"{self.interface_name}\t<< [{recv_packet.source.pretty} -> {recv_packet.dest.pretty}] {recv_packet}")
                received.append(recv_packet)

        self.socket.settimeout(previous_timeout)
        return received

    def _hpav_discover(self, target: MacAddress = MacAddress("FF:FF:FF:FF:FF:FF")) -> (
                                                                List[PowerlineDevice], List[HPAVDiscoverNetworkInfo]):
        """ Send CC_DISCOVER_LIST.REQ and wait for CC_DISCOVER_LIST.CNF responses.
            If target was not specified, send a broadcast request which will receive one response packet from
            each HPAV device on the network.
            Please note that for example with Broadcom based devices (at least my TL-PA7017) the network list in
            this response only contains those networks that the adapter is not part of, so it should be probably
            not used at all.
        """
        print("*** HPAV Discover")

        sta_info_size = 12
        network_info_size = 13

        packet = ManagementMessage(target, self.interface_mac)
        packet.mmtype = MMType.CC_DISCOVER_LIST.value

        received = self._request(packet)

        found_devices = []
        found_networks = []

        for packet in received:
            dev = PowerlineDevice(packet.source)
            dev.interface = self
            num_sta = packet.mmentry[0]

            for sta in range(num_sta):
                sta_data = packet.mmentry[1 + sta * sta_info_size:1 + (sta + 1) * sta_info_size]
                dev.add_station(HPAVDiscoverStationInfo.from_bytes(sta_data))

            pointer = 1 + num_sta * sta_info_size
            num_nets = packet.mmentry[pointer]

            pointer += 1
            for net in range(num_nets):
                net_data = packet.mmentry[pointer + net * network_info_size:pointer + (net + 1) * network_info_size]
                netinfo = HPAVDiscoverNetworkInfo.from_bytes(net_data)

                if netinfo.coord_status <= HPAVCCOCoordinatingStatus.NON_COORDINATING_NETWORK.value:
                    print(f"  Device {dev.mac.pretty} -> network {netinfo.nid.hex()} is a non-coordinating network")

                # Do we want to associate the networks to STAs like this or rather collect/process separately?
                dev.add_network(netinfo)
                found_networks.append(netinfo)

            print(f"    Device {dev.mac.pretty}: STAs[{num_sta}]={dev.stations()}, nets[{num_nets}]={dev.networks()}")
            dev.interface = self
            found_devices.append(dev)

        return found_devices, found_networks

    def _hpav_station_caps(self, device: PowerlineDevice):
        """ CM_STA_CAP can be used to identify device vendor/OUI for further, vendor specific requests
            This method will inject OUI and HPAV Version information into the device """

        print("*** HPAV station caps")

        packet = ManagementMessage(device.mac, self.interface_mac)
        packet.mmtype = MMType.CM_STA_CAP.value

        received = self._request(packet)

        for packet in received:
            caps = HPAVStationCapabilities.from_bytes(packet.mmentry[:25])

            if self.verbose:
                print(caps)

            device.oui = caps.oui
            device.hpav_version = caps.avversion

    def _hpav_network_stats(self, device: PowerlineDevice) -> List[HPAVNetworkStats]:
        """ CM_NW_STATS for generic network statistics including up/down rates
            Could be sent to broadcast MAC, but in that case only connected devices would respond (e.g. that have
            existing network), so cannot be used for device discovery alone. """

        print("*** HPAV network stats")

        stat_info_size = 10

        packet = ManagementMessage(device.mac, self.interface_mac)
        packet.mmv = 2
        packet.mmtype = MMType.CM_NW_STATS.value

        received = self._request(packet)

        networks = list()
        for packet in received:
            num_sta = packet.mmentry[0]

            if self.verbose:
                print(f"{packet.source.pretty}: stations={num_sta}")

            for sta in range(num_sta):
                sta_data = packet.mmentry[1 + sta * stat_info_size:1 + (sta + 1) * stat_info_size]
                netstat = HPAVNetworkStats.from_bytes(sta_data)
                networks.append(netstat)
                print(f"    STA {sta}: {device.mac.pretty} <-> {netstat.macaddr.pretty} Average PHY Rate: {netstat.txrate} up / {netstat.rxrate} down Mbps")

        return networks

    def _hpav_network_info(self, device: PowerlineDevice) -> List[HPAVNetworkInformation]:
        """ Not supported by Broadcom, returns MME_UNSUPPORTED error indication """
        """ Implementation - I have no device that responds to this """

        print("*** HPAV network info")

        packet = ManagementMessage(device.mac, self.interface_mac)
        packet.mmv = 1
        packet.mmtype = MMType.CM_NW_INFO.value

        received = self._request(packet)

        # TODO: Process response into device fields

    def _hpav_get_hfid(self, device: PowerlineDevice):
        """ Not supported by Broadcom - implementation tbd, I have no device that responds to this """

        print("*** HPAV get HFID")

        packet = ManagementMessage(device.mac, self.interface_mac)
        packet.mmtype = MMType.CM_HFID.value
        packet.mmentry = struct.pack("!B", HPAVHFIDRequest.GET_USER_HFID.value)

        received = self._request(packet)

        # TODO: Process response into device fields

    def _broadcom_discover(self, device: PowerlineDevice):
        """ This management message can be sent to both broadcast address and to specific device
            In the current implementation we discover devices with the generic HPAV MM and only call the
            vendor specific MMs once the vendor has been identified. This might be wrong.
            Currently, this simply injects the HFID into the device object, which might also be the wrong approach.
        """

        print("*** Broadcom discover")

        gigle_magic = b"\x01\xa3\x97\xa2\x55\x53\xbe\xf1\xfc\xf9\x79\x6b\x52\x14\x13\xe9\xe2"

        payload = struct.pack(f"!{len(OUI.BROADCOM.value)}s{len(gigle_magic)}s", OUI.BROADCOM.value, gigle_magic)

        packet = ManagementMessage(device.mac, self.interface_mac, EtherType.GIGLE.value)
        packet.mmv = 2
        packet.mmtype = MMType.BROADCOM_DISCOVER.value
        packet.mmentry = payload

        received = self._request(packet)

        # TODO: convert this to a BinaryData class

        for packet in received:
            oui, _tmp, interface, hfid_len = unpack("!3sBBB", packet.mmentry[:6])
            hfid = packet.mmentry[6:6 + hfid_len].decode('utf8')
            device.hfid = hfid

    def _broadcom_get_hfid(self, device: PowerlineDevice, arg: BroadcomHFIDRequest):
        """ Query either a Manufacturer or User HFID (Human-Friendly Identifier) and injects it into
            the device object """

        print("*** Broadcom get HFID")

        packet = ManagementMessage(device.mac, self.interface_mac, EtherType.GIGLE.value)
        packet.mmv = 2
        packet.mmtype = MMType.BROADCOM_GET_HFID.value
        # FIXME: Figure out what 0x02 is here - avoid magic bytes if possible...
        # Santa please bring me a protocol manual :(
        packet.mmentry = struct.pack(f"!{len(OUI.BROADCOM.value)}sBB", OUI.BROADCOM.value, 0x02, arg.value)

        received = self._request(packet)

        hfid = received[0].payload[12:].decode("utf8")
        device.hfid = hfid

    def _broadcom_network_info(self, device: PowerlineDevice, arg: BroadcomNetworkInfoRequest) -> List[BroadcomNetworkInformation]:
        """ Performs a Broadcom specific network info query """

        print("*** Broadcom network info")

        broadcom_network_info_size = 19

        packet = ManagementMessage(device.mac, self.interface_mac, EtherType.GIGLE.value)
        packet.mmv = 2
        packet.mmtype = MMType.BROADCOM_NETWORK_INFO.value
        # FIXME: [0x01, 0x00] another magic word...
        packet.mmentry = struct.pack(f"!{len(OUI.BROADCOM.value)}s2sB", OUI.BROADCOM.value, bytes([0x01, 0x00]), arg.value)

        received = self._request(packet)

        # Since we send a unicast message, there should be no more than a single packet received, right?
        payload = received[0].payload
        data = payload[9:]
        number_of_networks = data[0]
        print(f"    STA {received[0].source.pretty} reported {number_of_networks} networks")

        networks = []

        pointer = 1
        for num in range(1, number_of_networks + 1):
            chunk = data[pointer:pointer + broadcom_network_info_size]
            netstatus = BroadcomNetworkInformation.from_bytes(chunk)

            pointer = pointer + broadcom_network_info_size

            if self.verbose:
                print("    ", netstatus)

            networks.append(netstatus)

            print(f"      Network ID:  {netstatus.nid.hex()} role {BroadcomStationRole(netstatus.role).name}, "
                  f"{NetworkKind(netstatus.access).name}, coordinator is {netstatus.ccomac.pretty}, {BroadcomPowerlineStatus(netstatus.status).name}")

            if netstatus not in device.networks():
                device.add_network(netstatus)

        return networks

    def discover_devices(self) -> List[PowerlineDevice]:
        """ Remove network-specific queries and concentrate on detecting devices and collecting basic info? """
        """ Or only call network info queries to collect the number of networks known by each STA? """

        devices, networks = self._hpav_discover()
        print(f"Discovered {len(devices)} devices and {len(networks)} networks")

        for dev in devices:
            self._hpav_station_caps(dev)

            if dev.oui == OUI.BROADCOM:
                if self.verbose:
                    print("Broadcom device detected, using vendor specific requests")

                self._broadcom_discover(dev)
                self._broadcom_get_hfid(dev, BroadcomHFIDRequest.GET_USER_HFID)
                # only for network count?
                self._broadcom_network_info(dev, BroadcomNetworkInfoRequest.GET_NETWORK_ANY)
            else:
                if self.verbose:
                    print("Generic device, using HPAV standard queries")

                self._hpav_get_hfid(dev)
                # only for network count?
                self._hpav_network_info(dev)

        return devices

    def discover_networks(self):
        """ Discover networks and then collect CCO and network PHY rate data """

        network_list = []
        devices, networks = self._hpav_discover()

        for dev in devices:
            # Discover oui, so we can call the correct network info implementation
            self._hpav_station_caps(dev)

            netdata = None
            if dev.oui == OUI.BROADCOM:
                netdata = self._broadcom_network_info(dev, BroadcomNetworkInfoRequest.GET_NETWORK_ANY)
                for net in netdata:
                    if net.role == BroadcomStationRole.CCO.value:
                        print(f"{dev.mac.pretty}: I am CCO for network {net.nid.hex()}")
                    elif net.access == NetworkKind.IN_HOME_NETWORK.value:
                        print(f"{dev.mac.pretty}: CCO for network {net.nid.hex()} is {net.ccomac.pretty}")
                    else:
                        print(f"{dev.mac.pretty}: No access to network {net.nid.hex()}")
            else:
                netdata = self._hpav_network_info(dev)

            for net in netdata:
                _tmp = PowerlineNetwork(net.nid.hex())
                if _tmp not in network_list:
                    print(f"Adding newly found network {net.nid.hex()} to list")
                    network_list.append(_tmp)
                else:
                    # extend network information with new data
                    pass

            print(f"network_list: {network_list}")

            # Since the network info routes gave us the network IDs, discover network stats that now we can
            # correlate with the networks (down/up PHY rates between specific MACs)
            self._hpav_network_stats(dev)
