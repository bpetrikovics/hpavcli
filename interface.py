import socket
import time
from typing import List

import netifaces

from model import *

ETH_P_ALL = 3
DEVICE_TIMEOUT = 0.1


class PowerlineInterface():
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
        oldtimeout = self.socket.gettimeout()

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

        self.socket.settimeout(oldtimeout)
        return received

    def _hpav_discover(self) -> List[MacAddress]:
        """ Send CC_DISCOVER_LIST.REQ to broadcast address, and wait for CC_DISCOVER_LIST.CNF responses """

        sta_info_size = 12
        network_info_size = 13

        packet = ManagementMessage(MacAddress("FF:FF:FF:FF:FF:FF"), self.interface_mac)
        packet.mmtype = MMType.CC_DISCOVER_LIST.value

        received = self._request(packet)

        found_list = []
        for packet in received:
            dev = PowerlineDevice(packet.source)
            dev.interface = self
            num_sta = packet.mmentry[0]

            for sta in range(num_sta):
                sta_data = packet.mmentry[1 + sta * sta_info_size:1 + (sta + 1) * sta_info_size]
                dev.add_station(HPAVStationInfo.from_bytes(sta_data))

            pointer = 1 + num_sta * sta_info_size
            num_nets = packet.mmentry[pointer]

            for net in range(num_nets):
                net_data = packet.mmentry[pointer + net * network_info_size:pointer + (net + 1) * network_info_size]
                dev.add_net(HPAVNetworkInfo.from_bytes(net_data))

            dev.interface = self
            found_list.append(dev)

        return found_list

    def _hpav_station_caps(self, device: PowerlineDevice):
        """ CM_STA_CAP can be used to identify device vendor/OUI for further, vendor specific requests """
        packet = ManagementMessage(device.mac, self.interface_mac)
        packet.mmtype = MMType.CM_STA_CAP.value

        received = self._request(packet)

        for packet in received:
            caps = HPAVStationCapabilities.from_bytes(packet.mmentry[:25])

            if self.verbose:
                print(caps)

            device.oui = caps.oui
            device.hpav_version = caps.avversion

    def _hpav_network_stats(self, device: PowerlineDevice):

        stat_info_size = 10

        packet = ManagementMessage(device.mac, self.interface_mac)
        packet.mmv = 2
        packet.mmtype = MMType.CM_NW_STATS.value

        received = self._request(packet)

        for packet in received:
            num_sta = packet.mmentry[0]
            if self.verbose:
                print(f"{packet.source.pretty}: num_sta={num_sta}")
            for sta in range(num_sta):
                sta_data = packet.mmentry[1 + sta * stat_info_size:1 + (sta + 1) * stat_info_size]
                netstat = HPAVNetworkStats.from_bytes(sta_data)
                if self.verbose:
                    print(f"  STA {sta}: {device.mac.pretty} <-> {netstat.macaddr.pretty} Average PHY Rate: {netstat.txrate} up / {netstat.rxrate} down Mbps")

        # TODO: what to return? Shall we push the discovered data into the individual device object or return
        # TODO: ... related metadata in some other form? Right now it's simply displayed

    def _hpav_network_info(self, device: PowerlineDevice):
        """ Not supported by Broadcom, returns MME_UNSUPPORTED error indication """
        """ Implementation TBD """
        packet = ManagementMessage(device.mac, self.interface_mac)
        packet.mmv = 1
        packet.mmtype = MMType.CM_NW_INFO.value

        received = self._request(packet)

        # TODO: Process response into device fields

    def _hpav_get_hfid(self, device: PowerlineDevice):
        """ Not supported by Broadcom """
        packet = ManagementMessage(device.mac, self.interface_mac)
        packet.mmtype = MMType.CM_HFID.value
        packet.mmentry = struct.pack("!B", HPAVHFIDRequest.GET_USER_HFID.value)

        received = self._request(packet)

        # TODO: Process response into device fields

    def _broadcom_discover(self, device: PowerlineDevice):
        """ Send to broadcast and process responses or use already-discovered MAC to send to? """

        gigle_magic = b"\x01\xa3\x97\xa2\x55\x53\xbe\xf1\xfc\xf9\x79\x6b\x52\x14\x13\xe9\xe2"

        payload = struct.pack(f"!{len(OUI.BROADCOM.value)}s{len(gigle_magic)}s", OUI.BROADCOM.value, gigle_magic)

        packet = ManagementMessage(device.mac, self.interface_mac, EtherType.GIGLE.value)
        packet.mmv = 2
        packet.mmtype = MMType.BROADCOM_DISCOVER.value
        packet.mmentry = payload

        received = self._request(packet)

        for packet in received:
            oui, _tmp, interface, hfid_len = unpack("!3sBBB", packet.mmentry[:6])
            hfid = packet.mmentry[6:6 + hfid_len].decode('utf8')
            device.hfid = hfid

    def _broadcom_get_hfid(self, device: PowerlineDevice, arg: BroadcomHFIDRequest):
        """ Query either a Manufacturer or User HFID (Human-Friendly Identifier) """
        packet = ManagementMessage(device.mac, self.interface_mac, EtherType.GIGLE.value)
        packet.mmv = 2
        packet.mmtype = MMType.BROADCOM_GET_HFID.value
        # FIXME: Figure out what 0x02 is here - avoid magic bytes if possible...
        # Santa please bring me a protocol manual :(
        packet.mmentry = struct.pack(f"!{len(OUI.BROADCOM.value)}sBB", OUI.BROADCOM.value, 0x02, arg.value)

        received = self._request(packet)

        hfid = received[0].payload[12:].decode("utf8")
        device.hfid = hfid

    def _broadcom_network_info(self, device: PowerlineDevice, arg: BroadcomNetworkInfoRequest):
        """ Experimental to check the returned data - Clean me up pls and make me useful """
        packet = ManagementMessage(device.mac, self.interface_mac, EtherType.GIGLE.value)
        packet.mmv = 2
        packet.mmtype = MMType.BROADCOM_NETWORK_INFO.value
        # FIXME: 0x01, 0x00 another magic word...
        packet.mmentry = struct.pack(f"!{len(OUI.BROADCOM.value)}s2sB", OUI.BROADCOM.value, bytes([0x01, 0x00]), arg.value)

        received = self._request(packet)

        data = received[0].payload[9:]
        print(f"Got network data from {received[0].source.pretty}: {data.hex()}")
        number_of_networks = data[0]
        print(f"Number of networks: {number_of_networks}")
        pointer = 1
        for num in range(1, number_of_networks + 1):
            print(f"Info for network {num}")
            chunk = data[pointer:pointer + 19]
            nid, snid, tei, role, ccomac, kind, numnets, status = unpack('!7sBBB6sBBB', chunk)
            pointer = pointer + 19

            netstatus = BroadcomNetworkInformation(nid.hex(), snid, tei, role, MacAddress(ccomac.hex()), kind, numnets,
                                                   status)
            print(netstatus)

            print(f"  Network ID:  {nid.hex()}")
            print(f"  Short Network ID:  {snid}")
            print(f"  Terminal Equipment ID:  {tei}")
            print(f"  Role:  {StationRole(role).name}")
            print(f"  Central Coordinator MAC:  {MacAddress(ccomac.hex()).pretty}")
            print(f"  Kind:  {NetworkKind(kind).name}")
            print(f"  Number of coordinating networks:  {numnets}")
            print(f"  Status:  {PowerlineStatus(status).name}")

        return received

    def discover_devices(self) -> List[PowerlineDevice]:
        devices = self._hpav_discover()

        for dev in devices:
            self._hpav_station_caps(dev)

            # should the stats calls inject their data into the device passed to them as argument, or
            # is it the responsibility of the caller? Not all functions would include discovery e.g. when
            # directly getting/setting values on a specific device.

            self._hpav_network_stats(dev)

            if dev.oui == OUI.BROADCOM:
                if self.verbose:
                    print("Broadcom device detected, using vendor specific requests")
                self._broadcom_discover(dev)
                self._broadcom_get_hfid(dev, BroadcomHFIDRequest.GET_USER_HFID)
                self._broadcom_network_info(dev, BroadcomNetworkInfoRequest.GET_NETWORK_ANY)
            else:
                if self.verbose:
                    print("Generic device, using HPAV standard queries")
                self._hpav_network_info(dev)
                self._hpav_get_hfid(dev)

        return devices
