import sys
import os
import pytest

BASEDIR = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(BASEDIR, ".."))

from model import MacAddress, EthernetPacket, ManagementMessage, BinaryData


def test_macaddress_noparam() -> None:
    """MacAddress constructor without arguments expected to fail with TypeError"""
    with pytest.raises(TypeError):
        addr = MacAddress()


def test_macaddress_wrong_len() -> None:
    """Test for a MAC address without colon and wrong length"""
    with pytest.raises(ValueError):
        addr = MacAddress('1234567890123')


def test_macaddress_6bytes() -> None:
    """MAC address with colon notation should consist of 6 groups"""
    with pytest.raises(ValueError):
        addr = MacAddress('11:22:33:44:55:66:77')


def test_macaddress_nobyte() -> None:
    """MAC address with colon notation should have members with byte size"""
    with pytest.raises(ValueError):
        addr = MacAddress('11:222:33:44:55:66')


def test_macaddress_lower() -> None:
    """MAC address internally converted to lowercase"""
    addr = MacAddress('11:AA:33:44:55:66')
    assert addr.address == '11aa33445566'


def test_macaddress_lower2() -> None:
    """MAC address internally converted to lowercase"""
    addr = MacAddress('11AA33445566')
    assert addr.address == '11aa33445566'


def test_macaddr_eq() -> None:
    """MAC address equality is case-insensitive"""
    addr1 = MacAddress('1122334455aa')
    addr2 = MacAddress('1122334455AA')
    assert addr1 == addr2


def test_macaddr_as_bytes() -> None:
    addstr = '112233445566'
    addr = MacAddress(addstr)
    as_bytes = addr.as_bytes()
    assert as_bytes == b'\x11\x22\x33\x44\x55\x66'


def test_macaddr_pretty() -> None:
    addr = MacAddress('112233445566')
    assert addr.pretty == "11:22:33:44:55:66"


def test_macaddr_from_bytes() -> None:
    addr = MacAddress.from_bytes(b'\x11\x22\x33\x44\x55\x66')
    assert addr == MacAddress('112233445566')


def test_ethernetpacket_noarg() -> None:
    with pytest.raises(TypeError):
        packet = EthernetPacket()


def test_ethernetpacket_init() -> None:
    p1 = MacAddress('112233445566')
    p2 = MacAddress('223344556677')
    etype = b'\x11\x22'
    payload = b'\xaa\xbb\xcc'
    pack = EthernetPacket(p1, p2, etype, payload)
    assert pack.dest == p1
    assert pack.source == p2
    assert pack.ethertype == etype
    assert pack.payload == payload


def test_ethernetpacket_as_bytes() -> None:
    p1 = MacAddress('112233445566')
    p2 = MacAddress('223344556677')
    etype = b'\x11\x22'
    payload = b'\xaa\xbb\xcc'
    pack = EthernetPacket(p1, p2, etype, payload)
    assert pack.as_bytes() == p1.as_bytes() + p2.as_bytes() + etype + payload


def test_ethernetpacket_from_bytes() -> None:
    p1 = MacAddress('112233445566')
    p2 = MacAddress('223344556677')
    etype = b'\x11\x22'
    payload = b'\xaa\xbb\xcc'
    pack = EthernetPacket(p1, p2, etype, payload)
    pack2 = EthernetPacket.from_bytes(pack.as_bytes())
    assert pack.dest == pack2.dest
    assert pack.source == pack2.source
    assert pack.ethertype == pack2.ethertype
    assert pack.payload == pack2.payload


def test_managementmessage_init() -> None:
    p1 = MacAddress('112233445566')
    p2 = MacAddress('223344556677')
    msg = ManagementMessage(p1, p2)
    assert msg.mmv == 1
    assert msg.mmtype is None
    assert msg.fmi == 0
    assert msg.fmsn == 0
    assert msg.mmentry == bytes()


def test_managementmessage_payload_padding() -> None:
    p1 = MacAddress('112233445566')
    p2 = MacAddress('223344556677')
    pl = b'\x11\x22\x33\x44\x55'
    msg = ManagementMessage(p1, p2, payload=pl)
    # test if payload is padded to 60 bytes
    assert len(msg.payload) == 60


def test_managementmessage_props() -> None:
    p1 = MacAddress('112233445566')
    p2 = MacAddress('223344556677')
    msg = ManagementMessage(p1, p2)
    msg.mmv = 42
    assert msg.mmv == 42
    msg.mmtype = 42
    assert msg.mmtype == 42
    msg.fmi = 42
    assert msg.fmi == 42
    msg.fmsn = 42
    assert msg.fmsn == 42
    # 42(dec) == 0b101010
    assert msg.subtype == 0b10
    assert msg.mmbase == 0b101000


def test_binarydata_noarg() -> None:
    with pytest.raises(TypeError):
        bd = BinaryData.from_bytes(None)
