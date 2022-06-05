import sys
import os
import socket
import pytest
import netifaces

BASEDIR = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(BASEDIR, ".."))

from model import MacAddress
from interface import PowerlineInterface


def test_powerlineinterface_init_noarg() -> None:
    """PowerlineInterface constructor without argument should fail"""
    with pytest.raises(TypeError):
        pli = PowerlineInterface()


def test_powerlineinterface_init(monkeypatch) -> None:

    ifname = "testinterface0"
    ifaddr = "112233445566"

    def mock_ifaddresses(iface_name: str):
        return {netifaces.AF_LINK: [{"addr": ifaddr}]}

    class MockSocket:
        def __init__(self, **args):
            pass

        def bind(self, *args):
            return True

    def mock_socket(*args):
        return MockSocket()

    monkeypatch.setattr(netifaces, "ifaddresses", mock_ifaddresses)
    monkeypatch.setattr(socket, "socket", mock_socket)

    pli = PowerlineInterface(ifname)

    assert pli.interface_name == ifname
    assert pli.interface_mac == MacAddress(ifaddr)
