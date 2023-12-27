#!/usr/bin/env python3

import os
import sys
import argparse

from scapy.all import *


def get_default_interface() -> str:
    return conf.iface.name


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="hpavcli - Powerline (HPAV) management and query utility")
    parser.add_argument('--interface', '-i',
                        type=str,
                        help="Comma separated list of interfaces to search for devices")
    parser.add_argument('--verbose', '-v',
                        action='store_true',
                        help="Verbose mode")
    parser.add_argument('command',
                        choices=['scan', 'networks'],
                        default='scan')
    return parser.parse_args()


def main(in_args: argparse.Namespace):
    if in_args.interface:
        interface_list = in_args.interface.split(',')
    else:
        interface_list = [get_default_interface()]

    interfaces = list()
    for iface in interface_list:
        try:
            interfaces.append(PowerlineInterface(ifaces.dev_from_name(iface), verbose=in_args.verbose))
        except (ValueError, PermissionError) as exc:
            print(f"Error creating PowerlineInterface for {iface}: {exc}")

    if not len(interfaces):
        print("No ethernet interfaces could be initialized, exiting.")
        sys.exit(-1)

    if in_args.command == "scan":
        devices = []
        for iface in interfaces:
            devices.extend(iface.discover_devices())

        for device in devices:
            print(
                f"[{device.interface.interface_name}] {device.mac.pretty} ({HPAVVersion(device.hpav_version).name} "
                f"{OUI(device.oui).name}) STAs:{len(device.sta_list)} NETs:{len(device.net_list)} HFID:'{device.hfid}'")
            for net in device.networks():
                print(f"  {net}")

    elif args.command == "networks":
        for iface in interfaces:
            iface.discover_networks()


if __name__ == "__main__":
    app_dir = os.path.abspath(os.path.dirname(__file__))
    sys.path.append(app_dir)

    from venvtools import activate
    activate(app_dir)

    from interface import *

    args = parse_args()
    main(args)
