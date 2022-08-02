#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The ios legacy fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


import platform
import re

from ansible_collections.cisco.ios.plugins.module_utils.network.ios.ios import (
    run_commands,
    get_capabilities,
)
from ansible_collections.cisco.ios.plugins.module_utils.network.ios.ios import (
    normalize_interface,
)
from ansible.module_utils.six import iteritems
from ansible.module_utils.six.moves import zip


class FactsBase(object):

    COMMANDS = list()

    def __init__(self, module):
        self.module = module
        self.facts = {}
        self.warnings = []
        self.responses = None

    def populate(self):
        self.responses = run_commands(
            self.module, commands=self.COMMANDS, check_rc=False
        )

    def run(self, cmd):
        return run_commands(self.module, commands=cmd, check_rc=False)


class Default(FactsBase):

    COMMANDS = ["show version", "show virtual switch"]

    def populate(self):
        super(Default, self).populate()
        self.facts.update(self.platform_facts())
        data = self.responses[0]
        if data:
            self.facts["iostype"] = self.parse_iostype(data)
            self.facts["serialnum"] = self.parse_serialnum(data)
            self.parse_stacks(data)
        data = self.responses[1]
        vss_errs = ["Invalid input", "Switch Mode : Standalone"]
        if data and all(err not in data for err in vss_errs):
            self.parse_virtual_switch(data)

    def parse_iostype(self, data):
        return "IOS-XE" if (match := re.search(r"\sIOS-XE\s", data)) else "IOS"

    def parse_serialnum(self, data):
        if match := re.search(r"board ID (\S+)", data):
            return match[1]

    def parse_stacks(self, data):
        if match := re.findall(r"^Model [Nn]umber\s+: (\S+)", data, re.M):
            self.facts["stacked_models"] = match

        if match := re.findall(
            r"^System [Ss]erial [Nn]umber\s+: (\S+)", data, re.M
        ):
            self.facts["stacked_serialnums"] = match

        if "stacked_models" in self.facts:
            self.facts["virtual_switch"] = "STACK"

    def parse_virtual_switch(self, data):
        if match := re.search(
            r"^Virtual switch domain number : ([0-9]+)", data, re.M
        ):
            self.facts["virtual_switch"] = "VSS"
            self.facts["virtual_switch_domain"] = match[1]

    def platform_facts(self):
        resp = get_capabilities(self.module)
        device_info = resp["device_info"]

        platform_facts = {"system": device_info["network_os"]}
        for item in ("model", "image", "version", "platform", "hostname"):
            if val := device_info.get(f"network_os_{item}"):
                platform_facts[item] = val

        platform_facts["api"] = resp["network_api"]
        platform_facts["python_version"] = platform.python_version()

        return platform_facts


class Hardware(FactsBase):

    COMMANDS = ["dir", "show memory statistics"]

    def populate(self):
        super(Hardware, self).populate()
        if data := self.responses[0]:
            self.facts["filesystems"] = self.parse_filesystems(data)
            self.facts["filesystems_info"] = self.parse_filesystems_info(data)

        if data := self.responses[1]:
            if "Invalid input detected" in data:
                warnings = ["Unable to gather memory statistics"]
            else:
                processor_line = [
                    l for l in data.splitlines() if "Processor" in l
                ].pop()
                if match := re.findall(r"\s(\d+)\s", processor_line):
                    self.facts["memtotal_mb"] = int(match[0]) / 1024
                    self.facts["memfree_mb"] = int(match[3]) / 1024

    def parse_filesystems(self, data):
        return re.findall(r"^Directory of (\S+)/", data, re.M)

    def parse_filesystems_info(self, data):
        facts = {}
        fs = ""
        for line in data.split("\n"):
            if match := re.match(r"^Directory of (\S+)/", line):
                fs = match[1]
                facts[fs] = {}
                continue
            if match := re.match(r"^(\d+) bytes total \((\d+) bytes free\)", line):
                facts[fs]["spacetotal_kb"] = int(match[1]) / 1024
                facts[fs]["spacefree_kb"] = int(match[2]) / 1024
        return facts


class Config(FactsBase):

    COMMANDS = ["show running-config"]

    def populate(self):
        super(Config, self).populate()
        if data := self.responses[0]:
            data = re.sub(
                r"^Building configuration...\s+Current configuration : \d+ bytes\n",
                "",
                data,
                flags=re.MULTILINE,
            )
            self.facts["config"] = data


class Interfaces(FactsBase):

    COMMANDS = [
        "show interfaces",
        "show ip interface",
        "show ipv6 interface",
        "show lldp",
        "show cdp",
    ]

    def populate(self):
        super(Interfaces, self).populate()

        self.facts["all_ipv4_addresses"] = []
        self.facts["all_ipv6_addresses"] = []
        self.facts["neighbors"] = {}

        data = self.responses[0]
        if data:
            interfaces = self.parse_interfaces(data)
            self.facts["interfaces"] = self.populate_interfaces(interfaces)

        data = self.responses[1]
        if data:
            data = self.parse_interfaces(data)
            self.populate_ipv4_interfaces(data)

        data = self.responses[2]
        if data:
            data = self.parse_interfaces(data)
            self.populate_ipv6_interfaces(data)

        data = self.responses[3]
        lldp_errs = ["Invalid input", "LLDP is not enabled"]

        if data and all(err not in data for err in lldp_errs):
            if neighbors := self.run(["show lldp neighbors detail"]):
                self.facts["neighbors"].update(
                    self.parse_neighbors(neighbors[0])
                )

        data = self.responses[4]
        cdp_errs = ["CDP is not enabled"]

        if data and all(err not in data for err in cdp_errs):
            if cdp_neighbors := self.run(["show cdp neighbors detail"]):
                self.facts["neighbors"].update(
                    self.parse_cdp_neighbors(cdp_neighbors[0])
                )

    def populate_interfaces(self, interfaces):
        facts = {}
        for key, value in iteritems(interfaces):
            intf = {"description": self.parse_description(value)}
            intf["macaddress"] = self.parse_macaddress(value)

            intf["mtu"] = self.parse_mtu(value)
            intf["bandwidth"] = self.parse_bandwidth(value)
            intf["mediatype"] = self.parse_mediatype(value)
            intf["duplex"] = self.parse_duplex(value)
            intf["lineprotocol"] = self.parse_lineprotocol(value)
            intf["operstatus"] = self.parse_operstatus(value)
            intf["type"] = self.parse_type(value)

            facts[key] = intf
        return facts

    def populate_ipv4_interfaces(self, data):
        for key, value in data.items():
            self.facts["interfaces"][key]["ipv4"] = []
            primary_address = addresses = []
            primary_address = re.findall(
                r"Internet address is (.+)$", value, re.M
            )
            addresses = re.findall(r"Secondary address (.+)$", value, re.M)
            if len(primary_address) == 0:
                continue
            addresses.append(primary_address[0])
            for address in addresses:
                addr, subnet = address.split("/")
                ipv4 = dict(address=addr.strip(), subnet=subnet.strip())
                self.add_ip_address(addr.strip(), "ipv4")
                self.facts["interfaces"][key]["ipv4"].append(ipv4)

    def populate_ipv6_interfaces(self, data):
        for key, value in iteritems(data):
            try:
                self.facts["interfaces"][key]["ipv6"] = []
            except KeyError:
                self.facts["interfaces"][key] = {"ipv6": []}
            addresses = re.findall(r"\s+(.+), subnet", value, re.M)
            subnets = re.findall(r", subnet is (.+)$", value, re.M)
            for addr, subnet in zip(addresses, subnets):
                ipv6 = dict(address=addr.strip(), subnet=subnet.strip())
                self.add_ip_address(addr.strip(), "ipv6")
                self.facts["interfaces"][key]["ipv6"].append(ipv6)

    def add_ip_address(self, address, family):
        if family == "ipv4":
            self.facts["all_ipv4_addresses"].append(address)
        else:
            self.facts["all_ipv6_addresses"].append(address)

    def parse_neighbors(self, neighbors):
        facts = {}
        for entry in neighbors.split(
            "------------------------------------------------"
        ):
            if entry == "":
                continue
            intf = self.parse_lldp_intf(entry)
            if intf is None:
                return facts
            intf = normalize_interface(intf)
            if intf not in facts:
                facts[intf] = []
            fact = {"host": self.parse_lldp_host(entry)}
            fact["port"] = self.parse_lldp_port(entry)
            facts[intf].append(fact)
        return facts

    def parse_cdp_neighbors(self, neighbors):
        facts = {}
        for entry in neighbors.split("-------------------------"):
            if entry == "":
                continue
            intf_port = self.parse_cdp_intf_port(entry)
            if intf_port is None:
                return facts
            intf, port = intf_port
            if intf not in facts:
                facts[intf] = []
            fact = {"host": self.parse_cdp_host(entry)}
            fact["platform"] = self.parse_cdp_platform(entry)
            fact["port"] = port
            facts[intf].append(fact)
        return facts

    def parse_interfaces(self, data):
        parsed = {}
        key = ""
        for line in data.split("\n"):
            if len(line) == 0:
                continue
            if line[0] == " ":
                parsed[key] += "\n%s" % line
            elif match := re.match(r"^(\S+)", line):
                key = match[1]
                parsed[key] = line
        return parsed

    def parse_description(self, data):
        if match := re.search(r"Description: (.+)$", data, re.M):
            return match[1]

    def parse_macaddress(self, data):
        if match := re.search(r"Hardware is (?:.*), address is (\S+)", data):
            return match[1]

    def parse_ipv4(self, data):
        if match := re.search(r"Internet address is (\S+)", data):
            addr, masklen = match[1].split("/")
            return dict(address=addr, masklen=int(masklen))

    def parse_mtu(self, data):
        if match := re.search(r"MTU (\d+)", data):
            return int(match[1])

    def parse_bandwidth(self, data):
        if match := re.search(r"BW (\d+)", data):
            return int(match[1])

    def parse_duplex(self, data):
        if match := re.search(r"(\w+) Duplex", data, re.M):
            return match[1]

    def parse_mediatype(self, data):
        if match := re.search(r"media type is (.+)$", data, re.M):
            return match[1]

    def parse_type(self, data):
        if match := re.search(r"Hardware is (.+),", data, re.M):
            return match[1]

    def parse_lineprotocol(self, data):
        if match := re.search(r"line protocol is (\S+)\s*$", data, re.M):
            return match[1]

    def parse_operstatus(self, data):
        if match := re.search(r"^(?:.+) is (.+),", data, re.M):
            return match[1]

    def parse_lldp_intf(self, data):
        if match := re.search(r"^Local Intf: (.+)$", data, re.M):
            return match[1]

    def parse_lldp_host(self, data):
        if match := re.search(r"System Name: (.+)$", data, re.M):
            return match[1]

    def parse_lldp_port(self, data):
        if match := re.search(r"Port id: (.+)$", data, re.M):
            return match[1]

    def parse_cdp_intf_port(self, data):
        if match := re.search(
            r"^Interface: (.+),  Port ID \(outgoing port\): (.+)$", data, re.M
        ):
            return match[1], match[2]

    def parse_cdp_host(self, data):
        if match := re.search(r"^Device ID: (.+)$", data, re.M):
            return match[1]

    def parse_cdp_platform(self, data):
        if match := re.search(r"^Platform: (.+),", data, re.M):
            return match[1]
