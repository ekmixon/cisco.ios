#
# (c) 2019, Ansible by Red Hat, inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
from __future__ import absolute_import, division, print_function

__metaclass__ = type
import re

from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.cisco.ios.plugins.module_utils.network.ios.providers.providers import (
    register_provider,
)
from ansible_collections.cisco.ios.plugins.module_utils.network.ios.providers.providers import (
    CliProvider,
)
from ansible_collections.cisco.ios.plugins.module_utils.network.ios.providers.cli.config.bgp.neighbors import (
    Neighbors,
)
from ansible_collections.cisco.ios.plugins.module_utils.network.ios.providers.cli.config.bgp.address_family import (
    AddressFamily,
)
from ansible.module_utils.common.network import to_netmask

REDISTRIBUTE_PROTOCOLS = [
    "ospf",
    "ospfv3",
    "eigrp",
    "isis",
    "static",
    "connected",
    "odr",
    "lisp",
    "mobile",
    "rip",
]


@register_provider("ios", "ios_bgp")
class Provider(CliProvider):
    def render(self, config=None):
        commands = []

        existing_as = None
        if config:
            if match := re.search(r"router bgp (\d+)", config, re.M):
                existing_as = match[1]

        operation = self.params["operation"]

        context = None
        if self.params["config"]:
            context = f'router bgp {self.get_value("config.bgp_as")}'

        if operation == "delete":
            if existing_as:
                commands.append(f"no router bgp {existing_as}")
            elif context:
                commands.append(f"no {context}")

        else:
            self._validate_input(config)
            if operation == "replace":
                if existing_as and int(existing_as) != self.get_value(
                    "config.bgp_as"
                ):
                    commands.append(f"no router bgp {existing_as}")
                    config = None

            elif operation == "override":
                if existing_as:
                    commands.append(f"no router bgp {existing_as}")
                config = None

            context_commands = []

            for key, value in iteritems(self.get_value("config")):
                if value is not None:
                    if meth := getattr(self, f"_render_{key}", None):
                        if resp := meth(config):
                            context_commands.extend(to_list(resp))

            if context and context_commands:
                commands.append(context)
                commands.extend(context_commands)
                commands.append("exit")
        return commands

    def _render_router_id(self, config=None):
        cmd = f'bgp router-id {self.get_value("config.router_id")}'
        if not config or cmd not in config:
            return cmd

    def _render_log_neighbor_changes(self, config=None):
        cmd = "bgp log-neighbor-changes"
        log_neighbor_changes = self.get_value("config.log_neighbor_changes")
        if log_neighbor_changes is True:
            if not config or cmd not in config:
                return cmd
        elif log_neighbor_changes is False:
            if config and cmd in config:
                return f"no {cmd}"

    def _render_networks(self, config=None):
        commands = []
        safe_list = []

        for entry in self.get_value("config.networks"):
            network = entry["prefix"]
            cmd = f"network {network}"
            if entry["masklen"] and entry["masklen"] not in (24, 16, 8):
                cmd += f' mask {to_netmask(entry["masklen"])}'
                network += f' mask {to_netmask(entry["masklen"])}'

            if entry["route_map"]:
                cmd += f' route-map {entry["route_map"]}'
                network += f' route-map {entry["route_map"]}'

            safe_list.append(network)

            if not config or cmd not in config:
                commands.append(cmd)

        if self.params["operation"] == "replace" and config:
            matches = re.findall(r"network (.*)", config, re.M)
            commands.extend(
                f"no network {entry}"
                for entry in set(matches).difference(safe_list)
            )

        return commands

    def _render_neighbors(self, config):
        """ generate bgp neighbor configuration
        """
        return Neighbors(self.params).render(config)

    def _render_address_family(self, config):
        """ generate address-family configuration
        """
        return AddressFamily(self.params).render(config)

    def _validate_input(self, config=None):
        def device_has_AF(config):
            return re.search(r"address-family (?:.*)", config)

        address_family = self.get_value("config.address_family")
        root_networks = self.get_value("config.networks")
        operation = self.params["operation"]

        if operation == "replace":
            if address_family and root_networks:
                for item in address_family:
                    if item["networks"]:
                        raise ValueError(
                            f'operation is replace but provided both root level network(s) and network(s) under {item["afi"]} {item["safi"]} address family'
                        )


            if root_networks and config and device_has_AF(config):
                raise ValueError(
                    "operation is replace and device has one or more address family activated but root level network(s) provided"
                )
