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
    CliProvider,
)
from ansible_collections.cisco.ios.plugins.module_utils.network.ios.providers.cli.config.bgp.neighbors import (
    AFNeighbors,
)
from ansible.module_utils.common.network import to_netmask


class AddressFamily(CliProvider):
    def render(self, config=None):
        commands = []
        safe_list = []

        router_context = f'router bgp {self.get_value("config.bgp_as")}'
        context_config = None

        for item in self.get_value("config.address_family"):
            context = f'address-family {item["afi"]}'
            if item["safi"] != "unicast":
                context += f' {item["safi"]}'
            context_commands = []

            if config:
                context_path = [router_context, context]
                context_config = self.get_config_context(
                    config, context_path, indent=1
                )

            for key, value in iteritems(item):
                if value is not None:
                    if meth := getattr(self, f"_render_{key}", None):
                        if resp := meth(item, context_config):
                            context_commands.extend(to_list(resp))

            if context_commands:
                commands.append(context)
                commands.extend(context_commands)
                commands.append("exit-address-family")

            safe_list.append(context)

        if self.params["operation"] == "replace" and config:
            resp = self._negate_config(config, safe_list)
            commands.extend(resp)

        return commands

    def _negate_config(self, config, safe_list=None):
        matches = re.findall(r"(address-family .+)$", config, re.M)
        return [f"no {item}" for item in set(matches).difference(safe_list)]

    def _render_auto_summary(self, item, config=None):
        cmd = "auto-summary"
        if item["auto_summary"] is False:
            cmd = f"no {cmd}"
        if not config or cmd not in config:
            return cmd

    def _render_synchronization(self, item, config=None):
        cmd = "synchronization"
        if item["synchronization"] is False:
            cmd = f"no {cmd}"
        if not config or cmd not in config:
            return cmd

    def _render_networks(self, item, config=None):
        commands = []
        safe_list = []

        for entry in item["networks"]:
            network = entry["prefix"]
            cmd = f"network {network}"
            if entry["masklen"]:
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

    def _render_redistribute(self, item, config=None):
        commands = []
        safe_list = []

        for entry in item["redistribute"]:
            option = entry["protocol"]

            cmd = f'redistribute {entry["protocol"]}'

            if entry["id"] and entry["protocol"] in (
                "ospf",
                "ospfv3",
                "eigrp",
            ):
                cmd += f' {entry["id"]}'
                option += f' {entry["id"]}'

            if entry["metric"]:
                cmd += f' metric {entry["metric"]}'

            if entry["route_map"]:
                cmd += f' route-map {entry["route_map"]}'

            if not config or cmd not in config:
                commands.append(cmd)

            safe_list.append(option)

        if self.params["operation"] == "replace" and config:
            matches = re.findall(
                r"redistribute (\S+)(?:\s*)(\d*)", config, re.M
            )
            for i in range(len(matches)):
                matches[i] = " ".join(matches[i]).strip()
            commands.extend(
                f"no redistribute {entry}"
                for entry in set(matches).difference(safe_list)
            )

        return commands

    def _render_neighbors(self, item, config):
        """ generate bgp neighbor configuration
        """
        return AFNeighbors(self.params).render(
            config, nbr_list=item["neighbors"]
        )
