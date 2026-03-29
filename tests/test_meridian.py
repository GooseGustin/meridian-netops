# tests/test_meridian.py
from pyats import aetest
from genie.testbed import load
import logging
import time
import json 

logger = logging.getLogger(__name__)


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def load_testbed(self, testbed):
        # testbed is already a loaded Testbed object — loaded in __main__ before aetest.main()
        logger.info(f"Testbed devices: {list(testbed.devices.keys())}")

    @aetest.subsection
    def connect_devices(self, testbed):
        for name, device in testbed.devices.items():
            try:
                device.connect(log_stdout=False)
                logger.info(f"Connected to {name}")
            except Exception as e:
                self.failed(f"Cannot connect to {name}: {e}")


class OSPFTests(aetest.Testcase):
    @aetest.test
    def test_ospf_neighbor_count(self, testbed):
        r1 = testbed.devices["R1"]
        parsed = r1.parse("show ip ospf neighbor")
        # Genie returns: {"interfaces": {"Fa0/2": {"neighbors": {"2.2.2.2": {...}}}}}
        total_neighbors = sum(
            len(iface_data.get("neighbors", {}))
            for iface_data in parsed.get("interfaces", {}).values()
        )
        assert total_neighbors == 2, \
            f"R1 expected 2 OSPF neighbors, found {total_neighbors}"

    @aetest.test
    def test_ospf_all_full(self, testbed):
        r1 = testbed.devices["R1"]
        parsed = r1.parse("show ip ospf neighbor")
        for iface, iface_data in parsed.get("interfaces", {}).items():
            for neighbor_id, neighbor_data in iface_data.get("neighbors", {}).items():
                state = neighbor_data.get("state", "")
                assert "FULL" in state.upper(), \
                    f"Neighbor {neighbor_id} on {iface} is in state '{state}', expected FULL"


class BGPTests(aetest.Testcase):
    @aetest.test
    def test_bgp_sessions_established(self, testbed):
        r4 = testbed.devices["R4"]
        parsed = r4.parse("show bgp summary")
        neighbors = (parsed.get("vrf", {})
                         .get("default", {})
                         .get("neighbor", {}))
        for neighbor_ip, data in neighbors.items():
            # Genie iosxe structure: state_pfxrcd lives inside address_family,
            # not directly on the neighbor dict. data.get("state_pfxrcd") returns
            # empty string — must iterate address_family values.
            established = False
            for af_data in data.get("address_family", {}).values():
                state = str(af_data.get("state_pfxrcd", ""))
                if state.isdigit():
                    established = True
                    break
            assert established, \
                f"BGP neighbor {neighbor_ip} not established (no numeric state_pfxrcd found)"

    @aetest.test
    def test_branch_prefix_reachable(self, testbed):
        r4 = testbed.devices["R4"]
        parsed = r4.parse("show ip route")
        bgp_routes = parsed.get("vrf", {}).get("default", {}).get("address_family", {})
        branch_prefix_found = False
        for af, af_data in bgp_routes.items():
            for prefix in af_data.get("routes", {}).keys():
                if "10.100" in prefix:
                    branch_prefix_found = True
        assert branch_prefix_found, "Branch prefix 10.100.0.0/16 not in R4 routing table"


class SecurityTests(aetest.Testcase):
    @aetest.test
    def test_mgmt_acl_present(self, testbed):
        for name, device in testbed.devices.items():
            # Use execute instead of parse — Genie raises SchemaEmptyParserError
            # when all ACL entries have zero hit counts, even if the ACL exists.
            output = device.execute("show ip access-lists")
            assert "MGMT-ACCESS" in output, \
                f"{name}: MGMT-ACCESS ACL missing"

    @aetest.test
    def test_no_telnet_vty(self, testbed):
        for name, device in testbed.devices.items():
            output = device.execute("show running-config | include transport input")
            assert "telnet" not in output.lower(), \
                f"{name}: Telnet is permitted on VTY lines"


class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for device in testbed.devices.values():
            try:
                device.disconnect()
            except Exception:
                pass



class BGPStabilityTests(aetest.Testcase):
    @aetest.test
    def test_bgp_route_stability(self, testbed):
        r4 = testbed.devices["R4"]

        # Snapshot 1
        parsed1 = r4.parse("show ip bgp")
        print(json.dumps(parsed1, indent=2))
        snapshot1 = self._extract_routes(parsed1)
        logger.info(f"Snapshot 1: {len(snapshot1)} BGP prefixes")

        time.sleep(30)

        # Snapshot 2
        parsed2 = r4.parse("show ip bgp")
        print(json.dumps(parsed2, indent=2))
        snapshot2 = self._extract_routes(parsed2)
        logger.info(f"Snapshot 2: {len(snapshot2)} BGP prefixes")

        # Compare
        failures = []

        for prefix, next_hop in snapshot1.items():
            if prefix not in snapshot2:
                failures.append(f"Prefix {prefix} disappeared between snapshots")
            elif snapshot2[prefix] != next_hop:
                failures.append(
                    f"Prefix {prefix} next-hop changed: {next_hop} → {snapshot2[prefix]}"
                )

        assert not failures, "BGP route instability detected:\n" + "\n".join(failures)

    def _extract_routes(self, parsed):
        """
        Extract {prefix: next_hop} from Genie's show ip bgp output.
        Genie structure: parsed["vrf"]["default"]["address_family"]["ipv4 unicast"]["prefixes"]
        Each prefix entry has "index" -> {1: {"next_hop": "x.x.x.x", ...}}
        """
        routes = {}
        try:
            prefixes = (parsed
                        .get("vrf", {})
                        .get("default", {})
                        .get("address_family", {})
                        .get("ipv4 unicast", {})
                        .get("prefixes", {}))
            for prefix, data in prefixes.items():
                # Take the best path (index 1)
                best = data.get("index", {}).get(1, {})
                next_hop = best.get("next_hop", "unknown")
                routes[prefix] = next_hop
        except Exception:
            pass
        return routes


if __name__ == "__main__":
    import argparse
    from genie.testbed import load as load_testbed_yaml
    parser = argparse.ArgumentParser()
    parser.add_argument("--testbed", default="tests/testbed.yaml")
    args, unknown = parser.parse_known_args()
    # Load the testbed object BEFORE passing to aetest.main().
    # If you pass a path string, pyATS injects the string into every test method
    # that declares a `testbed` parameter — testbed.devices then fails with
    # AttributeError: 'str' object has no attribute 'devices'.
    # Passing a loaded Testbed object fixes this.
    aetest.main(testbed=load_testbed_yaml(args.testbed))