from netmiko.cisco.cisco_ios import CiscoIosSSH

class MockCiscoSSH(CiscoIosSSH):
    def set_terminal_width(self, *args, **kwargs):
        """Skip terminal width setup — mock server doesn't support it."""
        return ""