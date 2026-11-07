"""PCP_TEST_CONF_REPLACE: docker/conf_replace.awk drops the default lines a test's extra lines replace."""
import os
import subprocess
import tempfile
import unittest

AWK_COMMAND = os.environ.get("PCP_TEST_AWK", "awk")     # FreeBSD runs it with its own awk
AWK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docker", "conf_replace.awk")
DEFAULT = """ext_ifname=wan0
enable_upnp=no
enable_pcp_pmp=yes
port=0
max_lifetime=600
allow 1024-65535 0.0.0.0/0 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
"""


def kept(extra):
    """The default lines left with these extra lines."""
    with tempfile.NamedTemporaryFile("w", suffix=".conf", encoding="utf-8") as default:
        default.write(DEFAULT)
        default.flush()
        output = subprocess.run([AWK_COMMAND, "-f", AWK, "-", default.name], input=extra + "\n", text=True,
                                capture_output=True, check=True).stdout
    return output.splitlines()


class ConfReplaceTests(unittest.TestCase):
    def test_a_line_replaces_its_option_only(self):
        lines = kept("enable_upnp=yes")
        self.assertNotIn("enable_upnp=no", lines)
        self.assertEqual(len(lines), len(DEFAULT.splitlines()) - 1)

    def test_synonyms_are_one_option(self):
        self.assertNotIn("enable_pcp_pmp=yes", kept("enable_natpmp=no"))
        self.assertNotIn("port=0", kept("http_port=5000"))

    def test_spaces_around_the_key(self):
        self.assertNotIn("max_lifetime=600", kept(" max_lifetime =60"))

    def test_off_drops_the_default(self):
        self.assertNotIn("max_lifetime=600", kept("max_lifetime=@OFF@"))

    def test_one_permission_line_replaces_them_all(self):
        lines = kept("deny 0-65535 0.0.0.0/0 0-65535")
        self.assertFalse([line for line in lines if line.startswith(("allow", "deny"))])
        self.assertIn("enable_upnp=no", lines)

    def test_permissions_stay_without_one(self):
        self.assertEqual(kept("enable_upnp=yes")[-2:], DEFAULT.splitlines()[-2:])


if __name__ == "__main__":
    unittest.main()
