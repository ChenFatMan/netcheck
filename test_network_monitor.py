import unittest
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import network_monitor as nm


class NetworkMonitorTests(unittest.TestCase):
    def test_phase_durations_are_incremental(self):
        sample = {
            "dns": 0.010,
            "connect": 0.050,
            "tls": 0.200,
            "first_byte": 0.450,
            "total": 2.000,
        }

        phases = nm.phase_durations(sample)

        self.assertAlmostEqual(phases["dns"], 0.010)
        self.assertAlmostEqual(phases["tcp"], 0.040)
        self.assertAlmostEqual(phases["tls"], 0.150)
        self.assertAlmostEqual(phases["server"], 0.250)
        self.assertAlmostEqual(phases["download"], 1.550)

    def test_diagnose_download_when_body_dominates(self):
        samples = [
            {
                "ok": True,
                "dns": 0.010,
                "connect": 0.040,
                "tls": 0.200,
                "first_byte": 0.400,
                "total": 2.100,
                "speed_download": 300000.0,
            },
            {
                "ok": True,
                "dns": 0.020,
                "connect": 0.050,
                "tls": 0.220,
                "first_byte": 0.500,
                "total": 2.200,
                "speed_download": 290000.0,
            },
        ]

        diagnosis = nm.diagnose(nm.summarize_target(samples))

        self.assertIn("body download", diagnosis)

    def test_trace_analysis_reports_private_path_without_false_sustained_jump(self):
        trace = """traceroute to gitee.com (180.76.199.13), 15 hops max
 1  *
 2  192.168.70.1 (192.168.70.1)  5.421 ms
 8  219.158.123.150 (219.158.123.150)  110.084 ms
11  119.188.170.118 (119.188.170.118)  36.077 ms
"""

        analysis = nm.analyze_trace(trace)

        self.assertIn("private gateway path", analysis)
        self.assertIn("no sustained latency jump", analysis)

    def test_parse_route_gateway(self):
        route = """$ route -n get 180.76.199.13
   route to: 180.76.199.13
destination: default
    gateway: 192.168.110.1
  interface: en0
"""

        self.assertEqual(nm.parse_route_gateway(route), "192.168.110.1")

    def test_trace_key_nodes_include_gateway_public_and_last_hop(self):
        trace = """traceroute to gitee.com (180.76.199.13), 15 hops max
 1  *
 2  192.168.70.1 (192.168.70.1)  5.421 ms
 7  202.96.12.61 (202.96.12.61)  15.625 ms
 8  219.158.123.150 (219.158.123.150)  110.084 ms
11  119.188.170.118 (119.188.170.118)  36.077 ms
"""

        nodes = nm.trace_key_nodes(trace)
        roles = [node["role"] for node in nodes]

        self.assertIn("private gateway", roles)
        self.assertIn("first public hop", roles)
        self.assertIn("highest visible latency", roles)
        self.assertIn("last visible hop", roles)

    def test_trace_records_do_not_pollute_samples(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "samples.jsonl"
            nm.write_jsonl(path, {"target": "baidu", "ok": True, "total": 0.2})
            nm.write_jsonl(path, {"record_type": "trace", "sections": ["trace section"]})

            samples = nm.load_samples(path)
            sections = nm.load_trace_sections(path)

        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0]["target"], "baidu")
        self.assertEqual(sections, ["trace section"])


if __name__ == "__main__":
    unittest.main()
