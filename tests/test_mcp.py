import io
import json
import unittest

from ihc import __version__, mcp


class HandleTests(unittest.TestCase):
    def tearDown(self):
        mcp.DISPATCH = None

    def test_initialize(self):
        resp = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(
            resp,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "ihc", "version": __version__},
                },
            },
        )

    def test_notifications_initialized_ignored(self):
        resp = mcp.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.assertIsNone(resp)

    def test_ping(self):
        resp = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "ping"})
        self.assertEqual(resp, {"jsonrpc": "2.0", "id": 2, "result": {}})

    def test_tools_list(self):
        resp = mcp.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
        names = {t["name"] for t in resp["result"]["tools"]}
        self.assertEqual(names, {"status", "facts", "check", "bump", "fix", "docs_check"})
        for tool in resp["result"]["tools"]:
            self.assertIn("description", tool)
            self.assertIn("inputSchema", tool)

    def test_tools_call_check(self):
        calls = []

        def fake_dispatch(argv):
            calls.append(argv)
            return (0, "all good")

        mcp.DISPATCH = fake_dispatch
        resp = mcp.handle(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "check", "arguments": {"target": "hm"}},
            }
        )
        self.assertEqual(calls, [["check", "--target", "hm"]])
        self.assertEqual(
            resp,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "result": {"content": [{"type": "text", "text": "all good"}], "isError": False},
            },
        )

    def test_tools_call_error_exit(self):
        mcp.DISPATCH = lambda argv: (1, "boom")
        resp = mcp.handle(
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "status", "arguments": {}}}
        )
        self.assertTrue(resp["result"]["isError"])
        self.assertEqual(resp["result"]["content"][0]["text"], "boom")

    def test_tools_call_exception_does_not_crash(self):
        def raising_dispatch(argv):
            raise RuntimeError("kaboom")

        mcp.DISPATCH = raising_dispatch
        resp = mcp.handle(
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "facts", "arguments": {}}}
        )
        self.assertTrue(resp["result"]["isError"])
        self.assertIn("kaboom", resp["result"]["content"][0]["text"])

    def test_unknown_method(self):
        resp = mcp.handle({"jsonrpc": "2.0", "id": 7, "method": "bogus"})
        self.assertEqual(resp["error"]["code"], -32601)


class ServeTests(unittest.TestCase):
    def tearDown(self):
        mcp.DISPATCH = None

    def test_serve_end_to_end(self):
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "ping"},
        ]
        stdin = io.StringIO("\n".join(json.dumps(r) for r in requests) + "\n")
        stdout = io.StringIO()
        mcp.serve(stdin=stdin, stdout=stdout)
        lines = [l for l in stdout.getvalue().splitlines() if l.strip()]
        self.assertEqual(len(lines), 2)
        responses = [json.loads(l) for l in lines]
        self.assertEqual(responses[0]["id"], 1)
        self.assertEqual(responses[1]["id"], 2)


if __name__ == "__main__":
    unittest.main()


class FixWithoutTargetTests(unittest.TestCase):
    def test_fix_defaults_target_to_all(self):
        from ihc import mcp
        seen = {}
        mcp.DISPATCH = lambda argv: seen.setdefault("argv", argv) and (0, "ok") or (0, "ok")
        try:
            res = mcp.handle({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "fix", "arguments": {}}})
        finally:
            mcp.DISPATCH = None
        self.assertEqual(seen["argv"][:3], ["fix", "--target", "all"])
        self.assertFalse(res["result"]["isError"])
