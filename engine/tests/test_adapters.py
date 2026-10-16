from pathlib import Path

from boundaryx.adapters.httpx import HttpxAdapter
from boundaryx.adapters.registry import ToolRegistry
from boundaryx.adapters.subfinder import SubfinderAdapter


def test_subfinder_adapter_argv_and_parsing():
    adapter = SubfinderAdapter(custom_path="/fake/path/subfinder")
    argv = adapter.build_argv(["example.com"], {"all_sources": True})
    assert argv[0] == "/fake/path/subfinder"
    assert "-d" in argv
    assert "example.com" in argv
    assert "-all" in argv

    fake_stdout = """
    {"host":"api.example.com","source":"virustotal"}
    {"host":"admin.example.com","source":"alienvault"}
    malformed line to ignore
    """
    parsed = adapter.parse_output(fake_stdout, "")
    assert len(parsed) == 2
    assert parsed[0]["value"] == "api.example.com"
    assert parsed[0]["source"] == "virustotal"


def test_httpx_adapter_argv_and_parsing():
    adapter = HttpxAdapter(custom_path="/fake/path/httpx")
    argv = adapter.build_argv(["https://api.example.com"], {"rate_limit": 5})
    assert "-rate-limit" in argv
    assert "5" in argv
    assert "-follow-redirects=false" in argv

    fake_stdout = """
    {"url":"https://api.example.com/v1","status_code":200,"title":"API Portal","technologies":["Express","Node.js"]}
    """
    parsed = adapter.parse_output(fake_stdout, "")
    assert len(parsed) == 1
    assert parsed[0]["value"] == "https://api.example.com/v1"
    assert parsed[0]["status_code"] == 200
    assert "Express" in parsed[0]["technologies"]


def test_tool_registry_manifest_loading():
    manifest_path = Path(__file__).resolve().parent.parent.parent / "config" / "tool-manifest.yaml"
    registry = ToolRegistry(manifest_path)
    tools = registry.list_all_tools()
    assert len(tools) >= 6

    subfinder_status = registry.get_tool_status("subfinder")
    assert subfinder_status["id"] == "subfinder"
    assert subfinder_status["network_activity"] == "provider_dependent_passive"
