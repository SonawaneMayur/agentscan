import json
from pathlib import Path

from agentscan.cli import main

VULNERABLE = {
    "mcpServers": {
        "db": {
            "command": "npx",
            "args": ["-y", "some-db-server"],
            "env": {"DATABASE_PASSWORD": "hunter2-prod-password"},
        },
        "remote": {"url": "http://mcp.example.com/sse"},
    }
}
CLEAN = {
    "mcpServers": {
        "git": {
            "command": "uvx",
            "args": ["mcp-server-git==0.6.2"],
            "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"},
        }
    }
}


def test_json_output_lists_findings_and_fails(write_config, tmp_path: Path, capsys):
    write_config(".mcp.json", VULNERABLE)
    code = main(["scan", str(tmp_path), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert report["servers_scanned"] == 2
    assert sorted(f["rule_id"] for f in report["findings"]) == ["MCP001", "MCP002", "MCP003"]


def test_clean_config_passes(write_config, tmp_path: Path, capsys):
    write_config(".mcp.json", CLEAN)
    assert main(["scan", str(tmp_path)]) == 0
    assert "no issues found" in capsys.readouterr().out


def test_fail_on_threshold(write_config, tmp_path: Path):
    write_config(".mcp.json", VULNERABLE)
    assert main(["scan", str(tmp_path), "--fail-on", "critical"]) == 0


def test_text_output_shows_rule_and_server(write_config, tmp_path: Path, capsys):
    write_config(".mcp.json", VULNERABLE)
    main(["scan", str(tmp_path)])
    out = capsys.readouterr().out
    assert "MCP001" in out
    assert "db" in out


def test_missing_path_exits_2(tmp_path: Path, capsys):
    assert main(["scan", str(tmp_path / "nope")]) == 2
    assert "no such file" in capsys.readouterr().err


def test_rules_command_lists_rules(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    for rule_id in ("MCP001", "MCP002", "MCP003"):
        assert rule_id in out
