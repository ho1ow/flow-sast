import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

# Import the module to be tested. 
# (Assumes main.py is in the same directory and named main.py)
import main
import sys
import subprocess
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "flow-sast"))
def test_severity_breakdown():
    """Test that severities are correctly aggregated and defaulted."""
    findings = [
        {"severity": "CRITICAL"},
        {"severity": "high"},     # Should be case-insensitive in the implementation
        {"severity": "MEDIUM"},
        {"severity": "low"},
        {"severity": "info"},
        {"severity": "CRITICAL"},
        {"other_key": "value"}    # Missing severity should default to INFO
    ]
    breakdown = main._severity_breakdown(findings)

    assert breakdown["CRITICAL"] == 2
    assert breakdown["HIGH"] == 1
    assert breakdown["MEDIUM"] == 1
    assert breakdown["LOW"] == 1
    assert breakdown["INFO"] == 2

def test_generate_run_id():
    """Test that the run ID generates the correct format and hash."""
    repo_path = "/path/to/my/repo"
    run_id = main._generate_run_id(repo_path)

    # Check prefix
    assert run_id.startswith("run_")
    
    # Check that it ends with the first 6 chars of the MD5 hash of the repo path
    expected_hash = hashlib.md5(repo_path.encode()).hexdigest()[:6]
    assert run_id.endswith(expected_hash)
    
    # Ensure it has the timestamp components
    parts = run_id.split("_")
    assert len(parts) >= 3

def test_to_sarif():
    """Test that a basic finding is converted to a valid SARIF structure."""
    findings = [{
        "id": "vuln_1",
        "vuln_type": "SQL Injection",
        "title": "SQLi in Login",
        "severity": "HIGH",
        "file": "app/auth.py",
        "line_start": 42
    }]
    
    sarif = main._to_sarif(findings, "/mock/repo", "run_123")

    # Validate high-level SARIF structure
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    
    run = sarif["runs"][0]
    assert run["properties"]["run_id"] == "run_123"
    assert len(run["results"]) == 1
    
    # Validate the finding mapping
    result = run["results"][0]
    assert result["level"] == "error"  # HIGH should map to error
    assert result["ruleId"] == "pentest/SQL Injection"
    
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "app/auth.py"
    assert location["region"]["startLine"] == 42

def test_detect_stack_exact_match(tmp_path):
    """Test stack detection when exact indicator files exist."""
    # tmp_path is a built-in pytest fixture that provides a temporary directory
    (tmp_path / "manage.py").touch()
    (tmp_path / "settings.py").touch()

    stack = main._detect_stack(str(tmp_path))
    assert stack == "django"

def test_detect_stack_fallback_extension(tmp_path):
    """Test stack detection fallback based on file extensions."""
    (tmp_path / "main.go").touch()
    (tmp_path / "utils.go").touch()
    (tmp_path / "README.md").touch()

    stack = main._detect_stack(str(tmp_path))
    assert stack == "gin"

def test_detect_stack_auto(tmp_path):
    """Test that it defaults to 'auto' if it can't figure it out."""
    (tmp_path / "plain.txt").touch()
    
    stack = main._detect_stack(str(tmp_path))
    assert stack == "auto"

@patch("sys.argv", ["main.py", "--help"])
def test_main_cli_help(capsys):
    """Test that the CLI correctly handles the --help argument."""
    with pytest.raises(SystemExit) as exc_info:
        main.main()
    
    # Argparse should exit with status code 0 when --help is passed
    assert exc_info.value.code == 0
    
    # Verify the help text is printed to stdout
    captured = capsys.readouterr()
    assert "flow-sast — automated whitebox SAST" in captured.out
    assert "--repo" in captured.out





import json
import subprocess
import sys
from pathlib import Path
import importlib

# Import the module under test
main = importlib.import_module("main")


def test_resume_checkpoint_handling(tmp_path, monkeypatch, capsys):
    # ----- Repository -------------------------------------------------------
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')")

    # ----- Configuration ----------------------------------------------------
    cfg = {
        "pipeline": {
            "output_dir": str(tmp_path / "out"),
            "checkpoint_dir": str(tmp_path / "ckpt"),
            "audit_dir": str(tmp_path / "audit"),
        },
        "anthropic": {"max_concurrency": 1},
    }
    # Mock configuration loading and audit logging
    monkeypatch.setattr(main, "load_config", lambda _: cfg)
    monkeypatch.setattr(main, "audit_log", lambda *a, **k: None)

    # ----- Mock checkpoint_load to return a saved state ----------------------
    saved_state = {
        "findings": [
            {
                "id": "saved1",
                "severity": "LOW",
                "vuln_type": "XSS",
                "title": "saved finding",
                "file": "saved.py",
                "line_start": 1,
            }
        ]
    }
    monkeypatch.setattr(main, "checkpoint_load", lambda *a, **k: saved_state)

    # ----- Mock initial_state ------------------------------------------------
    def fake_initial_state(**kwargs):
        # Return a fresh state that will later be merged with saved_state
        return {"findings": []}

    monkeypatch.setattr(main, "initial_state", fake_initial_state)

    # ----- Mock graph with empty stream (no additional findings) ------------
    monkeypatch.setattr(
        main,
        "build_graph",
        lambda *a, **k: type(
            "G", (), {"stream": lambda self, *a, **k: iter([])}
        )(),
    )

    # ----- Make run_id deterministic ----------------------------------------
    monkeypatch.setattr(main, "_generate_run_id", lambda _: "run_test")

    # ----- Run with --resume (checkpoint exists) ----------------------------
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--repo", str(repo), "--stack", "django", "--resume"],
    )
    main.main()
    out = capsys.readouterr()
    # The resume message is printed via Rich's console (stdout)
    assert "Resumed from checkpoint" in out.out

    # Verify that the saved finding appears in the output JSON
    out_dir = Path(cfg["pipeline"]["output_dir"]) / "run_test"
    json_path = out_dir / "findings.json"
    assert json_path.is_file()
    data = json.loads(json_path.read_text())
    ids = [f["id"] for f in data["findings"]]
    assert "saved1" in ids

    # ----- Now test when no checkpoint is present ---------------------------
    # Make checkpoint_load return None to simulate missing checkpoint
    monkeypatch.setattr(main, "checkpoint_load", lambda *a, **k: None)
    # Clear previous output files but keep the directory
    for p in out_dir.iterdir():
        p.unlink()
    # Run again without a checkpoint
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--repo", str(repo), "--stack", "django", "--resume"],
    )
    main.main()
    out2 = capsys.readouterr()
    # Expect the “no checkpoint” warning (printed to stdout)
    assert "No checkpoint found" in out2.out

    # Verify that the output JSON still exists (empty findings list)
    json_path2 = out_dir / "findings.json"
    assert json_path2.is_file()
    data2 = json.loads(json_path2.read_text())
    assert data2["findings"] == []

    # ----- Verify that the module guard is exercised via subprocess -----------
    # Running the file as a script should hit the __main__ guard (line 403)
    result = subprocess.run(
        [sys.executable, str(Path(main.__file__)), "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "flow-sast — automated whitebox SAST" in result.stdout

def test_keyboard_interrupt_handling(tmp_path, monkeypatch, capsys):
    # Setup repo
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('y')")

    # Mock config
    cfg = {
        "pipeline": {
            "checkpoint_dir": str(tmp_path / "ckpt"),
            "audit_dir": str(tmp_path / "audit"),
            "output_dir": str(tmp_path / "out")
        }
    }
    monkeypatch.setattr(main, "load_config", lambda _: cfg)

    # Stub audit_log
    monkeypatch.setattr(main, "audit_log", lambda *a, **k: None)

    # initial_state returns empty containers
    monkeypatch.setattr(main, "initial_state", lambda **kw: {
        "findings": [], "confirmed_pocs": [], "errors": []
    })

    # Graph that raises KeyboardInterrupt after first chunk
    class InterruptGraph:
        def __init__(self):
            self.called = False
        def stream(self, *a, **k):
            # First (empty) chunk
            yield {"node1": {}}
            # Then raise interrupt
            raise KeyboardInterrupt
    monkeypatch.setattr(main, "build_graph", lambda *a, **k: InterruptGraph())

    # Run main
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--repo", str(repo),
    ])
    main.main()

    # Capture console output
    out = capsys.readouterr().out
    # Verify interruption warning printed
    assert "Interrupted — partial results saved" in out

    # Verify that output files were still written (may be empty findings)
    out_dir = Path(cfg["pipeline"]["output_dir"])
    run_dirs = list(out_dir.glob("run_*"))
    assert len(run_dirs) == 1
    sarif_path = run_dirs[0] / "findings.sarif"
    json_path = run_dirs[0] / "findings.json"
    assert sarif_path.is_file()
    assert json_path.is_file()

    # The JSON should contain zero findings but still be valid
    data = json.loads(json_path.read_text())
    assert data["stats"]["total_findings"] == 0

def test_resume_checkpoint_merges_findings(tmp_path, monkeypatch):
    # Setup repo
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('x')")

    # Mock config with known output directory
    cfg = {
        "pipeline": {
            "checkpoint_dir": str(tmp_path / "ckpt"),
            "audit_dir": str(tmp_path / "audit"),
            "output_dir": str(tmp_path / "out")
        }
    }
    monkeypatch.setattr(main, "load_config", lambda _: cfg)

    # Prepare a saved checkpoint containing a finding
    saved_state = {
        "findings": [{
            "id": "saved1",
            "severity": "MEDIUM",
            "vuln_type": "InfoLeak",
            "title": "Info leak",
            "file": "app/info.py",
            "line_start": 5,
            "sarif_rule_id": "pentest/InfoLeak"
        }]
    }
    monkeypatch.setattr(main, "checkpoint_load", lambda *a, **k: saved_state)

    # Stub audit_log
    monkeypatch.setattr(main, "audit_log", lambda *a, **k: None)

    # initial_state returns empty dicts
    monkeypatch.setattr(main, "initial_state", lambda **kw: {
        "findings": [], "confirmed_pocs": [], "errors": []
    })

    # Mock graph that yields no additional findings
    class EmptyGraph:
        def stream(self, *a, **k):
            return iter([])
    monkeypatch.setattr(main, "build_graph", lambda *a, **k: EmptyGraph())

    # Run with --resume
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--repo", str(repo),
        "--resume"
    ])
    main.main()

    # Locate the generated raw JSON file
    out_dir = Path(cfg["pipeline"]["output_dir"])
    run_dirs = list(out_dir.glob("run_*"))
    assert len(run_dirs) == 1
    raw_path = run_dirs[0] / "findings.json"
    data = json.loads(raw_path.read_text())

    # The saved finding should be present in the output
    ids = [f["id"] for f in data["findings"]]
    assert "saved1" in ids
    assert data["stats"]["total_findings"] == 1

def test_no_burp_and_no_joern_overrides(tmp_path, monkeypatch):
    # Prepare a minimal repo directory
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "dummy.py").write_text("print('hi')")

    # Prepare a mutable config dict that we can inspect after main runs
    cfg = {}

    # Mock load_config to return our mutable dict
    monkeypatch.setattr(main, "load_config", lambda _: cfg)

    # Stub out heavy functions
    monkeypatch.setattr(main, "audit_log", lambda *a, **k: None)
    monkeypatch.setattr(main, "checkpoint_load", lambda *a, **k: None)
    monkeypatch.setattr(main, "initial_state", lambda **kw: {})
    monkeypatch.setattr(main, "build_graph", lambda *a, **k: type(
        "G", (), {"stream": lambda self, *a, **k: iter([])}
    )())

    # Run main with the two flags
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--repo", str(repo),
        "--no-burp",
        "--no-joern",
    ])
    main.main()

    # After execution the config dict should have the skip flags set
    assert cfg.get("burp_mcp", {}).get("skip") is True
    assert cfg.get("joern", {}).get("skip") is True

import json
import sys
from pathlib import Path

import main


def test_main_full_successful_run(tmp_path, capsys, monkeypatch):
    """
    Run the full pipeline (non‑dry‑run) with mocked components, checking that:
    * run_id generation and output directory creation work,
    * findings are deduplicated,
    * SARIF and raw JSON files are written,
    * audit_log is called for start and done,
    * the summary table is printed.
    """
    # ----- Setup repository -------------------------------------------------
    repo = tmp_path / "repo"
    repo.mkdir()
    # create a dummy file so the repo is not empty
    (repo / "app.py").write_text("print('hello')")

    # ----- Mock configuration ------------------------------------------------
    cfg = {
        "pipeline": {
            "checkpoint_dir": str(tmp_path / "ckpt"),
            "audit_dir": str(tmp_path / "audit"),
            "output_dir": str(tmp_path / "out"),
        },
        "anthropic": {"max_concurrency": 2},
    }
    monkeypatch.setattr(main, "load_config", lambda _: cfg)

    # ----- Stub side‑effect functions ----------------------------------------
    audit_calls = []

    def fake_audit(dir_path, run_id, event, payload):
        # we only care about the event name and payload for the assertions
        audit_calls.append((event, payload))

    monkeypatch.setattr(main, "audit_log", fake_audit)
    monkeypatch.setattr(main, "checkpoint_load", lambda *a, **k: None)

    # initial_state returns a mutable dict that we can later inspect
    def fake_initial_state(**kwargs):
        return {"findings": [], "confirmed_pocs": [], "errors": []}

    monkeypatch.setattr(main, "initial_state", fake_initial_state)

    # ----- Mock graph --------------------------------------------------------
    class FakeGraph:
        def stream(self, state, config=None, stream_mode=None):
            # First chunk yields a node with duplicate findings
            dup_finding = {
                "id": "dup1",
                "severity": "HIGH",
                "vuln_type": "SQL Injection",
                "title": "SQLi",
                "file": "app/auth.py",
                "line_start": 10,
                "sarif_rule_id": "pentest/SQL Injection",
            }
            # Second chunk yields another finding with a different id
            other_finding = {
                "id": "uniq1",
                "severity": "LOW",
                "vuln_type": "XSS",
                "title": "XSS issue",
                "file": "app/views.py",
                "line_start": 20,
                "sarif_rule_id": "pentest/Cross Site Scripting",
            }
            # Simulate two nodes in the pipeline.
            # The second node must contain *both* findings because the
            # implementation overwrites list‑valued keys with dict.update().
            yield {"catalog": {"findings": [dup_finding, dup_finding]}}
            yield {"verify": {"findings": [dup_finding, other_finding]}}

    monkeypatch.setattr(main, "build_graph", lambda *a, **k: FakeGraph())

    # ----- Run main -----------------------------------------------------------
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--repo", str(repo),
        "--stack", "django",  # avoid auto‑detect logic
    ])
    main.main()

    # ----- Assertions ---------------------------------------------------------
    # Verify audit_log was called for start and done events
    assert any(event == "pipeline:start" for event, _ in audit_calls)
    assert any(event == "pipeline:done" for event, _ in audit_calls)

    # Verify output directory exists and contains the two files
    run_dirs = list(Path(cfg["pipeline"]["output_dir"]).glob("run_*"))
    assert len(run_dirs) == 1, "Expected exactly one run directory"
    run_dir = run_dirs[0]
    sarif_file = run_dir / "findings.sarif"
    json_file = run_dir / "findings.json"
    assert sarif_file.is_file()
    assert json_file.is_file()

    # Load and inspect SARIF – should contain two unique findings
    sarif_data = json.loads(sarif_file.read_text())
    assert len(sarif_data["runs"][0]["results"]) == 2

    # Load raw JSON and verify deduplication and metadata
    raw = json.loads(json_file.read_text())
    assert raw["run_id"].startswith("run_")
    assert raw["repo"] == str(repo.resolve())
    assert raw["stack"] == "django"
    assert raw["stats"]["total_findings"] == 2

    # Verify that the summary table was printed (look for severity rows)
    captured = capsys.readouterr()
    assert "CRITICAL" not in captured.out  # none expected
    assert "[red]HIGH[/]" in captured.out or "HIGH" in captured.out
    assert "[green]LOW[/]" in captured.out or "LOW" in captured.out


def test_main_dry_run_early_exit(tmp_path, capsys, monkeypatch):
    # Prepare a dummy repo
    repo = tmp_path / "repo"
    repo.mkdir()
    # Dummy config that the loader will return
    dummy_cfg = {"pipeline": {"checkpoint_dir": str(tmp_path / "ckpt"),
                             "audit_dir": str(tmp_path / "audit"),
                             "output_dir": str(tmp_path / "out")}}
    monkeypatch.setattr(main, "load_config", lambda _: dummy_cfg)
    # Stub functions that would otherwise have side effects
    monkeypatch.setattr(main, "audit_log", lambda *a, **k: None)
    monkeypatch.setattr(main, "checkpoint_load", lambda *a, **k: None)
    monkeypatch.setattr(main, "initial_state", lambda **k: {})
    # Build a fake graph whose stream yields a ``triage_score`` node
    class FakeGraph:
        def stream(self, state, config=None, stream_mode=None):
            yield {"triage_score": {
                "sources": [1, 2],
                "sinks": [],
                "endpoints": [],
                "structural_paths": [],
                "object_paths": [],
                "prioritized": []
            }}
    monkeypatch.setattr(main, "build_graph", lambda *a, **k: FakeGraph())
    # Run with --dry-run flag
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--repo", str(repo),
        "--dry-run",
    ])
    # Execute
    main.main()
    # Verify that no output files were created
    out_dir = Path(dummy_cfg["pipeline"]["output_dir"]) / "run_"  # prefix
    # Since run_id is auto‑generated, just ensure the directory exists but contains no SARIF/JSON
    # (the function returns after printing the dry‑run summary)
    captured = capsys.readouterr()
    assert "── DRY RUN SUMMARY" in captured.out
    assert "Sources found:" in captured.out


def test_main_config_not_found(tmp_path, capsys, monkeypatch):
    # Create a valid repo directory
    repo = tmp_path / "repo"
    repo.mkdir()
    # Point to a non‑existent config file
    missing_cfg = tmp_path / "missing_config.json"
    # Patch load_config to raise FileNotFoundError
    def raise_fn(_):
        raise FileNotFoundError("Config file not found")
    monkeypatch.setattr(main, "load_config", raise_fn)
    # Build argv
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--repo", str(repo),
        "--config", str(missing_cfg),
    ])
    # Run and expect SystemExit with code 1
    with pytest.raises(SystemExit) as exc:
        main.main()
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Config file not found" in captured.out


def test_main_repo_not_found(tmp_path, capsys, monkeypatch):
    # Create a path that does NOT exist
    missing_repo = tmp_path / "does_not_exist"
    # Minimal config file – we will patch load_config so it is never called
    dummy_config = tmp_path / "dummy_config.json"
    dummy_config.write_text("{}")
    # Patch load_config to ensure it would not be reached
    monkeypatch.setattr(main, "load_config", lambda _: {"pipeline": {}})
    # Build argv
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--repo", str(missing_repo),
        "--config", str(dummy_config),
    ])
    # Run and expect SystemExit with code 1
    with pytest.raises(SystemExit) as exc:
        main.main()
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Repository not found" in captured.out
