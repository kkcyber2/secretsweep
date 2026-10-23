from secretsweep.cli import main, render
from secretsweep.scanner import scan_path


def test_render_clean(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    assert "No secrets found" in render(scan_path(tmp_path))


def test_cli_fail_on_high_returns_1(tmp_path):
    (tmp_path / "a.py").write_text("k = 'AKIAIOSFODNN7EXAMPLE'\n")
    assert main([str(tmp_path), "--fail-on", "high"]) == 1


def test_cli_clean_tree_returns_0(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    assert main([str(tmp_path), "--fail-on", "high"]) == 0


def test_cli_writes_json(tmp_path):
    (tmp_path / "a.py").write_text("k = 'AKIAIOSFODNN7EXAMPLE'\n")
    out = tmp_path / "out.json"
    main([str(tmp_path), "--json", str(out)])
    assert out.exists()
