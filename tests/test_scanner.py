from pathlib import Path

from secretsweep.scanner import scan_path, scan_text, should_skip


def test_scan_text_finds_an_aws_key():
    findings = scan_text("key = 'AKIAIOSFODNN7EXAMPLE'", "a.py")
    assert any(f.rule == "aws.access_key" for f in findings)


def test_scan_text_ignores_placeholders():
    findings = scan_text('api_key = "your-api-key"', "a.py")
    assert findings == []


def test_scan_text_finds_high_entropy_string():
    findings = scan_text('token = "aB3xK9mQ2pL7vN4zR8tW1yC6"', "a.py")
    assert any(f.rule == "entropy.high" for f in findings)


def test_stronger_rule_wins_over_entropy_on_the_same_span():
    findings = scan_text('aws_secret = "AKIAIOSFODNN7EXAMPLE"', "a.py")
    spans = [(f.line, f.column) for f in findings]
    assert len(spans) == len(set(spans))


def test_scan_path_walks_a_tree(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "config.py").write_text('password = "AKIAIOSFODNN7EXAMPLE"')
    result = scan_path(tmp_path)
    assert result.files_scanned == 1
    assert result.findings


def test_scan_path_skips_excluded_directories(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("AKIAIOSFODNN7EXAMPLE")
    result = scan_path(tmp_path)
    assert result.files_scanned == 0


def test_scan_path_skips_binary_suffixes(tmp_path):
    (tmp_path / "image.png").write_text("AKIAIOSFODNN7EXAMPLE")
    assert scan_path(tmp_path).files_scanned == 0


def test_should_skip_rules():
    assert should_skip(Path("a/node_modules/b.js")) is True
    assert should_skip(Path("a/b.min.js")) is True
    assert should_skip(Path("a/b.py")) is False


def test_findings_are_redacted():
    findings = scan_text("key = 'AKIAIOSFODNN7EXAMPLE'", "a.py")
    public = findings[0].public()
    assert "AKIAIOSFODNN7EXAMPLE" not in public["match"]
    assert public["match"].startswith("AKIA")


def test_counts_group_by_severity():
    result = scan_path(Path("."))
    assert isinstance(result.counts(), dict)
