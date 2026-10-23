import pytest

from secretsweep.rules import RULES, is_allowlisted


def rule(rule_id):
    return next(r for r in RULES if r.id == rule_id)


@pytest.mark.parametrize(
    "rule_id,sample",
    [
        ("aws.access_key", "AKIAIOSFODNN7EXAMPLE"),
        ("github.token", "ghp_" + "a" * 36),
        ("slack.token", "xoxb-123456789012-abcdefghijkl"),
        ("stripe.key", "sk_live_" + "a" * 24),
        ("google.api_key", "AIza" + "a" * 35),
        ("private_key_block", "-----BEGIN RSA PRIVATE KEY-----"),
        ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop"),
        ("connection_string", "postgres://user:hunter2@db.internal:5432/app"),
    ],
)
def test_rule_matches_its_sample(rule_id, sample):
    assert rule(rule_id).pattern.search(sample) is not None


def test_generic_assignment_captures_the_value():
    match = rule("generic.assignment").pattern.search('password = "s3cr3t-value"')
    assert match is not None
    assert match.group(1) == "s3cr3t-value"


@pytest.mark.parametrize(
    "value",
    ["changeme", "your-api-key", "placeholder", "xxxxxxxx", "example", "TODO", "hunter2"],
)
def test_placeholders_are_allowlisted(value):
    assert is_allowlisted(value) is True


def test_real_looking_value_is_not_allowlisted():
    assert is_allowlisted("aB3xK9mQ2pL7vN4zR8tW1yC6") is False


def test_angle_bracket_placeholder_is_allowlisted():
    assert is_allowlisted("<your-token>") is True
