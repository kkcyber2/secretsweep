# SecretSweep

Finds credentials committed to a repository before someone else does.

Two detectors run together: a curated set of **pattern rules** for things with a
recognisable shape (AWS keys, GitHub tokens, private key blocks, JWTs), and a
**Shannon-entropy** pass that catches high-randomness strings assigned to
secret-sounding names — the ones no regex will ever know about.

## Why entropy as well as patterns

Patterns only find what someone already thought of. A 40-character random string
assigned to `DB_PASSWORD` is a secret whether or not it matches a vendor prefix.
Entropy finds those; the pattern rules keep the false-positive rate down.

## What it does to keep the noise down

* **Allowlists** for known-safe values (`example`, `changeme`, `your-key-here`, …).
* **Path exclusions** for lockfiles, vendored code and test fixtures.
* **Entropy thresholds** tuned per character class, so a long English sentence is not
  reported as a secret.
* **Redaction** — the report shows a masked value, never the secret itself.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
secretsweep .
secretsweep . --json findings.json
secretsweep . --fail-on high     # exit 1 if anything high or above is found
```

## As a library

```python
from secretsweep.scanner import scan_path

result = scan_path(".")
for finding in result.findings:
    print(finding.severity, finding.rule, finding.path, finding.line)
```

## Tests

```bash
pytest -q
```

## License

MIT — see `LICENSE`.
