<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=UEFISCAN&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="UEFISCAN"/>

# UEFISCAN

### Audit UEFI firmware dumps for missing Secure Boot keys, unsigned modules, S3 boot-script vulns, and known SMM threats.

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Audit+UEFI+firmware+dumps+for+missing+Secure+Boot+keys+unsig;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-uefiscan.svg?color=6b46c1)](https://pypi.org/project/cognis-uefiscan/) [![CI](https://github.com/cognis-digital/uefiscan/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/uefiscan/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*IoT / OT / Embedded — firmware, buses, and device security.*

</div>

```bash
pip install cognis-uefiscan
uefiscan scan .            # → prioritized findings in seconds
```

## Usage — step by step

1. **Install** (Python 3.9+):

   ```bash
   pip install uefiscan
   ```

2. **Scan a firmware dump** and print a red/green Secure Boot verdict:

   ```bash
   uefiscan scan firmware.bin
   ```

3. **Tune output.** Switch to JSON for tooling, SARIF for code-scanning, or
   write the report straight to a file:

   ```bash
   uefiscan scan firmware.bin --format json
   uefiscan scan firmware.bin --format sarif -o uefiscan.sarif
   uefiscan scan firmware.bin --no-color
   ```

4. **Read the verdict** programmatically with `jq`:

   ```bash
   uefiscan scan firmware.bin --format json | jq .verdict
   ```

5. **Gate in CI.** The exit code is non-zero when the audit fails, so the build breaks on an insecure image:

   ```bash
   uefiscan scan firmware.bin || echo "Secure Boot audit FAILED"
   ```


## Contents

- [Why uefiscan?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Demos](#demos) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why uefiscan?

Supply-chain firmware-implant fear (post-LogoFAIL/BlackLotus) — a friendly CLI wrapper that gives a red/green verdict instead of CHIPSEC's wall of output.

`uefiscan` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ Find Firmware Volumes
- ✅ Find Efi Variables
- ✅ Find Pe Modules
- ✅ Audit Bytes
- ✅ Audit Image
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-uefiscan
uefiscan --version
uefiscan scan firmware.bin                  # red/green Secure Boot verdict
uefiscan scan firmware.bin --format json    # machine-readable
uefiscan scan firmware.bin --format sarif -o uefiscan.sarif   # code-scanning
uefiscan scan firmware.bin || echo FAIL     # CI gate (non-zero exit on FAIL)
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

```text
$ uefiscan scan .
  [HIGH    ] UEF-001  example finding             (./src/app.py)
  [MEDIUM  ] UEF-002  another signal              (./config.yaml)

  2 findings · risk score 5 · 38ms
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="demos"></a>
## Demos — real-world scenarios you can run

Each folder under [`demos/`](demos/) ships a synthetic firmware image **in the
real UEFI binary format** plus a `SCENARIO.md` (where the dump came from, what
to expect, the exact command, how to act). Every image is regenerable with its
own `build.py` (stdlib only) and is covered by `tests/test_demos.py`, so the
documented verdict is guaranteed to fire.

| Demo | Situation | Verdict |
|---|---|:---:|
| [`01-basic`](demos/01-basic/) | Mis-provisioned image: unsigned module + no dbx | FAIL |
| [`02-clean-pass`](demos/02-clean-pass/) | Fully provisioned, all modules signed | PASS |
| [`03-missing-keys`](demos/03-missing-keys/) | Secure Boot never enrolled (db/dbx missing) | FAIL |
| [`04-unsigned-driver`](demos/04-unsigned-driver/) | One unsigned DXE driver in a signed image | FAIL |
| [`05-te-module`](demos/05-te-module/) | A TE (Terse Executable) PEI-phase module | FAIL |
| [`06-not-uefi`](demos/06-not-uefi/) | Dump isn't UEFI firmware at all (no `_FVH`) | FAIL |
| [`07-no-dbx`](demos/07-no-dbx/) | Provisioned but no revocation list | PASS (warn) |
| [`08-multi-volume`](demos/08-multi-volume/) | Laptop image with two firmware volumes | PASS |
| [`09-ci-gate`](demos/09-ci-gate/) | CI gate + SARIF upload on a regression | FAIL |
| [`10-truncated`](demos/10-truncated/) | A truncated / failed flash read | FAIL |
| [`11-kev-enrichment`](demos/11-kev-enrichment/) | Cross-reference component CVEs against **CISA KEV** (offline) | — |

```bash
python -m uefiscan scan demos/04-unsigned-driver/firmware.bin
python -m uefiscan scan demos/09-ci-gate/firmware.bin --format sarif -o uefiscan.sarif
python demos/11-kev-enrichment/run.py    # offline KEV cross-reference
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="feeds"></a>
## Threat-intel data feed — CISA KEV (edge / air-gap)

A firmware audit tells you *what's wrong with the image*. The **`feeds`**
command adds the other half a defender needs: *which of the CVEs riding on this
platform are being exploited right now*. UEFISCAN ingests the authoritative
**CISA Known Exploited Vulnerabilities (KEV)** catalog and cross-references it
against the CVEs attached to your firmware / BMC / boot-chain components.

**Real source (keyless HTTPS):**
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
(mirror: `https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json`).
KEV is the US-government list of actively-exploited CVEs carrying a federal
remediation deadline (CISA BOD 22-01 / 26-04).

```bash
# What feed does this tool consume, and how fresh is the local cache?
uefiscan feeds list

# Refresh the on-disk cache (online).
uefiscan feeds update cisa-kev

# Cross-reference a component CVE list — prioritised "patch now" output.
uefiscan feeds get --cve CVE-2025-47827 --cve CVE-2022-0492 --offline
uefiscan feeds get --cve CVE-2025-47827 --format json
```

```python
from uefiscan import feeds
report = feeds.enrich_cves(["CVE-2025-47827", "CVE-2022-0492"], offline=True)
report["patch_now"]          # ['CVE-2025-47827', 'CVE-2022-0492'] — KEV-listed, ordered by due date
```

You can also escalate a scan's findings: any `AuditResult` finding that
references a KEV-listed CVE is re-leveled to `error` and annotated
`[KEV: known-exploited, due <date>]` via `feeds.enrich_audit_result(result)`.

### Edge / air-gap workflow

The feed layer ([`uefiscan/datafeeds.py`](uefiscan/datafeeds.py) +
[`data_feeds_2026.json`](uefiscan/data_feeds_2026.json)) is **stdlib-only**:
fetch over HTTPS → cache to disk → re-serve with `offline=True`, never touching
the network. The cache directory is `COGNIS_FEEDS_CACHE` (default
`~/.cache/cognis-feeds`). To run on a disconnected enclave:

```bash
# On a connected staging box:
uefiscan feeds update cisa-kev
python -m uefiscan.datafeeds snapshot-export kev-snapshot.tar.gz

# Sneakernet kev-snapshot.tar.gz into the air-gapped network, then:
export COGNIS_FEEDS_CACHE=/srv/cognis-feeds
python -m uefiscan.datafeeds snapshot-import kev-snapshot.tar.gz
uefiscan feeds get --cve CVE-2025-47827 --offline   # works with zero network
```

The committed tests run **entirely offline** against a small trimmed real-data
KEV fixture under [`tests/fixtures/feeds-cache/`](tests/fixtures/feeds-cache/),
so CI never reaches out to the network.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[target / manifest] --> P[uefiscan<br/>checks + rules]
  P --> OUT[findings (JSON / SARIF)]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`uefiscan` is interoperable with every popular way of using AI:

- **MCP server** — `uefiscan mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `uefiscan scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis uefiscan** | CHIPSEC + UEFITool |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |
| Open license | ✅ COCL | varies |

*Built in the spirit of **CHIPSEC + UEFITool**, re-framed the Cognis way. Missing a credit? Open a PR.*

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`uefiscan mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/uefiscan.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/uefiscan.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/uefiscan.git" # uv
pip install cognis-uefiscan                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/uefiscan:latest --help        # Docker
brew install cognis-digital/tap/uefiscan                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/uefiscan/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/uefiscan` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools

- [`fwxray`](https://github.com/cognis-digital/fwxray) — Diff two firmware images and surface exactly what changed: new binaries, flipped config flags, added certs, and shifted entropy regions.
- [`canzap`](https://github.com/cognis-digital/canzap) — Replay, fuzz, and assert on CAN bus traffic from a .pcap or SocketCAN interface with a tiny YAML DSL.
- [`sbomb`](https://github.com/cognis-digital/sbomb) — Generate a CycloneDX SBOM directly from an unpacked firmware root filesystem and flag components with known CVEs and EOL kernels.
- [`mqttspy`](https://github.com/cognis-digital/mqttspy) — Passively map an MQTT broker: enumerate topics, detect unauthenticated writes, spot PII/secrets in payloads, and emit a risk report.
- [`modpot`](https://github.com/cognis-digital/modpot) — Spin up a high-interaction Modbus/DNP3 ICS honeypot that logs attacker register reads/writes as structured JSON.
- [`keyhunt`](https://github.com/cognis-digital/keyhunt) — Scan firmware blobs and filesystem dumps for hardcoded private keys, API tokens, default creds, and weak RSA/ECC material.

**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `uefiscan` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>

## Bundled vulnerability database

Ships `uefiscan/cognis_vulndb.jsonl.gz` — **262,351 real vulnerabilities** (OSV across 7 ecosystems) with detailed metadata; offline stdlib loader `vulndb_local.VulnDB`, air-gap ready.
