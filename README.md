# PoamForge

Turn Tenable Nessus CSV exports (plus optional Microsoft Defender inventory exports) into a
**FedRAMP Rev5 POA&M** and an **Integrated Inventory Workbook** (SSP Attachment 13) — ranked by a
"pain score" and flagged against the **CISA KEV** catalog.

Single portable Windows `.exe`, no install, no admin rights, works offline.

## Download

**[⬇ PoamForge.exe (latest release)](https://github.com/Infinit3i/poamforge/releases/latest/download/PoamForge.exe)**

All versions: [Releases](https://github.com/Infinit3i/poamforge/releases). Every release is built
from this repository by GitHub Actions ([workflow](.github/workflows/release.yml)), so the exe always
matches the tagged source.

> Windows SmartScreen may warn because the exe is unsigned: *More info → Run anyway*.

## Quick start

1. Run `PoamForge.exe`.
2. Drag and drop onto the window (or use the buttons):
   - one or more **Nessus CSV** exports
   - optionally **Defender for Endpoint** device exports or **Defender for Cloud** inventory CSVs
3. Tick the findings you want, fill in the POA&M settings on the left, click **Export POA&M**.
4. Optionally click **Export Inventory Workbook** for the Integrated Inventory Workbook.

## Features

- **CISA KEV, automatic** — downloaded at startup and cached, so it still works offline.
  **Update KEV** refreshes it; **Load KEV file…** lets air-gapped machines use a JSON copied in by hand.
  KEV findings get the BOD 22-01 tracking/due-date columns filled.
- **Pain score (0–100)** to prioritize: severity 35 (max of CVSSv3 / CVSSv2 / VPR), exploitability 25
  (KEV, public exploit, EPSS), spread 15 (host count), effort 15 (EOL, no patch, upgrade, reboot), age 10.
- **FedRAMP Rev5 POA&M** — fresh workbook, or append into the official template / an existing POA&M.
  Items already present (same plugin ID, and same host in per-host mode) are skipped.
  Scheduled completion dates follow FedRAMP remediation timelines by risk.
- **Environments** — define each system you report on with its own POAM ID prefix
  (e.g. `V-PROD-` and `V-GOV-`). Choosing a POA&M template auto-selects the environment whose
  prefix its IDs use, numbering continues from that prefix's highest ID, and exporting into a
  POA&M that belongs to a different environment is refused.
- **Inventory workbook** — Defender assets matched to scanned hosts by IP / FQDN / NetBIOS,
  with "In Latest Scan" and "Authenticated Scan" filled from the Nessus results.
- One item per plugin (assets listed together) or one item per host.

## Where settings live

`%APPDATA%\PoamForge\` (Windows) or `~/.config/PoamForge/` (Linux):

| File | Contents |
|---|---|
| `environments.tsv` | your environments, `name<TAB>prefix` per line |
| `kev.json` | last downloaded / loaded CISA KEV catalog |

## Build from source

Needs [Rust](https://rustup.rs) (stable).

```sh
cargo build --release          # binary in target/release/
cargo test                     # set SAMPLES=<dir> to run the end-to-end tests on sample files
```

The Windows build links the C runtime statically (see `.cargo/config.toml`), so the exe runs on a
clean machine.

## Releasing

Bump `version` in `Cargo.toml`, then:

```sh
git tag v0.2.0
git push origin v0.2.0
```

GitHub Actions tests, builds `PoamForge.exe` and publishes it as the latest release; the download
link above always points to it. The workflow can also be run manually from the Actions tab.

## Data handling

Everything runs locally. The only network call is the KEV download from `cisa.gov`.
Scan data never leaves the machine — still, don't commit real scan exports to this repository;
`samples/` contains only made-up data.
