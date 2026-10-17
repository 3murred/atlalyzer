# `atlalyzer` // file analysis toolkit

<p align="center">
  <img src="https://img.shields.io/badge/status-in%20development-d32f2f?style=for-the-badge" alt="status: in development">
  <img src="https://img.shields.io/badge/python-3.13+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="python">
  <img src="https://img.shields.io/badge/security-static%20analysis-black?style=for-the-badge&logo=kalilinux&logoColor=white" alt="static analysis">
  <img src="https://img.shields.io/badge/tests-27%20passing-2ea44f?style=for-the-badge" alt="tests passing">
</p>

<p align="center">
  <b>inspect. detect. understand.</b>
  <br>
  a lightweight file analysis laboratory built with python.
</p>

---

## `01 // overview`

the **atlalyzer** is an educational file analysis tool designed to inspect files, extract technical information and identify potentially suspicious characteristics.

inspired by tools used in cybersecurity and malware analysis, the project combines file fingerprinting, format identification, metadata extraction, heuristic anomaly detection and yara-based pattern matching.

the goal is simple: build a useful security tool from the ground up, understand every component and keep improving it through practical development.

> not another black box. a tool to learn how analysis works under the hood.

## `02 // capabilities`

| feature              | description                                                                    |
| -------------------- | ------------------------------------------------------------------------------ |
| `sha256`             | calculates SHA-256 file hashes using chunked reading                           |
| `file signatures`    | identifies supported formats through binary signatures                         |
| `extension checks`   | compares file extensions with detected formats                                 |
| `metadata`           | extracts available metadata from supported image formats                       |
| `archive inspection` | checks supported archives for suspicious paths, entries and compression ratios |
| `yara engine`        | scans file contents against locally defined YARA rules                         |
| `anomaly detection`  | identifies suspicious characteristics using heuristic rules                    |
| `risk scoring`       | assigns a heuristic score and risk level to detected anomalies                 |
| `json reports`       | organizes analysis results into structured JSON reports                        |
| `sqlite history`     | stores analysis history in a local database                                    |
| `batch analysis`     | supports analysis workflows involving multiple files                           |
| `automated tests`    | uses Python's `unittest` framework to validate behavior                        |

**important:** detection depends on the implemented rules, supported formats and available dependencies. a clean result does not prove that a file is safe.

## `03 // installation`

### requirements

- Python 3.13 or a compatible version.
- pip.
- Git (optional, if cloning the repository).
- `yara-python` for YARA scanning.
- Pillow for supported image metadata extraction.

### clone the repository

```bash
git clone https://github.com/3murred/atlalyzer.git
cd atlalyzer
```

if you already have the project locally, navigate to its directory instead.

### create a virtual environment

**Windows PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux / Kali Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install yara-python Pillow
```

the YARA integration is optional: without `yara-python`, the analyzer can still run, but YARA scanning will be unavailable.

## `04 // usage`

the current project is being developed as a Python analysis engine. the commands below are useful for running the existing code and inspecting its behavior.

### run the analyzer

```bash
python main.py
```

the script's behavior depends on the current entry point in `main.py`. the command-line interface is still being developed, so arguments such as `--file`, `--json` and `--batch` should not be assumed to exist yet.

### analyze a file from Python

```powershell
python -c "from main import analyze_file; print(analyze_file('sample.txt'))"
```

replace `sample.txt` with the path to the file you want to inspect.

for a file in another directory:

```powershell
python -c "from main import analyze_file; print(analyze_file(r'C:\path\to\sample.exe'))"
```

### inspect YARA results

```powershell
python -c "from main import analyze_file; r=analyze_file('sample.txt'); print(r['yara_analysis'])"
```

the result contains YARA availability, matched rules and any reported scanning error.

### create a JSON report

if your current `main.py` exposes the analysis result as a Python dictionary, you can serialize it with Python's `json` module:

```powershell
python -c "import json; from main import analyze_file; r=analyze_file('sample.txt'); print(json.dumps(r, indent=2, ensure_ascii=False, default=str))"
```

this prints the report to the terminal. it does not automatically save a JSON file.

to save the output:

```powershell
python -c "import json; from pathlib import Path; from main import analyze_file; r=analyze_file('sample.txt'); Path('report.json').write_text(json.dumps(r, indent=2, ensure_ascii=False, default=str), encoding='utf-8')"
```

### run automated tests

```powershell
python -m unittest -v
```

the current test suite contains **27 passing tests**. run it after code changes to check for regressions.

## `05 // yara rules`

YARA allows the analyzer to search files for patterns defined in local rule files.

the project stores its rules in:

```text
atlalyzer/
├── main.py
├── teste_main.py
└── rules/
    └── basic_suspicious.yar
```

example rule:

```yara
rule Suspicious_PowerShell_Download
{
    meta:
        description = "Detects download-related PowerShell patterns"
        severity = "medium"

    strings:
        $download1 = "DownloadString" nocase
        $download2 = "DownloadFile" nocase
        $encoded = "-EncodedCommand" nocase

    condition:
        1 of them
}
```

create additional `.yar` files inside the `rules/` directory to expand the local detection rules.

a rule match indicates that a pattern was found. it does **not**, by itself, prove malicious intent.

## `06 // project structure`

```text
atlalyzer/
├── main.py                  # analysis engine
├── teste_main.py            # automated tests
├── rules/
│   └── basic_suspicious.yar # local YARA rules
├── README.md
└── .gitignore
```

other files, including generated reports and the SQLite database, may appear as the project evolves.

## `07 // limitations`

atlalyzer is an early-stage project. its current capabilities are useful for learning and preliminary inspection, but it is not a complete malware analysis platform.

**what it does not do yet:**

- execute files in an isolated sandbox.
- guarantee malware detection or certify that a file is safe.
- replace antivirus engines or multi-engine services such as VirusTotal.
- provide a complete behavioral analysis of running processes.
- perform comprehensive reverse engineering or memory forensics.
- query threat intelligence services for reputation checks.
- guarantee detection of obfuscated, packed or previously unknown malware.
- offer a fully developed, stable command-line interface with documented flags.
- provide a graphical dashboard or web interface.

heuristics and YARA rules can produce false positives and false negatives. risk scores are indicators for further investigation, not definitive security verdicts.

## `08 // roadmap`

planned improvements, subject to change:

- [ ] complete and document a consistent CLI.
- [ ] improve file format and signature coverage.
- [ ] expand archive inspection and validation.
- [ ] improve anomaly classification and risk scoring.
- [ ] identify suspicious indicators such as URLs, domains and IP addresses.
- [ ] support optional threat intelligence lookups.
- [ ] expand automated tests and test coverage.
- [ ] improve report export and analysis history.
- [ ] add safer workflows for handling suspicious files.
- [ ] explore a web interface for interactive reports.

features listed here are planned, not necessarily implemented.

## `09 // security & responsible use`

use atlalyzer on files you own or are authorized to analyze.

when inspecting suspicious files, prefer an isolated environment and avoid executing unknown files. static analysis alone cannot establish whether a file is harmless.

this project is intended for education, defensive security research and experimentation.

## `10 // development`

contributions, suggestions and constructive feedback are welcome.

the project is developed incrementally: implement a feature, understand its behavior, test it and improve it.

**author:** [@3murred](https://github.com/3murred)

**repository:** [github.com/3murred/atlalyzer](https://github.com/3murred/atlalyzer)

---

<p align="center">
  <code>building tools. breaking assumptions. learning security.</code>
  <br><br>
  <i>made with python, curiosity and a terminal.</i>
</p>
