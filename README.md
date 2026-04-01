# Prisma AIRS SDK Example

Example scripts for batch-scanning prompts against Palo Alto Networks [Prisma AIRS](https://docs.paloaltonetworks.com/ai-runtime-security) using the `pan-aisecurity` Python SDK.

Two scanning modes:

- **`main.py`** — synchronous, one prompt at a time with 0.5s delay
- **`main_threaded.py`** — multi-threaded with configurable worker pool (default 20)

Both scripts read from `prompts.csv` and write results back to the same file.

## Prerequisites

- Python 3.11+
- Prisma AIRS API key and AI security profile name

## Setup

```bash
git clone git@github.com:cdot65/prisma-airs-sdk-example.git
cd prisma-airs-sdk-example
```

### Configure credentials

```bash
cp .env.example .env
```

Edit `.env`:

```
AIRS_API_KEY="your-api-key-here"
AIRS_AI_PROFILE="your-ai-profile-name-here"
```

### Install dependencies

```bash
uv sync
```

Or with pip:

```bash
python -m venv .venv
source .venv/bin/activate
pip install pan-aisecurity python-dotenv
```

### Prepare your prompts

```bash
cp prompts.example.csv prompts.csv
```

Edit `prompts.csv` to add your test prompts. Only three columns are required as input:

| Column | Description |
|---|---|
| `index` | Row number (0-based) |
| `prompt_preview` | The prompt text to scan |
| `expected` | `TRUE` if the prompt should be blocked, `FALSE` if allowed |

All other columns are populated by the scanner after running.

## Usage

### Synchronous scan

```bash
uv run main.py
```

### Threaded scan

```bash
uv run main_threaded.py
```

Set `AIRS_THREAD_COUNT` to control worker pool size (minimum 20):

```bash
AIRS_THREAD_COUNT=50 uv run main_threaded.py
```

## Output columns

After scanning, `prompts.csv` is updated with these result columns:

| Column | Description |
|---|---|
| `action` | AIRS verdict: `allow` or `block` |
| `category` | AIRS classification: `benign` or `malicious` |
| `scan_id` | Scan identifier |
| `report_id` | Report identifier |
| `agent` | Agent security detection triggered |
| `injection` | Prompt injection detection triggered |
| `dlp` | Data loss prevention detection triggered |
| `toxic_content` | Toxic content detection triggered |
| `malicious_code` | Malicious code detection triggered |
| `url_cats` | URL filtering detection triggered |
| `topic_violation` | Topic violation detection triggered |
| `match` | `PASS` if result matches `expected`, `FAIL` otherwise, `ERROR` on failure |
| `error_message` | Error details if scan failed |

Additional verdict detail columns (`dlp_verdict`, `tc_verdict`, `overall_actions`, etc.) are populated when report data is available.

## Tests

```bash
uv run pytest
```

## Linting

```bash
uv run ruff check --fix .
uv run ruff format .
```
