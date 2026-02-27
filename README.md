# Prisma AIRS Prompt Scanner

Batch-scans a CSV of test prompts against Palo Alto Networks' [Prisma AIRS](https://docs.paloaltonetworks.com/ai-runtime-security) API and outputs categorized results to a new CSV.

Includes 25 pre-built malicious test prompts across categories like prompt injection, data exfiltration, social engineering, encoding evasion, and more.

## Prerequisites

- Python 3.11+
- A Prisma AIRS API key and AI security profile name

## Setup

### 1. Clone the repo

```bash
git clone git@github.com:cdot65/sdk-test.git
cd sdk-test
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

```
AIRS_API_KEY="your-api-key-here"
AIRS_AI_PROFILE="your-ai-profile-name-here"
```

### 3. Install dependencies

#### Option A: uv (recommended)

```bash
uv sync
```

#### Option B: pip

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install pan-aisecurity
```

## Usage

### With uv

```bash
export $(cat .env | xargs)
uv run main.py
```

### With pip

```bash
source .venv/bin/activate
export $(cat .env | xargs)
python main.py
```

The script reads `malicious_test_prompts.csv`, scans each prompt, and writes results to `scan_results.csv`.

## Output

`scan_results.csv` contains the following columns:

| Column | Description |
|---|---|
| `id` | Prompt ID from input CSV |
| `category` | Attack category (e.g. `prompt_injection`) |
| `prompt` | The test prompt text |
| `description` | Human-readable description of the attack |
| `action` | AIRS verdict: `allow` or `block` |
| `category_result` | AIRS classification: `benign` or `malicious` |
| `prompt_detected_categories` | JSON of detected threat categories |
| `scan_id` | AIRS scan identifier |
| `report_id` | AIRS report identifier |
| `raw_response` | Full JSON response from the API |

## Test Prompt Categories

| Category | Count | Description |
|---|---|---|
| `prompt_injection` | 5 | Instruction override and jailbreak attempts |
| `data_exfiltration` | 3 | System prompt and config extraction |
| `social_engineering` | 2 | Authority impersonation, emotional manipulation |
| `encoding_evasion` | 2 | Base64/ROT13 obfuscation |
| `context_manipulation` | 3 | Fictional/academic framing bypasses |
| `multi_turn_attack` | 2 | Gradual escalation setups |
| `token_smuggling` | 2 | Character/token-level evasion |
| `privilege_escalation` | 2 | Fake admin mode attempts |
| `goal_hijacking` | 2 | Output manipulation |
| `recursive_injection` | 2 | Indirect injection via external content |
