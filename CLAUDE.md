# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Example repo showing batch prompt scanning via the Palo Alto Networks Prisma AIRS API using `pan-aisecurity` SDK. Two modes: synchronous (`main.py`) and multi-threaded (`main_threaded.py`).

## Commands

```bash
uv sync                  # install deps
uv run main.py           # sync scan
uv run main_threaded.py  # threaded scan
uv run pytest            # run tests (with coverage)
uv run ruff check --fix . # lint
uv run ruff format .      # format
```

Pre-commit hooks run ruff check + format on commit.

## Architecture

- `main.py` — synchronous scanner: loads `prompts.csv`, scans each prompt via `Scanner.sync_scan()`, writes results back
- `main_threaded.py` — threaded scanner: same CSV contract, configurable worker pool, retry logic
- `prompts.example.csv` — example CSV with headers and 5 sample rows (copy to `prompts.csv` to use)
- `tests/` — unit tests using unittest.mock to patch the aisecurity SDK

## Environment

Requires `.env` with `AIRS_API_KEY` and `AIRS_AI_PROFILE`. Auto-loaded via `python-dotenv`.

## Key SDK types

- `aisecurity.init(api_key=...)` — SDK initialization
- `AiProfile(profile_name=...)` — security profile selector
- `Scanner().sync_scan(ai_profile=..., content=Content(prompt=...))` — the scan call
