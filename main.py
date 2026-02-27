import csv
import json
import os
import time

import aisecurity
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
from aisecurity.scan.inline.scanner import Scanner
from aisecurity.scan.models.content import Content

API_KEY = os.environ["AIRS_API_KEY"]
AI_PROFILE_NAME = os.environ["AIRS_AI_PROFILE"]

INPUT_CSV = "malicious_test_prompts.csv"
OUTPUT_CSV = "scan_results.csv"

aisecurity.init(api_key=API_KEY)
ai_profile = AiProfile(profile_name=AI_PROFILE_NAME)
scanner = Scanner()

results = []

with open(INPUT_CSV, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    rows = list(reader)

print(f"Scanning {len(rows)} prompts...\n")

for row in rows:
    prompt_id = row["id"]
    category = row["category"]
    prompt_text = row["prompt"]
    description = row["description"]

    print(f"[{prompt_id}/{len(rows)}] Scanning: {description}...")

    try:
        scan_response = scanner.sync_scan(
            ai_profile=ai_profile,
            content=Content(prompt=prompt_text),
        )
        resp = scan_response.to_dict()

        result = {
            "id": prompt_id,
            "category": category,
            "prompt": prompt_text,
            "description": description,
            "action": resp.get("action", ""),
            "category_result": resp.get("category", ""),
            "prompt_detected_categories": json.dumps(
                resp.get("prompt_detected_categories", {})
            ),
            "scan_id": resp.get("scan_id", ""),
            "report_id": resp.get("report_id", ""),
            "raw_response": json.dumps(resp),
        }
    except Exception as e:
        print(f"  ERROR: {e}")
        result = {
            "id": prompt_id,
            "category": category,
            "prompt": prompt_text,
            "description": description,
            "action": "error",
            "category_result": "error",
            "prompt_detected_categories": "",
            "scan_id": "",
            "report_id": "",
            "raw_response": str(e),
        }

    results.append(result)
    print(f"  -> action={result['action']}  category={result['category_result']}")

    # small delay to avoid rate limiting
    time.sleep(0.5)

# write results CSV
fieldnames = [
    "id",
    "category",
    "prompt",
    "description",
    "action",
    "category_result",
    "prompt_detected_categories",
    "scan_id",
    "report_id",
    "raw_response",
]

with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(results)

print(f"\nDone. Results written to {OUTPUT_CSV}")
