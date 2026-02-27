import csv
import json
import os
import time

import aisecurity
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
from aisecurity.scan.inline.scanner import Scanner
from aisecurity.scan.models.content import Content

INPUT_CSV = "malicious_test_prompts.csv"
OUTPUT_CSV = "scan_results.csv"

FIELDNAMES = [
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


def load_prompts(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def scan_prompt(scanner, ai_profile, row):
    prompt_id = row["id"]
    category = row["category"]
    prompt_text = row["prompt"]
    description = row["description"]

    try:
        scan_response = scanner.sync_scan(
            ai_profile=ai_profile,
            content=Content(prompt=prompt_text),
        )
        resp = scan_response.to_dict()

        return {
            "id": prompt_id,
            "category": category,
            "prompt": prompt_text,
            "description": description,
            "action": resp.get("action", ""),
            "category_result": resp.get("category", ""),
            "prompt_detected_categories": json.dumps(resp.get("prompt_detected", {})),
            "scan_id": resp.get("scan_id", ""),
            "report_id": resp.get("report_id", ""),
            "raw_response": json.dumps(resp),
        }
    except Exception as e:
        return {
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


def write_results(path, results):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(results)


def main():
    from dotenv import load_dotenv

    load_dotenv()

    api_key = os.environ["AIRS_API_KEY"]
    ai_profile_name = os.environ["AIRS_AI_PROFILE"]

    aisecurity.init(api_key=api_key)
    ai_profile = AiProfile(profile_name=ai_profile_name)
    scanner = Scanner()

    rows = load_prompts(INPUT_CSV)
    print(f"Scanning {len(rows)} prompts...\n")

    results = []
    for row in rows:
        print(f"[{row['id']}/{len(rows)}] Scanning: {row['description']}...")
        result = scan_prompt(scanner, ai_profile, row)
        results.append(result)
        print(f"  -> action={result['action']}  category={result['category_result']}")
        time.sleep(0.5)

    write_results(OUTPUT_CSV, results)
    print(f"\nDone. Results written to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
