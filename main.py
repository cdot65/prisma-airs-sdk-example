import csv
import os
import time

import aisecurity
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
from aisecurity.scan.inline.scanner import Scanner
from aisecurity.scan.models.content import Content

CSV_PATH = "prompts.csv"
SCAN_DELAY_SECONDS = 0.5

FIELDNAMES = [
    "index",
    "prompt_preview",
    "expected",
    "action",
    "category",
    "scan_id",
    "report_id",
    "agent",
    "injection",
    "dlp",
    "toxic_content",
    "malicious_code",
    "url_cats",
    "topic_violation",
    "dlp_verdict",
    "dlp_profile_name",
    "tc_verdict",
    "malicious_code_verdict",
    "uf_urls",
    "uf_categories",
    "cg_status",
    "overall_actions",
    "overall_verdicts",
    "match",
    "error_message",
]

READONLY_FIELDS = {"index", "prompt_preview", "expected"}


def load_prompts(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def extract_report_details(scanner, report_id):
    """Query report API for detailed verdict info."""
    details = {
        "dlp_verdict": "",
        "dlp_profile_name": "",
        "tc_verdict": "",
        "malicious_code_verdict": "",
        "uf_urls": "",
        "uf_categories": "",
        "cg_status": "",
        "overall_actions": "",
        "overall_verdicts": "",
    }

    try:
        reports = scanner.query_by_report_ids([report_id])
    except Exception:
        return details

    if not reports:
        return details

    report = reports[0]
    if not report.detection_results:
        return details

    actions_parts = []
    verdicts_parts = []

    for dr in report.detection_results:
        if dr.data_type != "prompt":
            continue

        svc = dr.detection_service or ""
        if dr.action is not None:
            actions_parts.append(f"{svc}:{dr.action}")
        if dr.verdict is not None:
            verdicts_parts.append(f"{svc}:{dr.verdict}")

        if dr.result_detail is None:
            continue

        rd = dr.result_detail

        if rd.dlp_report:
            details["dlp_verdict"] = rd.dlp_report.data_pattern_rule1_verdict or ""
            details["dlp_profile_name"] = rd.dlp_report.dlp_profile_name or ""

        if rd.tc_report:
            details["tc_verdict"] = rd.tc_report.verdict or ""

        if rd.mc_report:
            details["malicious_code_verdict"] = rd.mc_report.verdict or ""

        if rd.urlf_report:
            urls = [e.url for e in rd.urlf_report if e.url]
            cats = []
            for e in rd.urlf_report:
                if e.categories:
                    cats.extend(e.categories)
            details["uf_urls"] = "|".join(urls) if urls else ""
            details["uf_categories"] = "|".join(cats) if cats else ""

        if rd.cg_report:
            details["cg_status"] = rd.cg_report.status or ""

    details["overall_actions"] = "|".join(actions_parts)
    details["overall_verdicts"] = "|".join(verdicts_parts)

    return details


def compute_match(expected, action):
    expected_block = expected.upper() == "TRUE"
    was_blocked = action.lower() == "block"
    return "PASS" if expected_block == was_blocked else "FAIL"


def build_error_result(row, error):
    result = {field: row.get(field, "") for field in READONLY_FIELDS}
    for field in FIELDNAMES:
        if field not in result:
            result[field] = ""
    result["action"] = "error"
    result["category"] = "error"
    result["match"] = "ERROR"
    result["error_message"] = str(error)
    return result


def scan_prompt(scanner, ai_profile, row):
    scan_response = scanner.sync_scan(
        ai_profile=ai_profile,
        content=Content(prompt=row["prompt_preview"]),
    )
    resp = scan_response.to_dict()
    prompt_detected = resp.get("prompt_detected", {})

    report_id = resp.get("report_id", "")
    action = resp.get("action", "")

    result = {field: row.get(field, "") for field in READONLY_FIELDS}
    result.update(
        {
            "action": action,
            "category": resp.get("category", ""),
            "scan_id": resp.get("scan_id", ""),
            "report_id": report_id,
            "agent": str(prompt_detected.get("agent", False)).upper(),
            "injection": str(prompt_detected.get("injection", False)).upper(),
            "dlp": str(prompt_detected.get("dlp", False)).upper(),
            "toxic_content": str(prompt_detected.get("toxic_content", False)).upper(),
            "malicious_code": str(prompt_detected.get("malicious_code", False)).upper(),
            "url_cats": str(prompt_detected.get("url_cats", False)).upper(),
            "topic_violation": str(
                prompt_detected.get("topic_violation", False)
            ).upper(),
            "error_message": "",
        }
    )

    if report_id:
        result.update(extract_report_details(scanner, report_id))
    else:
        for field in (
            "dlp_verdict",
            "dlp_profile_name",
            "tc_verdict",
            "malicious_code_verdict",
            "uf_urls",
            "uf_categories",
            "cg_status",
            "overall_actions",
            "overall_verdicts",
        ):
            result[field] = ""

    result["match"] = compute_match(row.get("expected", ""), action)
    return result


def write_results(path, results):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(results)


def main():
    from dotenv import load_dotenv

    load_dotenv(override=True)

    api_key = os.environ["AIRS_API_KEY"]
    ai_profile_name = os.environ["AIRS_AI_PROFILE"]

    aisecurity.init(api_key=api_key)
    ai_profile = AiProfile(profile_name=ai_profile_name)
    scanner = Scanner()

    rows = load_prompts(CSV_PATH)
    print(f"Scanning {len(rows)} prompts...\n")

    results = []
    for i, row in enumerate(rows):
        preview = row.get("prompt_preview", "")[:60]
        print(f"[{i + 1}/{len(rows)}] Scanning: {preview}...")
        try:
            result = scan_prompt(scanner, ai_profile, row)
        except Exception as error:
            result = build_error_result(row, error)
        results.append(result)
        print(f"  -> action={result['action']}  match={result['match']}")
        time.sleep(SCAN_DELAY_SECONDS)

    write_results(CSV_PATH, results)
    print(f"\nDone. Results written to {CSV_PATH}")


if __name__ == "__main__":
    main()
