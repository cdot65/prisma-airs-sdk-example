import csv
import os
import queue
import threading
import time

import aisecurity
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
from aisecurity.scan.inline.scanner import Scanner
from aisecurity.scan.models.content import Content

CSV_PATH = "prompts.csv"
DEFAULT_WORKER_COUNT = 20
REQUEST_RETRIES = 3
RETRY_BACKOFF_SECONDS = 1.0
QUEUE_GET_TIMEOUT_SECONDS = 0.5

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


def scan_prompt_with_retries(scanner, ai_profile, row):
    last_error = None
    for attempt in range(1, REQUEST_RETRIES + 1):
        try:
            return scan_prompt(scanner, ai_profile, row)
        except Exception as error:
            last_error = error
            if attempt == REQUEST_RETRIES:
                break
            time.sleep(RETRY_BACKOFF_SECONDS * attempt)
    return build_error_result(row, last_error)


def write_results(path, results):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(results)


def get_worker_count():
    raw_value = os.environ.get("AIRS_THREAD_COUNT", str(DEFAULT_WORKER_COUNT))
    try:
        return max(DEFAULT_WORKER_COUNT, int(raw_value))
    except ValueError:
        print(
            "Invalid AIRS_THREAD_COUNT; "
            f"falling back to {DEFAULT_WORKER_COUNT} threads.",
            flush=True,
        )
        return DEFAULT_WORKER_COUNT


def threaded_scan(rows, ai_profile, worker_count=DEFAULT_WORKER_COUNT):
    total = len(rows)
    if total == 0:
        return []

    effective_worker_count = max(DEFAULT_WORKER_COUNT, worker_count)
    task_queue = queue.Queue()
    results = [None] * total
    result_lock = threading.Lock()
    print_lock = threading.Lock()
    progress = {"completed": 0}

    for index, row in enumerate(rows):
        task_queue.put((index, row))

    def log(message):
        with print_lock:
            print(message, flush=True)

    def worker(worker_id):
        scanner = Scanner()

        while True:
            try:
                index, row = task_queue.get(timeout=QUEUE_GET_TIMEOUT_SECONDS)
            except queue.Empty:
                if task_queue.empty():
                    return
                continue

            try:
                preview = row.get("prompt_preview", "")[:60]
                log(
                    f"[worker-{worker_id:02d}] "
                    f"[{row['index']}/{total}] Scanning: {preview}..."
                )
                result = scan_prompt_with_retries(scanner, ai_profile, row)
                results[index] = result

                with result_lock:
                    progress["completed"] += 1
                    completed = progress["completed"]

                log(
                    f"[worker-{worker_id:02d}] "
                    f"Completed {completed}/{total}: "
                    f"action={result['action']} match={result['match']}"
                )
            except Exception as error:
                results[index] = build_error_result(row, error)
                with result_lock:
                    progress["completed"] += 1
                    completed = progress["completed"]
                log(
                    f"[worker-{worker_id:02d}] "
                    f"Completed {completed}/{total}: action=error"
                )
            finally:
                task_queue.task_done()

    threads = [
        threading.Thread(
            target=worker,
            args=(worker_id,),
            name=f"scan-worker-{worker_id:02d}",
            daemon=True,
        )
        for worker_id in range(1, effective_worker_count + 1)
    ]

    for thread in threads:
        thread.start()

    task_queue.join()

    for thread in threads:
        thread.join()

    return [result for result in results if result is not None]


def main():
    from dotenv import load_dotenv

    load_dotenv(override=True)

    api_key = os.environ["AIRS_API_KEY"]
    ai_profile_name = os.environ["AIRS_AI_PROFILE"]

    aisecurity.init(api_key=api_key)
    ai_profile = AiProfile(profile_name=ai_profile_name)
    worker_count = get_worker_count()

    rows = load_prompts(CSV_PATH)
    print(f"Scanning {len(rows)} prompts with {worker_count} threads...\n")

    results = threaded_scan(rows, ai_profile, worker_count=worker_count)
    write_results(CSV_PATH, results)
    print(f"\nDone. Results written to {CSV_PATH}")


if __name__ == "__main__":
    main()
