import csv
import os
import textwrap
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("AIRS_API_KEY", "test-key")
os.environ.setdefault("AIRS_AI_PROFILE", "test-profile")

with (
    patch("aisecurity.init"),
    patch("aisecurity.generated_openapi_client.models.ai_profile.AiProfile"),
    patch("aisecurity.scan.inline.scanner.Scanner"),
    patch("aisecurity.scan.models.content.Content"),
):
    import main_threaded
    from main_threaded import (
        FIELDNAMES,
        build_error_result,
        compute_match,
        extract_report_details,
        get_worker_count,
        load_prompts,
        main,
        scan_prompt,
        scan_prompt_with_retries,
        threaded_scan,
        write_results,
    )


@pytest.fixture()
def sample_csv(tmp_path):
    path = tmp_path / "prompts.csv"
    path.write_text(
        textwrap.dedent("""\
            index,prompt_preview,expected,action,category,scan_id,report_id,agent,injection,dlp,toxic_content,malicious_code,url_cats,topic_violation,dlp_verdict,dlp_profile_name,tc_verdict,malicious_code_verdict,uf_urls,uf_categories,cg_status,overall_actions,overall_verdicts,match,error_message
            0,test prompt,TRUE,,,,,,,,,,,,,,,,,,,,,,
            1,another prompt,FALSE,,,,,,,,,,,,,,,,,,,,,,
        """)
    )
    return str(path)


@pytest.fixture()
def sample_row():
    return {
        "index": "0",
        "prompt_preview": "test prompt",
        "expected": "TRUE",
    }


class TestLoadPrompts:
    def test_loads_rows(self, sample_csv):
        rows = load_prompts(sample_csv)
        assert len(rows) == 2
        assert rows[0]["index"] == "0"
        assert rows[1]["prompt_preview"] == "another prompt"


class TestComputeMatch:
    def test_pass_when_expected_block(self):
        assert compute_match("TRUE", "block") == "PASS"

    def test_fail_when_expected_block_got_allow(self):
        assert compute_match("TRUE", "allow") == "FAIL"

    def test_pass_when_expected_allow(self):
        assert compute_match("FALSE", "allow") == "PASS"

    def test_fail_when_expected_allow_got_block(self):
        assert compute_match("FALSE", "block") == "FAIL"


class TestScanPrompt:
    def test_success(self, sample_row):
        mock_scanner = MagicMock()
        mock_profile = MagicMock()
        mock_scanner.sync_scan.return_value.to_dict.return_value = {
            "action": "block",
            "category": "malicious",
            "prompt_detected": {
                "injection": True,
                "dlp": False,
                "agent": True,
                "toxic_content": False,
                "malicious_code": False,
                "url_cats": False,
                "topic_violation": False,
            },
            "scan_id": "abc-123",
            "report_id": "Rabc-123",
        }
        mock_scanner.query_by_report_ids.return_value = []

        result = scan_prompt(mock_scanner, mock_profile, sample_row)

        assert result["index"] == "0"
        assert result["prompt_preview"] == "test prompt"
        assert result["action"] == "block"
        assert result["category"] == "malicious"
        assert result["injection"] == "TRUE"
        assert result["dlp"] == "FALSE"
        assert result["agent"] == "TRUE"
        assert result["scan_id"] == "abc-123"
        assert result["report_id"] == "Rabc-123"
        assert result["match"] == "PASS"

    def test_build_error_result(self, sample_row):
        result = build_error_result(sample_row, RuntimeError("API timeout"))

        assert result["action"] == "error"
        assert result["category"] == "error"
        assert result["match"] == "ERROR"
        assert "API timeout" in result["error_message"]
        assert result["index"] == "0"
        assert result["prompt_preview"] == "test prompt"


class TestExtractReportDetails:
    def test_extracts_details_from_report(self):
        mock_scanner = MagicMock()

        mock_dlp_report = MagicMock()
        mock_dlp_report.data_pattern_rule1_verdict = "NOT_MATCHED"
        mock_dlp_report.dlp_profile_name = "Sensitive Content"

        mock_tc_report = MagicMock()
        mock_tc_report.verdict = "malicious"

        mock_mc_report = MagicMock()
        mock_mc_report.verdict = "benign"

        mock_urlf_entry = MagicMock()
        mock_urlf_entry.url = "http://evil.com"
        mock_urlf_entry.categories = ["malware"]

        mock_cg_report = MagicMock()
        mock_cg_report.status = "completed"

        mock_detail = MagicMock()
        mock_detail.dlp_report = mock_dlp_report
        mock_detail.tc_report = mock_tc_report
        mock_detail.mc_report = mock_mc_report
        mock_detail.urlf_report = [mock_urlf_entry]
        mock_detail.cg_report = mock_cg_report

        mock_dr = MagicMock()
        mock_dr.data_type = "prompt"
        mock_dr.detection_service = "tc"
        mock_dr.action = "block"
        mock_dr.verdict = "malicious"
        mock_dr.result_detail = mock_detail

        mock_report = MagicMock()
        mock_report.detection_results = [mock_dr]

        mock_scanner.query_by_report_ids.return_value = [mock_report]

        details = extract_report_details(mock_scanner, "Rabc-123")

        assert details["dlp_verdict"] == "NOT_MATCHED"
        assert details["dlp_profile_name"] == "Sensitive Content"
        assert details["tc_verdict"] == "malicious"
        assert details["malicious_code_verdict"] == "benign"
        assert details["uf_urls"] == "http://evil.com"
        assert details["uf_categories"] == "malware"
        assert details["cg_status"] == "completed"
        assert "tc:block" in details["overall_actions"]
        assert "tc:malicious" in details["overall_verdicts"]

    def test_handles_empty_reports(self):
        mock_scanner = MagicMock()
        mock_scanner.query_by_report_ids.return_value = []

        details = extract_report_details(mock_scanner, "Rabc-123")

        assert details["dlp_verdict"] == ""
        assert details["tc_verdict"] == ""

    def test_handles_api_error(self):
        mock_scanner = MagicMock()
        mock_scanner.query_by_report_ids.side_effect = RuntimeError("API error")

        details = extract_report_details(mock_scanner, "Rabc-123")

        assert details["dlp_verdict"] == ""


class TestScanPromptWithRetries:
    @patch("main_threaded.time.sleep")
    def test_retries_then_succeeds(self, mock_sleep, sample_row):
        mock_scanner = MagicMock()
        mock_profile = MagicMock()
        mock_response = MagicMock()
        mock_response.to_dict.return_value = {
            "action": "allow",
            "category": "benign",
            "prompt_detected": {},
            "report_id": "",
        }
        mock_scanner.sync_scan.side_effect = [RuntimeError("temporary"), mock_response]

        result = scan_prompt_with_retries(mock_scanner, mock_profile, sample_row)

        assert result["action"] == "allow"
        assert result["category"] == "benign"
        mock_sleep.assert_called_once_with(main_threaded.RETRY_BACKOFF_SECONDS * 1)

    @patch("main_threaded.time.sleep")
    def test_returns_error_after_retries(self, mock_sleep, sample_row):
        mock_scanner = MagicMock()
        mock_profile = MagicMock()
        mock_scanner.sync_scan.side_effect = RuntimeError("still failing")

        result = scan_prompt_with_retries(mock_scanner, mock_profile, sample_row)

        assert result["action"] == "error"
        assert result["match"] == "ERROR"
        assert mock_sleep.call_count == main_threaded.REQUEST_RETRIES - 1


class TestWriteResults:
    def test_writes_csv(self, tmp_path):
        path = str(tmp_path / "out.csv")
        rows = [
            {
                "index": "0",
                "prompt_preview": "p",
                "expected": "TRUE",
                "action": "block",
                "category": "malicious",
                "scan_id": "s1",
                "report_id": "r1",
                "agent": "TRUE",
                "injection": "FALSE",
                "dlp": "FALSE",
                "toxic_content": "FALSE",
                "malicious_code": "FALSE",
                "url_cats": "FALSE",
                "topic_violation": "FALSE",
                "dlp_verdict": "",
                "dlp_profile_name": "",
                "tc_verdict": "malicious",
                "malicious_code_verdict": "benign",
                "uf_urls": "",
                "uf_categories": "",
                "cg_status": "",
                "overall_actions": "tc:block",
                "overall_verdicts": "tc:malicious",
                "match": "PASS",
                "error_message": "",
            }
        ]

        write_results(path, rows)

        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            written = list(reader)

        assert len(written) == 1
        assert written[0]["action"] == "block"
        assert written[0]["match"] == "PASS"
        assert list(written[0].keys()) == FIELDNAMES


class TestGetWorkerCount:
    def test_enforces_minimum(self):
        with patch.dict(os.environ, {"AIRS_THREAD_COUNT": "5"}):
            assert get_worker_count() == main_threaded.DEFAULT_WORKER_COUNT

    def test_uses_larger_env_value(self):
        with patch.dict(os.environ, {"AIRS_THREAD_COUNT": "32"}):
            assert get_worker_count() == 32


class TestThreadedScan:
    @patch("main_threaded.Scanner")
    @patch("main_threaded.scan_prompt_with_retries")
    def test_preserves_order_and_handles_errors(
        self,
        mock_scan_with_retries,
        mock_scanner_cls,
    ):
        rows = [
            {"index": "0", "prompt_preview": "p1", "expected": "TRUE"},
            {"index": "1", "prompt_preview": "p2", "expected": "TRUE"},
            {"index": "2", "prompt_preview": "p3", "expected": "FALSE"},
        ]
        ai_profile = MagicMock()

        mock_scanner_cls.side_effect = lambda: MagicMock()
        mock_scan_with_retries.side_effect = [
            {"index": "0", "action": "block", "match": "PASS"},
            {"index": "1", "action": "error", "match": "ERROR"},
            {"index": "2", "action": "allow", "match": "PASS"},
        ]

        results = threaded_scan(rows, ai_profile, worker_count=20)

        assert [r["index"] for r in results] == ["0", "1", "2"]
        assert results[0]["action"] == "block"
        assert results[1]["action"] == "error"
        assert results[2]["action"] == "allow"
        assert mock_scanner_cls.call_count == 20
        assert mock_scan_with_retries.call_count == 3


class TestMain:
    @patch("main_threaded.write_results")
    @patch("main_threaded.threaded_scan")
    @patch("main_threaded.load_prompts")
    @patch("main_threaded.AiProfile")
    @patch("main_threaded.aisecurity")
    @patch("dotenv.load_dotenv")
    def test_main_flow(
        self,
        mock_dotenv,
        mock_aisec,
        mock_profile_cls,
        mock_load,
        mock_threaded_scan,
        mock_write,
    ):
        mock_load.return_value = [
            {"index": "0", "prompt_preview": "p", "expected": "TRUE"}
        ]
        mock_threaded_scan.return_value = [
            {"index": "0", "action": "block", "match": "PASS"}
        ]

        with patch.dict(
            os.environ,
            {"AIRS_API_KEY": "k", "AIRS_AI_PROFILE": "p"},
        ):
            main()

        mock_dotenv.assert_called_once()
        mock_aisec.init.assert_called_once_with(api_key="k")
        mock_profile_cls.assert_called_once_with(profile_name="p")
        mock_load.assert_called_once_with(main_threaded.CSV_PATH)
        mock_write.assert_called_once_with(
            main_threaded.CSV_PATH, mock_threaded_scan.return_value
        )
