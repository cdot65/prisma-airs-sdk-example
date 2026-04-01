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
    from main import (
        FIELDNAMES,
        build_error_result,
        compute_match,
        extract_report_details,
        load_prompts,
        main,
        scan_prompt,
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


class TestMain:
    @patch("main.write_results")
    @patch("main.scan_prompt")
    @patch("main.load_prompts")
    @patch("main.Scanner")
    @patch("main.AiProfile")
    @patch("main.aisecurity")
    @patch("main.time")
    @patch("dotenv.load_dotenv")
    def test_main_flow(
        self,
        mock_dotenv,
        mock_time,
        mock_aisec,
        mock_profile_cls,
        mock_scanner_cls,
        mock_load,
        mock_scan,
        mock_write,
    ):
        mock_load.return_value = [
            {"index": "0", "prompt_preview": "p", "expected": "TRUE"}
        ]
        mock_scan.return_value = {
            "action": "block",
            "match": "PASS",
        }

        with patch.dict(
            os.environ,
            {"AIRS_API_KEY": "k", "AIRS_AI_PROFILE": "p"},
        ):
            main()

        mock_dotenv.assert_called_once()
        mock_aisec.init.assert_called_once_with(api_key="k")
        mock_load.assert_called_once()
        mock_scan.assert_called_once()
        mock_write.assert_called_once()
        mock_time.sleep.assert_called_once_with(0.5)
