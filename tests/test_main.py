import csv
import json
import os
import textwrap
from unittest.mock import MagicMock, patch

import pytest

# Patch env vars and heavy imports before importing main
os.environ.setdefault("AIRS_API_KEY", "test-key")
os.environ.setdefault("AIRS_AI_PROFILE", "test-profile")

with (
    patch("aisecurity.init"),
    patch("aisecurity.generated_openapi_client.models.ai_profile.AiProfile"),
    patch("aisecurity.scan.inline.scanner.Scanner"),
    patch("aisecurity.scan.models.content.Content"),
):
    from main import FIELDNAMES, load_prompts, main, scan_prompt, write_results


@pytest.fixture()
def sample_csv(tmp_path):
    path = tmp_path / "prompts.csv"
    path.write_text(
        textwrap.dedent("""\
            id,category,prompt,description
            1,prompt_injection,test prompt,test desc
            2,data_exfiltration,another prompt,another desc
        """)
    )
    return str(path)


@pytest.fixture()
def sample_row():
    return {
        "id": "1",
        "category": "prompt_injection",
        "prompt": "test prompt",
        "description": "test desc",
    }


class TestLoadPrompts:
    def test_loads_rows(self, sample_csv):
        rows = load_prompts(sample_csv)
        assert len(rows) == 2
        assert rows[0]["id"] == "1"
        assert rows[1]["category"] == "data_exfiltration"


class TestScanPrompt:
    def test_success(self, sample_row):
        mock_scanner = MagicMock()
        mock_profile = MagicMock()
        mock_scanner.sync_scan.return_value.to_dict.return_value = {
            "action": "block",
            "category": "malicious",
            "prompt_detected": {"injection": True, "dlp": False},
            "scan_id": "abc-123",
            "report_id": "Rabc-123",
        }

        result = scan_prompt(mock_scanner, mock_profile, sample_row)

        assert result["id"] == "1"
        assert result["action"] == "block"
        assert result["category_result"] == "malicious"
        assert result["category"] == "prompt_injection"
        assert json.loads(result["prompt_detected_categories"]) == {
            "injection": True,
            "dlp": False,
        }
        assert result["scan_id"] == "abc-123"
        assert result["report_id"] == "Rabc-123"
        assert "block" in result["raw_response"]

    def test_missing_fields_default_empty(self, sample_row):
        mock_scanner = MagicMock()
        mock_profile = MagicMock()
        mock_scanner.sync_scan.return_value.to_dict.return_value = {}

        result = scan_prompt(mock_scanner, mock_profile, sample_row)

        assert result["action"] == ""
        assert result["category_result"] == ""
        assert result["scan_id"] == ""
        assert result["report_id"] == ""

    def test_error_handling(self, sample_row):
        mock_scanner = MagicMock()
        mock_profile = MagicMock()
        mock_scanner.sync_scan.side_effect = RuntimeError("API timeout")

        result = scan_prompt(mock_scanner, mock_profile, sample_row)

        assert result["action"] == "error"
        assert result["category_result"] == "error"
        assert result["prompt_detected_categories"] == ""
        assert "API timeout" in result["raw_response"]


class TestWriteResults:
    def test_writes_csv(self, tmp_path):
        path = str(tmp_path / "out.csv")
        rows = [
            {
                "id": "1",
                "category": "test",
                "prompt": "p",
                "description": "d",
                "action": "block",
                "category_result": "malicious",
                "prompt_detected_categories": "{}",
                "scan_id": "s1",
                "report_id": "r1",
                "raw_response": "{}",
            }
        ]

        write_results(path, rows)

        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            written = list(reader)

        assert len(written) == 1
        assert written[0]["action"] == "block"
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
            {"id": "1", "category": "c", "prompt": "p", "description": "d"}
        ]
        mock_scan.return_value = {
            "action": "block",
            "category_result": "malicious",
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
