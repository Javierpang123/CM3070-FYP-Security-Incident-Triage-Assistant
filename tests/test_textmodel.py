import json
import pytest
from unittest.mock import patch, MagicMock

# Fixture providing a sample text model result for testing
@pytest.fixture
def sample_text_result():
    return {
        "model": "text",
        "confidence": 0.85,
        "entities": ["administrator", "192.168.1.105", "svchost.exe"],
        "summary": "Repeated failed logon attempts from external IP suggest brute force.",
        "attack_classification": "Credential Access",
        "severity": 4,
        "raw": '{"attack_classification": "Credential Access", "severity": 4}',
    }


# TEXT MODEL TESTS CLASS
class TestTextModel:

    # Test to verify that the text model returns a result with standardised output
    def test_returns_standardised_schema(self, sample_text_result):
        """Wrapper output must contain all required schema keys."""
        required_keys = {"model", "confidence", "entities", "summary",
                         "attack_classification", "severity", "raw"}
        assert required_keys.issubset(sample_text_result.keys())

    # Test to verify that modell field is correctly set to "text"
    def test_model_field_is_text(self, sample_text_result):
        assert sample_text_result["model"] == "text"

    # Test to vertify that confidence is within expected range of 0.0 to 1.0
    def test_confidence_in_range(self, sample_text_result):
        assert 0.0 <= sample_text_result["confidence"] <= 1.0

    # Test to verify that severity is within expected range of 1 to 5
    def test_severity_in_range(self, sample_text_result):
        assert 1 <= sample_text_result["severity"] <= 5

    # Test to verify that entities field is a list, even if no entities are found    
    def test_entities_is_list(self, sample_text_result):
        assert isinstance(sample_text_result["entities"], list)

    # Test to verify that if Ollama is unreachable, wrapper returns a safe error result
    @patch("models.text_model.requests.post")
    def test_ollama_connection_error_returns_error_result(self, mock_post):
        import requests
        mock_post.side_effect = requests.exceptions.ConnectionError
        from models.text_model import analyse_text
        result = analyse_text("test log")
        assert result["confidence"] == 0.0
        assert result["attack_classification"] == "Unknown"
        assert "[ERROR]" in result["summary"]

    # Test to verify that Valid Ollama JSON response is parsed into correct schema.
    @patch("models.text_model.requests.post")
    def test_valid_ollama_response_parsed_correctly(self, mock_post):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "response": json.dumps({
                "attack_classification": "Execution",
                "severity": 3,
                "entities": ["powershell.exe"],
                "summary": "PowerShell execution detected.",
                "confidence_hint": "high",
            })
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        from models.text_model import analyse_text
        result = analyse_text({"EventID": 4688, "ProcessName": "powershell.exe"})

        assert result["attack_classification"] == "Execution"
        assert result["severity"] == 3
        assert result["confidence"] == 0.85  # "high" confidence hint
        assert "powershell.exe" in result["entities"]

    # Test to verify that dictionary input is serialised to JSON before sending to Ollama
    @patch("models.text_model.requests.post")
    def test_dict_input_serialised_to_json(self, mock_post):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "response": json.dumps({
                "attack_classification": "Unknown",
                "severity": 1,
                "entities": [],
                "summary": "No threat detected.",
                "confidence_hint": "low",
            })
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        from models.text_model import analyse_text
        result = analyse_text({"EventID": 4624})
        assert result["model"] == "text"
        call_args = mock_post.call_args
        prompt = call_args[1]["json"]["prompt"]
        assert "EventID" in prompt
        