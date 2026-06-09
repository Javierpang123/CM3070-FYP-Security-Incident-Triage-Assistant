import json
import io
import pytest
from unittest.mock import patch, MagicMock

@pytest.fixture
def flask_client():
    """Create a test Flask client."""
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

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
    
@pytest.fixture
def sample_vision_result():
    return {
        "model": "vision",
        "confidence": 0.70,
        "entities": ["192.168.1.105", "EventID:4625"],
        "summary": "Visual: dashboard showing multiple failed login alerts. Possible tactic: Credential Access.",
        "attack_classification": "Credential Access",
        "severity": 3,
        "raw": "dashboard showing failed login alerts credential access",
    }

@pytest.fixture
def sample_speech_result():
    return {
        "model": "speech",
        "confidence": 0.75,
        "entities": ["administrator", "DESKTOP-HR4KX92"],
        "summary": "Analyst noted suspicious login attempts from unknown IP on admin account",
        "attack_classification": "Credential Access",
        "severity": 3,
        "raw": "Analyst noted suspicious login attempts from unknown IP on admin account.",
    }

@pytest.fixture
def error_result():
    return {
        "model": "text",
        "confidence": 0.0,
        "entities": [],
        "summary": "[ERROR] Ollama service unreachable",
        "attack_classification": "Unknown",
        "severity": 1,
        "raw": "",
    }
    
# FLASK ROUTE TESTS CLASS
class TestFlaskRoutes:

    # Test to verify that index route of UI returns HTTP 200 (OK)
    def test_index_returns_200(self, flask_client):
        response = flask_client.get("/")
        assert response.status_code == 200

    # Test to verify that submitting POST request to /analyse route,
    # must return HTTP 400 (Bad Request)
    def test_analyse_no_input_returns_400(self, flask_client):
        """POST /analyse with no inputs must return 400."""
        response = flask_client.post("/analyse", data={})
        assert response.status_code == 400
        data = response.get_json()
        assert data["status"] == "error"

    # Test to verify that unsupported image extension returns a warning, not a 500.
    def test_analyse_invalid_image_extension_returns_warning(self, flask_client):
        
        with patch("app.routes.analyse_text") as mock_text, \
             patch("app.routes.late_fusion_orchestrator") as mock_fuse:
            mock_text.return_value = {"model": "text", "confidence": 0.8, "entities": [],
                                      "summary": "Test", "attack_classification": "Execution",
                                      "severity": 3, "raw": ""}
            mock_fuse.return_value = {"severity": 3, "attack_classification": "Execution",
                                      "recommended_actions": ["Action 1"],
                                      "confidence": 0.8, "entities": [],
                                      "modality_breakdown": {"text": {}, "vision": None, "speech": None},
                                      "fusion_weights": {"text": 1.0},
                                      "active_modalities": ["text"]}

            log_file = (io.BytesIO(b'{"EventID": 4625}'), "test.json")
            bad_image = (io.BytesIO(b"fake image data"), "screenshot.gif")

            response = flask_client.post("/analyse",
                                         data={"log_file": log_file, "screenshot": bad_image},
                                         content_type="multipart/form-data",)
            
            assert response.status_code == 200
            data = response.get_json()
            assert "warnings" in data

    # Test to verify that valid log file upload returns a triage output 
    @patch("app.routes.analyse_text")
    @patch("app.routes.late_fusion_orchestrator")
    def test_analyse_valid_log_file_returns_triage(self, mock_fuse, 
                                                   mock_text, flask_client):
    
        mock_text.return_value = {"model": "text", "confidence": 0.85, "entities": ["192.168.1.105"],
                                  "summary": "Brute force detected.", "attack_classification": "Credential Access",
                                  "severity": 4, "raw": ""}
        
        mock_fuse.return_value = {"severity": 4, "attack_classification": "Credential Access",
                                  "recommended_actions": ["Reset credentials."],
                                  "confidence": 0.85, "entities": ["192.168.1.105"],
                                  "modality_breakdown": {"text": {"confidence": 0.85, 
                                                                  "attack_classification": "Credential Access",
                                                                                            "severity": 4, 
                                                                                            "summary": "Brute force detected.", 
                                                                                            "entities": []},
                                                         "vision": None, 
                                                         "speech": None},
                                  "fusion_weights": {"text": 1.0},
                                  "active_modalities": ["text"]}

        log_file = (io.BytesIO(b'{"EventID": 4625, "IpAddress": "192.168.1.105"}'), "test.json")
        response = flask_client.post("/analyse",
                                     data={"log_file": log_file},
                                     content_type="multipart/form-data")
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "ok"
        assert "triage" in data
        assert data["triage"]["severity"] == 4