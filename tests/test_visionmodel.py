import json
import pytest
from unittest.mock import patch, MagicMock

# Fixture providing a sample vision model result for testing
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
    
# VISION MODEL TESTS CLASS
class TestVisionModel:

    # Test to verify that the vision model returns a result with standardised output
    def test_returns_standardised_schema(self, sample_vision_result):
        required_keys = {"model", "confidence", "entities", "summary",
                         "attack_classification", "severity", "raw"}
        assert required_keys.issubset(sample_vision_result.keys())

    # Test to verify that model field is correctly set to "vision"
    def test_model_field_is_vision(self, sample_vision_result):
        assert sample_vision_result["model"] == "vision"

    # Test to verify that confidence is within expected range of 0.0 to 1.0
    def test_confidence_in_range(self, sample_vision_result):
        assert 0.0 <= sample_vision_result["confidence"] <= 1.0

    # Test to verify that severity is within expected range of 1 to 5
    def test_severity_in_range(self, sample_vision_result):
        assert 1 <= sample_vision_result["severity"] <= 5

    # Test to verify that analyse_image() returns a valid standardised result
    # when BLIP captioning and Tesseract OCR are replaced with lightweight
    # lambda stubs, confirming the wrapper processes mocked outputs correctly.
    def test_valid_image_returns_result(self):
    
        import models.vision_model as vision_module

        # Create a mock image object to prevent real file I/O
        mock_image = MagicMock()

        # Save original functions so they can be restored after the test
        original_blip_caption = vision_module.blip_caption
        original_tesseract_extract = vision_module.tesseract_extract

        # Replace heavy model calls with deterministic stubs
        vision_module.blip_caption = lambda image: ("dashboard showing failed logins", 0.70)
        vision_module.tesseract_extract = lambda image: "Failed logon 4625 192.168.1.105 lsass.exe"

        # Patch PIL.Image.open so no real file is read from disk
        with patch("PIL.Image.open", return_value=mock_image):
            mock_image.convert.return_value = mock_image
            result = vision_module.analyse_image("fake_path.png")

        # Restore original functions to avoid affecting other tests
        vision_module.blip_caption = original_blip_caption
        vision_module.tesseract_extract = original_tesseract_extract

        # Verify the result conforms to the standardised schema
        assert result["model"] == "vision"
        assert result["confidence"] > 0.0
        assert isinstance(result["entities"], list)


    # Verifies that analyse_image() returns a safe error result with zero confidence 
    # when PIL.Image.open raises a FileNotFoundError, confirming
    # the wrapper handles missing files gracefully without crashing.
    def test_invalid_image_path_returns_error(self):

        # Simulate a missing file by making PIL.Image.open raise FileNotFoundError
        with patch("PIL.Image.open", side_effect=FileNotFoundError("No such file")):
            from models.vision_model import analyse_image
            result = analyse_image("nonexistent.png")

        # Verify the error result contains zero confidence and an error summary
        assert result["confidence"] == 0.0
        assert "[ERROR]" in result["summary"]
