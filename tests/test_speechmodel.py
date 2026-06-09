import json
import pytest
from unittest.mock import patch, MagicMock

# Fixture providing a sample speech model result for testing
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

# SPEECH MODEL TESTS CLASS
class TestSpeechModel:

    # Test to verify that the speech model returns a result with standardised output
    def test_returns_standardised_schema(self, sample_speech_result):
        required_keys = {"model", "confidence", "entities", "summary",
                         "attack_classification", "severity", "raw"}
        assert required_keys.issubset(sample_speech_result.keys())

    # Test to verify that model field is correctly set to "speech"
    def test_model_field_is_speech(self, sample_speech_result):
        assert sample_speech_result["model"] == "speech"

    # Test to verify that confidence is within expected range of 0.0 to 1.0
    def test_confidence_in_range(self, sample_speech_result):
        assert 0.0 <= sample_speech_result["confidence"] <= 1.0

    # Test to verify that severity is within expected range of 1 to 5
    def test_severity_in_range(self, sample_speech_result):
        assert 1 <= sample_speech_result["severity"] <= 5

    # Test to verify that non-existent audio path returns a safe error result.
    def test_missing_audio_file_returns_error(self):
        from models.speech_model import analyse_audio
        result = analyse_audio("nonexistent.wav")
        assert result["confidence"] == 0.0
        assert "[ERROR]" in result["summary"]

    # Test to verify if Whisper model returns a transcript, returns a result
    @patch("models.speech_model._whisper_model", new=None)
    def test_valid_transcript_returns_result(self, tmp_path):
        dummy_wav = tmp_path / "test.wav"
        dummy_wav.write_bytes(b"\x00" * 100)

        mock_whisper = MagicMock()
        mock_whisper.transcribe.return_value = {
            "text": "Suspicious PowerShell script executed on DESKTOP-HR4KX92 by administrator.",
            "segments": [{"avg_logprob": -0.3, "no_speech_prob": 0.01}],
        }

        import models.speech_model as speech_module
        speech_module._whisper_model = mock_whisper

        result = speech_module.analyse_audio(str(dummy_wav))
        assert result["model"] == "speech"
        assert result["confidence"] > 0.0
        assert result["attack_classification"] != ""

    # Test to verify that if Whisper model returns empty transcript, returns a safe error result
    @patch("models.speech_model._whisper_model", new=None)
    def test_empty_transcript_returns_error(self, tmp_path):
        dummy_wav = tmp_path / "silent.wav"
        dummy_wav.write_bytes(b"\x00" * 100)

        mock_whisper = MagicMock()
        mock_whisper.transcribe.return_value = {"text": "", "segments": []}

        import models.speech_model as speech_module
        speech_module._whisper_model = mock_whisper

        result = speech_module.analyse_audio(str(dummy_wav))
        assert result["confidence"] == 0.0
        assert "[ERROR]" in result["summary"]