import json
import pytest
from unittest.mock import patch, MagicMock

@pytest.fixture
# Fixture providing a sample text model result for testing
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
# Fixture providing a sample vision  model result for testing
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
# Fixture providing a sample speech model result for testing
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
# Fixture providing a result in the case of an error for testing
def error_result():
    return {
        "model": "text",
        "confidence": 0.0,
        "entities": [],
        "summary": "[ERROR] Service unreachable",
        "attack_classification": "Unknown",
        "severity": 1,
        "raw": "",
    }

# LATE FUSION ORCHESTRATOR TESTS CLASS
class TestFusionOrchestrator:

    # Test to verify that all three model returns results
    def test_all_three_modalities_returns_result(self,
                                                 sample_text_result, 
                                                 sample_vision_result,
                                                 sample_speech_result):
        
        from orchestrator.fusion import late_fusion_orchestrator
        result = late_fusion_orchestrator(text_result=sample_text_result,
                                          vision_result=sample_vision_result,
                                          speech_result=sample_speech_result)
        assert "severity" in result
        assert "attack_classification" in result
        assert "recommended_actions" in result
        assert "confidence" in result
        assert "modality_breakdown" in result
        assert "fusion_weights" in result

    # Test to verify that severity is within expected range of 1 to 5
    def test_severity_in_range(self,
                               sample_text_result,
                               sample_vision_result,
                               sample_speech_result):
        
        from orchestrator.fusion import late_fusion_orchestrator
        result = late_fusion_orchestrator(text_result=sample_text_result,
                                          vision_result=sample_vision_result,
                                          speech_result=sample_speech_result)
        assert 1 <= result["severity"] <= 5

    # Test to verify that the sum of fusion weights equals to 1
    def test_fusion_weights_sum_to_one(self, 
                                       sample_text_result,
                                       sample_vision_result,
                                       sample_speech_result):
        
        from orchestrator.fusion import late_fusion_orchestrator
        result = late_fusion_orchestrator(text_result=sample_text_result,
                                          vision_result=sample_vision_result,
                                          speech_result=sample_speech_result)
        total = sum(result["fusion_weights"].values())
        assert abs(total - 1.0) < 0.01

    # Test to verify that if all modalities have zero confidence, 
    # it should return an error triage
    def test_all_error_results_returns_error_triage(self, error_result):
        
        from orchestrator.fusion import late_fusion_orchestrator
        vision_error = {**error_result, "model": "vision"}
        speech_error = {**error_result, "model": "speech"}
        result = late_fusion_orchestrator(text_result=error_result,
                                          vision_result=vision_error,
                                          speech_result=speech_error)
        assert result["confidence"] == 0.0
        assert "error" in result

    # Test to verify that calling with no inputs must return an error triage.
    def test_no_inputs_returns_error_triage(self):
        
        from orchestrator.fusion import late_fusion_orchestrator
        result = late_fusion_orchestrator()
        assert "error" in result
        assert result["severity"] == 1

    # Test to verify that when all three models agree on a ATT&CK tactic, the results should match
    def test_consistent_tactic_across_modalities(self, 
                                                 sample_text_result, 
                                                 sample_vision_result,
                                                 sample_speech_result):
        
        from orchestrator.fusion import late_fusion_orchestrator
        result = late_fusion_orchestrator(text_result=sample_text_result,
                                          vision_result=sample_vision_result,
                                          speech_result=sample_speech_result)
        assert result["attack_classification"] == "Credential Access"
    
    
    
    
    
    
    
    # def test_text_only_input_redistributes_weights(self, sample_text_result):
    #     """With only text input, text weight should equal 1.0."""
    #     from orchestrator.fusion import late_fusion_orchestrator
    #     result = late_fusion_orchestrator(text_result=sample_text_result)
    #     assert result["fusion_weights"].get("text", 0) == 1.0
    #     assert result["modality_breakdown"]["vision"] is None
    #     assert result["modality_breakdown"]["speech"] is None

    # def test_text_and_vision_redistributes_weights(
    #     self, sample_text_result, sample_vision_result
    # ):
    #     """With text and vision, weights must sum to 1.0 and speech absent."""
    #     from orchestrator.fusion import late_fusion_orchestrator
    #     result = late_fusion_orchestrator(
    #         text_result=sample_text_result,
    #         vision_result=sample_vision_result,
    #     )
    #     total = sum(result["fusion_weights"].values())
    #     assert abs(total - 1.0) < 0.01
    #     assert "speech" not in result["fusion_weights"]

    # def test_entities_are_deduplicated(
    #     self, sample_text_result, sample_vision_result
    # ):
    #     """Entities appearing in multiple modalities must not be duplicated."""
    #     from orchestrator.fusion import late_fusion_orchestrator
    #     result = late_fusion_orchestrator(
    #         text_result=sample_text_result,
    #         vision_result=sample_vision_result,
    #     )
    #     assert len(result["entities"]) == len(set(result["entities"]))
    
    # def test_recommended_actions_is_non_empty_list(self, sample_text_result):
        
    #     from orchestrator.fusion import late_fusion_orchestrator
    #     result = late_fusion_orchestrator(text_result=sample_text_result)
    #     assert isinstance(result["recommended_actions"], list)
    #     assert len(result["recommended_actions"]) > 0