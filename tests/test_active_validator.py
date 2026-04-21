import pytest
from unittest.mock import patch, Mock
import json
from models.active_validator import check_waf_presence, run_nuclei_validation, validate_cve

class TestActiveValidator:
    
    @patch('models.active_validator.requests.get')
    def test_waf_presence_blocked_403(self, mock_get):
        # Mock a 403 Forbidden response
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"
        mock_get.return_value = mock_response
        
        result = check_waf_presence("http://example.com")
        
        assert result["is_blocked"] is True
        assert result["status_code"] == 403
        assert mock_get.called
        
    @patch('models.active_validator.requests.get')
    def test_waf_presence_blocked_captcha(self, mock_get):
        # Mock a 200 response but with a Cloudflare CAPTCHA signature
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Please complete the security check. cloudflare</body></html>"
        mock_get.return_value = mock_response
        
        result = check_waf_presence("http://example.com")
        
        assert result["is_blocked"] is True
        assert result["status_code"] == 200
        assert "Signature" in result["reason"]

    @patch('models.active_validator.requests.get')
    def test_waf_presence_allowed_200(self, mock_get):
        # Mock a normal 200 response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Welcome to the vulnerable site</body></html>"
        mock_get.return_value = mock_response
        
        result = check_waf_presence("http://example.com")
        
        assert result["is_blocked"] is False
        assert result["status_code"] == 200

    @patch('models.active_validator.subprocess.run')
    def test_run_nuclei_exploitable(self, mock_run):
        # Mock Nuclei finding a vulnerability
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({"info": {"classification": {"cve-id": ["CVE-2021-44228"]}}})
        mock_run.return_value = mock_result
        
        is_exploitable = run_nuclei_validation("CVE-2021-44228", "http://example.com")
        
        assert is_exploitable is True
        
    @patch('models.active_validator.subprocess.run')
    def test_run_nuclei_patched(self, mock_run):
        # Mock Nuclei not finding anything (empty stdout)
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_run.return_value = mock_result
        
        is_exploitable = run_nuclei_validation("CVE-2021-44228", "http://example.com")
        
        assert is_exploitable is False

    @patch('models.active_validator.check_waf_presence')
    @patch('models.active_validator.run_nuclei_validation')
    def test_validate_cve_blocked_by_waf(self, mock_nuclei, mock_waf):
        # If WAF blocks it, Nuclei shouldn't even be called
        mock_waf.return_value = {"is_blocked": True, "status_code": 403, "reason": "HTTP 403"}
        
        result = validate_cve("CVE-2021-44228", "http://example.com")
        
        assert result["cve_id"] == "CVE-2021-44228"
        assert result["validation_status"] == "Blocked by WAF"
        assert result["http_response_code"] == 403
        mock_nuclei.assert_not_called()

    @patch('models.active_validator.check_waf_presence')
    @patch('models.active_validator.run_nuclei_validation')
    def test_validate_cve_exploitable(self, mock_nuclei, mock_waf):
        mock_waf.return_value = {"is_blocked": False, "status_code": 200, "reason": "OK"}
        mock_nuclei.return_value = True
        
        result = validate_cve("CVE-2021-44228", "http://example.com")
        
        assert result["validation_status"] == "Exploitable"
        assert result["http_response_code"] == 200
        mock_nuclei.assert_called_once()
        
    @patch('models.active_validator.check_waf_presence')
    @patch('models.active_validator.run_nuclei_validation')
    def test_validate_cve_patched(self, mock_nuclei, mock_waf):
        mock_waf.return_value = {"is_blocked": False, "status_code": 200, "reason": "OK"}
        mock_nuclei.return_value = False
        
        result = validate_cve("CVE-2021-44228", "http://example.com")
        
        assert result["validation_status"] == "Patched"
        assert result["http_response_code"] == 200
        mock_nuclei.assert_called_once()
