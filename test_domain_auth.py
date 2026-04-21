import sys
import os

# Add parent path to simulate running from root
sys.path.insert(0, os.path.abspath('.'))

from utils.token_manager import generate_token, get_token_info, clear_token
from utils.verification import verify_domain_token

def test_token_manager():
    print("Testing token manager...")
    domain = "https://example.com"
    token = generate_token(domain)
    assert len(token) >= 32, "Token too short"
    info = get_token_info(domain)
    assert info["token"] == token, "Token mismatch in store"
    print("Token Manager OK.")

def test_verification_network_failure():
    print("Testing verification failure mode...")
    # Using an invalid domain should yield CONNECTION_ERROR
    domain = "https://this-is-a-fake-domain-123456789.com"
    token = "abcdef123456"
    res = verify_domain_token(domain, token)
    print("Result:", res)
    assert res in ("CONNECTION_ERROR", "FILE_NOT_FOUND"), "Should fail via network"

if __name__ == "__main__":
    test_token_manager()
    test_verification_network_failure()
    print("All backend domain-auth modules loaded and functioning accurately!")
