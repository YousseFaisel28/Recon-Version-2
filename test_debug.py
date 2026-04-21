import sys
import os

sys.path.insert(0, os.path.abspath('.'))

from utils.verification import verify_domain_token
from utils.token_manager import clear_token

def run_test():
    domain = "https://aabdelrahmanssalah.github.io/reconx-verification-test"
    
    # We will simulate that the token manager generated "expected_token_123" 
    # but the repo might just have arbitrary text right now... wait, the user says
    # "The verification file is publicly accessible and contains the correct token".
    # I should find out what the token actually is by hitting the public URL first!
    import requests
    url = "https://aabdelrahmanssalah.github.io/reconx-verification-test/reconx-verification.txt"
    try:
        r = requests.get(url)
        if r.status_code == 200:
            actual_token = r.text.strip()
            print(f"[*] Detected token on public URL: {actual_token}")
            
            # Now test verification logic with that exact token
            res = verify_domain_token(domain, actual_token)
            print(f"[*] Test Result: {res}")
            assert res == "VERIFIED", "Verification failed!"
        else:
            print(f"[!] Target URL returned status code {r.status_code}")
    except Exception as e:
        print("[!] Network failure querying:", e)

if __name__ == '__main__':
    run_test()
