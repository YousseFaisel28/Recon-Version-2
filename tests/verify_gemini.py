import os
import sys
from dotenv import load_dotenv

# Ensure project root is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.gemini_service import gemini_service

def test_gemini():
    print("="*60)
    print("GEMINI QUOTA & FALLBACK VERIFICATION")
    print("="*60)
    
    # 1. Check Env
    load_dotenv()
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[X] ERROR: GEMINI_API_KEY not found in .env")
        return
    else:
        print(f"[OK] GEMINI_API_KEY found.")

    # 2. Test Query
    test_question = "Explain why SSL validation is important for a security scanner."
    test_context = "REPORT SUMMARY: The scanner detected several hosts with exposed ports but no valid SSL certificates on some subdomains."
    
    print(f"\n[*] Testing ask_gemini() with fallback logic...")
    
    response = gemini_service.ask_gemini(test_question, test_context)
    
    print(f"\n[AI Response]:\n{response}")
    
    if "quota reached" in response.lower():
        print("\n[!] QUOTA DETECTED: Service correctly identified and handled the 429 error.")
        print("[OK] Verification passed (successful error handling).")
    elif "unavailable" in response.lower() or not response:
        print("\n[X] VERIFICATION FAILED: General failure without specific quota message.")
    else:
        print("\n[OK] VERIFICATION SUCCESSFUL: Gemini returned a valid response!")
    print("="*60)

if __name__ == "__main__":
    test_gemini()
