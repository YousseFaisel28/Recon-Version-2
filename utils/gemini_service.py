"""
Gemini AI Service - Advanced Analysis & Question Handling
=========================================================
This service connects to Google Gemini to provide deep security 
insights when the rule-based assistant reaches its limits.
"""

import os
import google.generativeai as genai
from typing import Optional
from utils.logger import get_logger

logger = get_logger(__name__)

# Configuration
PRIMARY_MODEL = "gemini-2.5-flash"
FALLBACK_MODEL = "gemini-2.5-pro"

class GeminiService:
    def __init__(self):
        # Ensure env is loaded if not already
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except ImportError:
            pass
            
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.primary_model = None
        self.fallback_model = None
        
        if self.api_key:
            try:
                genai.configure(api_key=self.api_key)
                self.primary_model = genai.GenerativeModel(PRIMARY_MODEL)
                self.fallback_model = genai.GenerativeModel(FALLBACK_MODEL)
                print(f"[Gemini Service] Initialized successfully with primary: {PRIMARY_MODEL} and fallback: {FALLBACK_MODEL}")
            except Exception as e:
                print(f"[Gemini Service] Initialization Error: {e}")
        else:
            print("[Gemini Service] WARNING: GEMINI_API_KEY not found in environment.")

    def ask_gemini(self, question: str, context: str) -> str:
        """
        Queries Gemini with a specific question and security context.
        Uses a hybrid approach with fallback for reliability.
        """
        if not self.primary_model:
            return "AI assistant is temporarily unavailable."

        prompt = f"""
You are ReconX AI, an elite cybersecurity assistant integrated into a reconnaissance platform.
You have access to the following security assessment context for a target domain:

--- SECURITY CONTEXT ---
{context}
--- END CONTEXT ---

User Question: {question}

Instructions:
1. Provide a professional, structured, and technically accurate answer.
2. Use the context provided to ground your answer in facts.
3. NEVER output a single massive paragraph. You MUST break your answer into well-structured sections.
4. Format your response heavily with clear bullet points. Ensure EVERY bullet point starts on a NEW LINE.
5. Highlight important terms using bold formatting (e.g., **Vulnerability:**).

Answer:
"""
        
        # Try Primary Model
        try:
            logger.info(f"[Gemini Service] Attempting query with primary model ({PRIMARY_MODEL})...")
            response = self.primary_model.generate_content(prompt)
            if response and response.text:
                return response.text.strip()
        except Exception as e:
            error_msg = str(e).lower()
            logger.info(f"Gemini Service configured with model: {PRIMARY_MODEL}")
            
            # Detect Quota Error
            if "429" in error_msg or "quota" in error_msg:
                logger.warning("[Gemini Service] Quota limit detected on primary model.")
                # We still try the fallback just in case it has its own quota
            
        # Try Fallback Model
        if self.fallback_model:
            try:
                print(f"[Gemini Service] Attempting fallback to {FALLBACK_MODEL}...")
                response = self.fallback_model.generate_content(prompt)
                if response and response.text:
                    print(f"[Gemini Service] Fallback successful.")
                    return response.text.strip()
            except Exception as e:
                error_msg = str(e).lower()
                print(f"[Gemini Service] Fallback model error: {e}")
                
                if "429" in error_msg or "quota" in error_msg:
                    print("[Gemini Service] FINAL: All models quota reached.")
                    return "AI quota reached. Please try again later."

        return "AI assistant is temporarily unavailable."

    def query_gemini(self, question: str, context: str) -> str:
        """Alias for backward compatibility if needed temporarily"""
        return self.ask_gemini(question, context)

# Singleton instance
gemini_service = GeminiService()
