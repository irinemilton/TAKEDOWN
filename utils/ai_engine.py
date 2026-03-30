import os
import google.generativeai as genai
from config import Config

# Initialize API Key
genai.configure(api_key=Config.GEMINI_API_KEY)

# Use the recommended model for general text tasks
try:
    model = genai.GenerativeModel('gemini-1.5-flash')
except Exception:
    # Fallback to gemini-pro if flash is unavailable in the installed package version
    model = genai.GenerativeModel('gemini-pro')

def generate_ai_suggestions(vuln_type, endpoint, payload, description):
    """
    Calls the Google Gemini API to generate dynamic explanations and fixes for vulnerabilities.
    Returns: (ai_explanation, fix_suggestion)
    """
    prompt = f"""
    You are an expert cybersecurity analyst helping a developer understand a security vulnerability.
    
    A vulnerability was detected during an automated scan.
    
    Details:
    - Vulnerability Type: {vuln_type}
    - Endpoint Affected: {endpoint}
    - Payload/Test Used: {payload}
    - Technical Description: {description}
    
    Please provide your response in exactly two sections separated by "---FIX_SUGGESTION---". Do not use markdown headers for the sections, just raw text.
    
    First Section (AI Explanation): Write a simple, non-technical explanation (3-4 sentences) explaining to a non-technical client what this vulnerability is and why it's dangerous, specifically referencing the payload or context if helpful.
    
    ---FIX_SUGGESTION---
    
    Second Section (Fix Suggestion): Provide a 1-2 sentence technical instruction for a developer on exactly how they should mitigate or patch this vulnerability. Keep it concise.
    """
    
    try:
        response = model.generate_content(prompt)
        text = response.text
        
        parts = text.split('---FIX_SUGGESTION---')
        if len(parts) == 2:
            ai_explanation = parts[0].strip()
            fix_suggestion = parts[1].strip()
            return ai_explanation, fix_suggestion
        else:
            return (
                "An error occurred while parsing the AI explanation.",
                "Please consult standard documentation for fixing this vulnerability."
            )
    except Exception as e:
        print(f"Gemini API Error: {e}")
        return (
            "The AI engine is currently unavailable to explain this vulnerability.",
            "Please review secure coding guidelines."
        )
