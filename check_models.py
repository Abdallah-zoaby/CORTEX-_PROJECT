import sys
import google.generativeai as genai

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# مفتاحك الشخصي
API_KEY = "AIzaSyBOmJyejA9vuQ5ysx06tteD5ubKv6V-Yrw"
genai.configure(api_key=API_KEY)

print("🔍 Searching for available AI models...")
try:
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            print(f"✅ Found: {m.name}")
except Exception as e:
    print(f"❌ Error: {e}")