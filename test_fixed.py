# test_fixed.py
import asyncio
from urllib.parse import urlparse, urljoin, urlencode
import re
import warnings

# Suppress warnings for cleaner output
warnings.filterwarnings("ignore")

# ==========================================
# IMPORTED CLASSES FOR TESTING
# ==========================================

class FormDetector:
    @staticmethod
    def extract_forms(html, base_url):
        forms = []
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, html, re.DOTALL | re.IGNORECASE)
        
        for action, form_content in form_matches:
            if not action or action.strip() == '':
                action = base_url
            else:
                action = urljoin(base_url, action)
            
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', form_content, re.IGNORECASE)
            
            if inputs:
                test_params = {}
                for field in inputs[:3]:
                    test_params[field] = f"TEST_{field}"
                
                query_string = urlencode(test_params, doseq=True)
                test_url = f"{action}?{query_string}"
                forms.append(test_url)
        
        return forms

class URLExpander:
    @staticmethod
    def expand_with_common_params(url):
        expanded_urls = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        common_params = {
            'login': ['username', 'password', 'email'],
            'search': ['q', 'query', 'search'],
            'product': ['id', 'product', 'category'],
            'user': ['id', 'user', 'name'],
        }
        
        url_lower = url.lower()
        url_type = 'general'
        
        for param_type in common_params:
            if param_type in url_lower:
                url_type = param_type
                break
        
        for param in common_params.get(url_type, ['id', 'page', 'view'])[:3]:
            test_url = f"{base_url}?{param}=1"
            expanded_urls.append(test_url)
        
        return expanded_urls

# ==========================================
# TEST RUNNER
# ==========================================

async def test():
    print("=" * 60)
    print("🧪 TESTING NEW DETECTION CAPABILITIES")
    print("=" * 60)
    
    # HTML example with a form
    html_example = '''
    <html>
        <body>
            <h1>Test Page</h1>
            
            <!-- Login Form -->
            <form action="/login.php" method="POST">
                <input type="text" name="username">
                <input type="password" name="password">
                <input type="hidden" name="csrf_token" value="12345">
                <input type="submit" value="Login">
            </form>
            
            <!-- Search Form -->
            <form action="/search">
                <input type="text" name="q" placeholder="Search...">
                <input type="submit" value="Search">
            </form>
        </body>
    </html>
    '''
    
    print("\n[TEST 1] Form Detection")
    print("-" * 30)
    form_detector = FormDetector()
    forms = form_detector.extract_forms(html_example, "https://example.com")
    
    if forms:
        print(f"✅ PASSED: Detected {len(forms)} forms")
        for form in forms:
            print(f"   • {form}")
    else:
        print("❌ FAILED: No forms detected")
    
    
    print("\n[TEST 2] URL Expansion")
    print("-" * 30)
    expander = URLExpander()
    
    test_urls = [
        "https://example.com/login",
        "https://example.com/search",
        "https://example.com/products",
        "https://example.com/about-us"  # Should use general params
    ]
    
    passed_expansion = True
    for url in test_urls:
        print(f"\nTarget: {url}")
        expanded = expander.expand_with_common_params(url)
        if expanded:
            for exp_url in expanded:
                print(f"   → {exp_url}")
        else:
            print("   ⚠️ No expansion generated")
            passed_expansion = False
            
    if passed_expansion:
        print("\n✅ PASSED: URL expansion working correctly")
    
    print("\n" + "=" * 60)
    print("Ready to integrate into Titanium Scanner!")

if __name__ == "__main__":
    asyncio.run(test())
