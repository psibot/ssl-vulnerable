#!/usr/bin/env python3
import requests
import time
import sys
from urllib.parse import urljoin

class BreachTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (BREACH-Tester)',
            'Accept-Encoding': 'gzip, deflate'
        })
        
    def test_breach_vulnerability(self):
        """Test if target is vulnerable to BREACH attack"""
        print(f"[*] Testing {self.target_url} for BREACH vulnerability")
        
        # Step 1: Check if compression is enabled
        if not self._check_compression():
            print("[-] Target does not use HTTP compression")
            return False
        
        # Step 2: Check for CSRF tokens in response
        if not self._check_for_secrets():
            print("[-] No apparent secrets in response")
            return False
        
        # Step 3: Test response size variations
        print("[*] Testing response size variations...")
        return self._test_response_variations()
    
    def _check_compression(self):
        """Verify if server responds with compressed content"""
        try:
            r = self.session.get(self.target_url, timeout=10)
            return 'gzip' in r.headers.get('Content-Encoding', '').lower()
        except Exception as e:
            print(f"[!] Compression check failed: {e}")
            return False
    
    def _check_for_secrets(self):
        """Check if response contains potential secrets"""
        try:
            r = self.session.get(self.target_url, timeout=10)
            common_secret_patterns = [
                'csrf', 'token', 'secret', 'nonce', 
                'authenticity_token', 'request_token'
            ]
            return any(pattern in r.text.lower() for pattern in common_secret_patterns)
        except Exception as e:
            print(f"[!] Secret check failed: {e}")
            return False
    
    def _test_response_variations(self, samples=30):
        """Test if response sizes vary with different inputs"""
        base_size = self._get_response_size("")
        variations = 0
        
        test_strings = [
            "", "A"*10, "B"*20, "C"*30, 
            "AAAAA", "BBBBB", "CCCCC",
            "token=", "csrf=", "secret="
        ]
        
        for i in range(samples):
            for test_str in test_strings:
                try:
                    current_size = self._get_response_size(test_str)
                    if current_size != base_size:
                        variations += 1
                        print(f"[+] Response size variation detected: {base_size} -> {current_size} (with payload: {test_str[:10]}...)")
                        if variations >= 3:  # Multiple variations confirm vulnerability
                            return True
                except Exception as e:
                    print(f"[!] Test failed: {e}")
                    continue
                time.sleep(0.5)  # Rate limiting
        
        return variations > 0
    
    def _get_response_size(self, payload):
        """Get compressed response size for a given payload"""
        params = {'breach_test': payload} if payload else {}
        r = self.session.get(self.target_url, params=params, timeout=10)
        return len(r.content)

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        print("Example: python3 breach_test.py https://example.com/login")
        sys.exit(1)
    
    tester = BreachTester(sys.argv[1])
    if tester.test_breach_vulnerability():
        print("[!] VULNERABLE to BREACH attack (CVE-2013-3587)")
        print("Mitigation options:")
        print("1. Disable HTTP compression for sensitive pages")
        print("2. Add random noise to responses (length hiding)")
        print("3. Separate secrets from user input")
    else:
        print("[+] Target appears NOT vulnerable to BREACH")

if __name__ == "__main__":
    main()