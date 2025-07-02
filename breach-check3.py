#!/usr/bin/env python3
import requests
import time
import sys
import zlib
from urllib.parse import urljoin, urlparse
from termcolor import colored
import argparse

class BreachTester:
    def __init__(self, target_url, verify_ssl=False):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (BREACH-Tester)',
            'Accept-Encoding': 'gzip, deflate, br'
        })
        self.base_response_size = 0
        self.base_compressed_size = 0
        
    def test_breach_vulnerability(self):
        """Test if target is vulnerable to BREACH attack"""
        print(f"\n[*] Testing {self.target_url} for BREACH vulnerability (CVE-2013-3587)")
        
        # Step 1: Check if compression is enabled
        if not self._check_compression():
            print(colored("[-] Target does not use HTTP compression", "yellow"))
            return False
        
        # Step 2: Check for secrets in response
        if not self._check_for_secrets():
            print(colored("[-] No apparent secrets in response", "yellow"))
            return False
        
        # Step 3: Test response size variations
        print("[*] Testing response size variations...")
        return self._test_response_variations()
    
    def _check_compression(self):
        """Verify if server responds with compressed content"""
        try:
            r = self.session.get(self.target_url, timeout=10)
            self.base_response_size = len(r.content)
            self.base_compressed_size = len(zlib.compress(r.content))
            
            # Check both headers and actual compression
            using_compression = any(
                enc in r.headers.get('Content-Encoding', '').lower()
                for enc in ['gzip', 'deflate', 'br']
            )
            
            # Verify if actual compression is happening
            actual_compression = len(r.content) > len(zlib.compress(r.content))
            
            if not (using_compression or actual_compression):
                print(colored("[!] No compression detected in headers or content", "yellow"))
                return False
                
            print(f"[+] Compression detected: {r.headers.get('Content-Encoding', 'unknown')}")
            print(f"[+] Response size: {len(r.content)} bytes")
            print(f"[+] Compressed size: {len(zlib.compress(r.content))} bytes")
            return True
            
        except Exception as e:
            print(colored(f"[!] Compression check failed: {e}", "red"))
            return False
    
    def _check_for_secrets(self):
        """Check if response contains potential secrets"""
        try:
            r = self.session.get(self.target_url, timeout=10)
            common_secret_patterns = [
                'csrf', 'token', 'secret', 'nonce', 
                'authenticity_token', 'request_token',
                'session', 'auth', 'password'
            ]
            
            found_secrets = [p for p in common_secret_patterns if p in r.text.lower()]
            
            if not found_secrets:
                print(colored("[!] No common secret patterns found in response", "yellow"))
                return False
                
            print(colored(f"[+] Found potential secrets: {', '.join(found_secrets)}", "green"))
            return True
            
        except Exception as e:
            print(colored(f"[!] Secret check failed: {e}", "red"))
            return False
    
    def _test_response_variations(self, samples=30, threshold=0.05):
        """Test if response sizes vary with different inputs"""
        base_size = self._get_response_size("")
        variations = 0
        
        test_strings = [
            "", "A"*10, "B"*20, "C"*30, 
            "AAAAA", "BBBBB", "CCCCC",
            "token=", "csrf=", "secret=",
            "session=", "auth=", "password="
        ]
        
        print(f"\n{'='*60}\n[+] Testing with base response size: {base_size} bytes")
        print(f"[+] Variation threshold set to: {threshold*100:.1f}%\n{'='*60}")
        
        for i in range(samples):
            for test_str in test_strings:
                try:
                    current_size = self._get_response_size(test_str)
                    size_diff = abs(current_size - base_size)
                    variation = size_diff / base_size if base_size > 0 else 0
                    
                    if variation > threshold:
                        variations += 1
                        print(colored(
                            f"[+] Significant variation detected ({variation*100:.1f}%): "
                            f"{base_size} → {current_size} bytes (payload: {test_str[:30]}{'...' if len(test_str) > 30 else ''})", 
                            "red"))
                        if variations >= 3:  # Multiple variations confirm vulnerability
                            return True
                            
                except Exception as e:
                    print(colored(f"[!] Test failed: {e}", "yellow"))
                    continue
                
                time.sleep(0.5)  # Rate limiting
        
        return variations > 0
    
    def _get_response_size(self, payload):
        """Get compressed response size for a given payload"""
        params = {'breach_test': payload} if payload else {}
        r = self.session.get(self.target_url, params=params, timeout=10)
        return len(zlib.compress(r.content))

def main():
    parser = argparse.ArgumentParser(description='BREACH Vulnerability Tester (CVE-2013-3587) Extended 2')
    parser.add_argument('url', help='Target URL to test')
    parser.add_argument('--verify', action='store_true', help='Enable SSL certificate verification')
    parser.add_argument('--samples', type=int, default=30, help='Number of test samples (default: 30)')
    parser.add_argument('--threshold', type=float, default=0.05, 
                       help='Size variation threshold (default: 0.05 = 5%)')
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print(colored("BREACH Vulnerability Tester (CVE-2013-3587)", "cyan", attrs=["bold"]))
    print("="*60)
    print(f"Target URL: {args.url}")
    print(f"Start time: {time.ctime()}")
    print(f"SSL Verification: {'Enabled' if args.verify else 'Disabled'}")
    print("="*60 + "\n")
    
    tester = BreachTester(args.url, verify_ssl=args.verify)
    if tester.test_breach_vulnerability():
        print(colored("\n[!] VULNERABLE to BREACH attack (CVE-2013-3587)", "red", attrs=["bold"]))
        print(colored("Mitigation options:", "yellow"))
        print("1. Disable HTTP compression for sensitive pages")
        print("2. Add random noise to responses (length hiding)")
        print("3. Separate secrets from user input")
        print("4. Implement CSRF tokens that change with each request")
        print("5. Use TLS-level compression instead of HTTP-level")
    else:
        print(colored("\n[+] Target appears NOT vulnerable to BREACH", "green"))
    
    print("\n" + "="*60)
    print("Test completed at:", time.ctime())
    print("="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[!] Test interrupted by user", "yellow"))
        sys.exit(1)