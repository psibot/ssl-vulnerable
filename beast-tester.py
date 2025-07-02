#!/usr/bin/env python3
import socket
import ssl
import argparse
import time
from termcolor import colored
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

def test_beast_vulnerability(host, port=443, timeout=10, verify_cert=False):
    """Test for BEAST vulnerability (CVE-2011-3389)"""
    print(f"\n[*] Testing {host}:{port} for BEAST (CVE-2011-3389)")
    
    try:
        # Create socket with modern SSL context
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Updated SSL context configuration
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        
        # Configure certificate verification
        if verify_cert:
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            try:
                context.load_default_certs()
            except:
                print(colored("[!] Could not load system CA certificates", "yellow"))
        else:
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False
        
        # Set protocol versions for testing (updated to avoid deprecation)
        context.minimum_version = ssl.TLSVersion.TLSv1  # Allows old protocols
        context.maximum_version = ssl.TLSVersion.TLSv1_1 # BEAST affects up to TLS 1.1
        
        # Enable all ciphers including legacy ones for testing
        context.set_ciphers('ALL:@SECLEVEL=0')
        
        # Connect with SSL
        ssl_sock = context.wrap_socket(sock, server_hostname=host if verify_cert else None)
        start_time = time.time()
        ssl_sock.connect((host, port))
        elapsed = time.time() - start_time
        
        # Get connection details
        cipher = ssl_sock.cipher()
        protocol = ssl_sock.version()
        
        print(f"[+] Connected using: {protocol}")
        print(f"[+] Cipher suite: {cipher[0]}")
        print(f"[+] Handshake time: {elapsed:.4f} seconds")
        
        # Check for vulnerable conditions
        vulnerable = False
        cbc_ciphers = [
            'AES128-SHA', 'AES256-SHA', 'DES-CBC3-SHA',
            'CAMELLIA128-SHA', 'CAMELLIA256-SHA',
            'ECDHE-RSA-AES128-SHA', 'ECDHE-RSA-AES256-SHA'
        ]
        
        if "SSL" in protocol:
            vulnerable = True
            print(colored("[!] VULNERABLE: Using SSL protocol", "red"))
        elif any(cipher_name in cipher[0] for cipher_name in cbc_ciphers):
            if protocol in ["TLSv1", "TLSv1.1"]:
                vulnerable = True
                print(colored("[!] VULNERABLE: Using TLS 1.0/1.1 with CBC cipher", "red"))
            else:
                print(colored("[+] Using CBC cipher but with newer TLS version", "yellow"))
        else:
            print(colored("[+] SAFE: Not using vulnerable protocol/cipher combination", "green"))
        
        ssl_sock.close()
        return vulnerable
        
    except ssl.SSLError as e:
        print(colored(f"[!] SSL Error: {str(e)}", "red"))
        return False
    except Exception as e:
        print(colored(f"[!] Connection failed: {str(e)}", "red"))
        return False

def main():
    parser = argparse.ArgumentParser(description='BEAST Vulnerability Tester (CVE-2011-3389)')
    parser.add_argument('host', help='Target hostname or IP address')
    parser.add_argument('-p', '--port', type=int, default=443, help='Target port (default: 443)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Connection timeout (default: 10)')
    parser.add_argument('--verify', action='store_true', help='Enable certificate verification')
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print(colored("BEAST Vulnerability Tester (CVE-2011-3389)", "cyan", attrs=["bold"]))
    print("="*60)
    print(f"Target: {args.host}:{args.port}")
    print(f"Start time: {time.ctime()}\n")
    
    vulnerable = test_beast_vulnerability(args.host, args.port, args.timeout, args.verify)
    
    if vulnerable:
        print(colored("\n[!] VULNERABLE TO BEAST ATTACK", "red", attrs=["bold"]))
        print(colored("Mitigation recommendations:", "yellow"))
        print("1. Disable SSLv3 and TLS 1.0 completely")
        print("2. Prioritize AES-GCM or ChaCha20 cipher suites")
        print("3. Enable TLS 1.2 as minimum version")
        print("4. Implement TLS_FALLBACK_SCSV to prevent downgrade attacks")
    else:
        print(colored("\n[+] No BEAST vulnerability detected", "green"))
    
    print("\n" + "="*60)
    print("Test completed at:", time.ctime())
    print("="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[!] Test interrupted by user", "yellow"))
        exit(1)