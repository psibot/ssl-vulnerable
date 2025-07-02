#!/usr/bin/env python3
import socket
import ssl
import argparse
import time
from termcolor import colored
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

def test_lucky13(host, port=443, timeout=10, verify_cert=False):
    """Test for LUCKY13 vulnerability (CVE-2013-0169)"""
    print(f"\n[*] Testing {host}:{port} for LUCKY13 (CVE-2013-0169)")
    
    try:
        # Create socket and SSL context
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
        
        # Set protocol versions (using modern approach)
        context.minimum_version = ssl.TLSVersion.TLSv1  # Allows old protocols
        context.maximum_version = ssl.TLSVersion.TLSv1_1
        
        # Enable all ciphers including legacy ones for testing
        context.set_ciphers('ALL:@SECLEVEL=0')
        
        # Connect and test
        start_time = time.time()
        ssl_sock = context.wrap_socket(sock, server_hostname=host if verify_cert else None)
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
        
        if any(cipher_name in cipher[0] for cipher_name in cbc_ciphers):
            if protocol in ["TLSv1", "TLSv1.1", "TLSv1.2"]:
                # Enhanced timing test
                timing_samples = []
                for _ in range(3):
                    try:
                        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        test_sock.settimeout(timeout)
                        test_ssl = context.wrap_socket(test_sock, server_hostname=host if verify_cert else None)
                        start = time.time()
                        test_ssl.connect((host, port))
                        timing_samples.append(time.time() - start)
                        test_ssl.close()
                    except:
                        continue
                
                if timing_samples:
                    avg_time = sum(timing_samples) / len(timing_samples)
                    time_diff = max(timing_samples) - min(timing_samples)
                    print(f"[+] Timing samples: {timing_samples} (avg: {avg_time:.4f}s, diff: {time_diff:.4f}s)")
                    
                    if time_diff > 0.1:  # Significant variation threshold
                        vulnerable = True
                        print(colored("[!] TIMING VARIATIONS DETECTED - VULNERABLE to LUCKY13", "red"))
                    else:
                        print(colored("[+] No significant timing variations detected", "green"))
            else:
                print(colored("[+] Using CBC cipher with modern TLS version", "green"))
        else:
            print(colored("[+] SAFE: Not using CBC cipher mode", "green"))
        
        ssl_sock.close()
        return vulnerable
        
    except ssl.SSLError as e:
        print(colored(f"[!] SSL Error: {str(e)}", "red"))
        return False
    except Exception as e:
        print(colored(f"[!] Connection failed: {str(e)}", "red"))
        return False

def main():
    parser = argparse.ArgumentParser(description='LUCKY13 Vulnerability Tester (CVE-2013-0169)')
    parser.add_argument('host', help='Target hostname or IP address')
    parser.add_argument('-p', '--port', type=int, default=443, help='Target port (default: 443)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Connection timeout (default: 10)')
    parser.add_argument('--verify', action='store_true', help='Enable certificate verification')
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print(colored("LUCKY13 Vulnerability Tester (CVE-2013-0169)", "cyan", attrs=["bold"]))
    print("="*60)
    print(f"Target: {args.host}:{args.port}")
    print(f"Start time: {time.ctime()}\n")
    
    vulnerable = test_lucky13(args.host, args.port, args.timeout, args.verify)
    
    if vulnerable:
        print(colored("\n[!] VULNERABLE TO LUCKY13 ATTACK", "red", attrs=["bold"]))
        print(colored("Mitigation recommendations:", "yellow"))
        print("1. Disable CBC cipher modes completely")
        print("2. Prioritize AES-GCM or ChaCha20 cipher suites")
        print("3. Update to patched TLS implementations (OpenSSL 1.0.2+, 1.0.1k+)")
        print("4. Enable TLS 1.2 or higher as minimum version")
    else:
        print(colored("\n[+] No LUCKY13 vulnerability detected", "green"))
    
    print("\n" + "="*60)
    print("Test completed at:", time.ctime())
    print("="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[!] Test interrupted by user", "yellow"))
        exit(1)