#!/usr/bin/env python3
import socket
import ssl
import argparse
from termcolor import colored
from datetime import datetime
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

def check_sweet32(host, port=443, timeout=5, verify_cert=True):
    """Check for SWEET32 vulnerability (CVE-2016-2183, CVE-2016-6329)"""
    print(f"\n[*] Testing {host}:{port} for SWEET32 vulnerability")
    print(f"[*] Certificate verification: {'Enabled' if verify_cert else 'Disabled'}")
    
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # SSL context configuration
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        
        # Certificate verification settings
        if not verify_cert:
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False
        else:
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            try:
                context.load_default_certs()
            except:
                print(colored("[!] Could not load system CA certificates", "yellow"))
        
        # Protocol and cipher settings
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.set_ciphers('ALL:@SECLEVEL=0')  # Allow all ciphers including weak ones
        
        # Connect with error handling
        try:
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.connect((host, port))
        except ssl.SSLCertVerificationError as e:
            print(colored(f"[!] Certificate verification failed: {e}", "yellow"))
            if verify_cert:
                print(colored("[*] Retrying with certificate verification disabled...", "yellow"))
                return check_sweet32(host, port, timeout, False)
            else:
                raise
        
        # Get connection details
        cipher = ssl_sock.cipher()
        protocol = ssl_sock.version()
        ssl_sock.close()
        
        # Vulnerable cipher suites (64-bit block ciphers)
        vulnerable_ciphers = [
            'DES-CBC3-SHA', 'DES-CBC3-MD5',
            'RC2-CBC-MD5', 'IDEA-CBC-SHA',
            'EDH-RSA-DES-CBC3-SHA', 'EDH-DSS-DES-CBC3-SHA',
            'ECDHE-RSA-DES-CBC3-SHA', 'ECDHE-ECDSA-DES-CBC3-SHA'
        ]
        
        print(f"\n[+] Connection established")
        print(f"    Protocol: {protocol}")
        print(f"    Cipher Suite: {cipher[0]}")
        
        # Check for vulnerability
        if any(cipher_name in cipher[0] for cipher_name in vulnerable_ciphers):
            print(colored("\n[!] VULNERABLE: Using weak 64-bit block cipher (SWEET32)", "red"))
            print(colored("Mitigation:", "yellow"))
            print("1. Disable 3DES, DES, RC2, and IDEA cipher suites")
            print("2. Prioritize AES-GCM (128+ bit block ciphers)")
            print("3. Enable TLS 1.2 as minimum version")
            return True
        else:
            print(colored("\n[+] Secure: Not using vulnerable 64-bit block ciphers", "green"))
            return False
            
    except ssl.SSLError as e:
        print(colored(f"[!] SSL Error: {e}", "red"))
        return False
    except Exception as e:
        print(colored(f"[!] Connection failed: {e}", "red"))
        return False

def main():
    parser = argparse.ArgumentParser(description='SWEET32 Vulnerability Scanner (CVE-2016-2183, CVE-2016-6329)')
    parser.add_argument('host', help='Target hostname or IP')
    parser.add_argument('-p', '--port', type=int, default=443, help='Target port (default: 443)')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Connection timeout (default: 5)')
    parser.add_argument('--no-verify', action='store_true', help='Disable certificate verification')
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print(colored("SWEET32 Vulnerability Scanner", "cyan", attrs=["bold"]))
    print("="*60)
    print(f"Target: {args.host}:{args.port}")
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    
    vulnerable = check_sweet32(args.host, args.port, args.timeout, not args.no_verify)
    
    print("\n" + "="*60)
    print(colored("Scan Summary:", "yellow"))
    print(f"Target: {args.host}:{args.port}")
    print(f"Status: {'VULNERABLE' if vulnerable else 'SECURE'}")
    print(f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[!] Scan interrupted by user", "yellow"))
        exit(1)