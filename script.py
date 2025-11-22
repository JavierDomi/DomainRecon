#!/usr/bin/env python3

import sys
import whois # type: ignore
import socket
import dns.resolver
import json
import time
import requests
import os
from datetime import datetime
from dotenv import load_dotenv # type: ignore

# Load environment variables from .env file
load_dotenv()

# ============================================================================
# CONFIGURATION
# ============================================================================
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389]  # Top 10 most common ports
TIMEOUT = 2  # Connection timeout in seconds

# Intelligence X Configuration
INTELX_API_KEY = os.getenv("INTELX_API_KEY")
INTELX_BASE_URL = "https://free.intelx.io"  # Free tier endpoint for registered users

# ============================================================================
# AUXILIARY FUNCTIONS
# ============================================================================

def print_banner():
    """Display script banner"""
    print("=" * 70)
    print(" " * 20 + "DOMAIN RECONNAISSANCE TOOL")
    print("=" * 70)
    print()

def print_section(title):
    """Print section separator"""
    print("\n" + "─" * 70)
    print(f"► {title}")
    print("─" * 70)

def clean_domain(url):
    """Clean domain by removing protocol and www"""
    url = url.replace('http://', '').replace('https://', '')
    url = url.replace('www.', '')
    url = url.split('/')[0]
    return url

# ============================================================================
# 1. WHOIS
# ============================================================================

def get_whois(domain):
    """Obtain domain WHOIS information"""
    print_section("1. WHOIS INFORMATION")
    
    try:
        clean_url = clean_domain(domain)
        whois_info = whois.whois(clean_url, timeout=15)
        
        print(f" WHOIS obtained successfully for: {clean_url}\n")
        
        # Extract relevant information
        info = {
            'domain_name': whois_info.domain_name,
            'registrar': whois_info.registrar,
            'creation_date': whois_info.creation_date,
            'expiration_date': whois_info.expiration_date,
            'name_servers': whois_info.name_servers,
            'emails': whois_info.emails,
            'country': whois_info.country,
            'state': whois_info.state,
            'city': whois_info.city
        }
        
        # Display formatted information
        for key, value in info.items():
            if value:
                print(f"  {key.replace('_', ' ').title()}: {value}")
        
        return whois_info
        
    except Exception as e:
        print(f"[ERROR] Error obtaining WHOIS: {e}")
        return None

# ============================================================================
# 2. INTELLIGENCE X API INTEGRATION
# ============================================================================

class IntelligenceXAPI:
    """Intelligence X API wrapper for breach checking"""
    
    def __init__(self, api_key, base_url=INTELX_BASE_URL):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            'x-key': api_key,
            'Content-Type': 'application/json'
        }
    
    def search(self, term, maxresults=100, timeout=5):
        """
        Initiate a search using Intelligence X API
        Returns search_id for retrieving results
        """
        endpoint = f"{self.base_url}/intelligent/search"
        
        payload = {
            "term": term,
            "maxresults": maxresults,
            "media": 0,  # 0 = all media types
            "sort": 4,  # Sort by date
            "timeout": timeout
        }
        
        try:
            response = requests.post(
                endpoint,
                headers=self.headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('id'), data.get('status')
            else:
                print(f"  [ERROR] Search request failed: {response.status_code}")
                return None, None
                
        except requests.exceptions.RequestException as e:
            print(f"  [ERROR] Connection error: {e}")
            return None, None
    
    def get_results(self, search_id, limit=100):
        """
        Retrieve search results using search_id
        """
        endpoint = f"{self.base_url}/intelligent/search/result"
        
        params = {
            'id': search_id,
            'limit': limit
        }
        
        try:
            response = requests.get(
                endpoint,
                headers=self.headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('records', []), data.get('status')
            else:
                print(f"  [ERROR] Results request failed: {response.status_code}")
                return [], None
                
        except requests.exceptions.RequestException as e:
            print(f"  [ERROR] Connection error: {e}")
            return [], None
    
    def check_email_breaches(self, email, debug=False):
        """
        Check if email appears in any data breaches
        """
        if debug:
            print(f"  [DEBUG] Searching for: {email}")
        
        # Step 1: Initiate search
        search_id, status = self.search(email, maxresults=50, timeout=5)
        
        if not search_id:
            return None, "SEARCH_FAILED"
        
        if debug:
            print(f"  [DEBUG] Search ID: {search_id}, Status: {status}")
        
        # Step 2: Wait for results to be ready (Intelligence X recommendation)
        time.sleep(1)
        
        # Step 3: Retrieve results
        records, result_status = self.get_results(search_id)
        
        if debug:
            print(f"  [DEBUG] Found {len(records)} records")
        
        if records and len(records) > 0:
            return True, records
        else:
            return False, []

def check_email_breaches_intelx(email, api_key=INTELX_API_KEY, debug=False):
    """
    Wrapper function to check email breaches using Intelligence X
    """
    if not api_key or api_key == "YOUR_API_KEY_HERE":
        return None, "NO_API_KEY"
    
    try:
        intelx = IntelligenceXAPI(api_key)
        found, result = intelx.check_email_breaches(email, debug=debug)
        return found, result
    except Exception as e:
        print(f"  [ERROR] Intelligence X error: {e}")
        return None, str(e)

# ============================================================================
# 3. VERIFY IF DOMAIN IS ALIVE
# ============================================================================

def is_domain_alive(domain):
    """Verify if domain is alive via DNS resolution"""
    print_section("3. AVAILABILITY VERIFICATION")
    
    clean_url = clean_domain(domain)
    
    try:
        # Try to resolve domain to IP
        ip_address = socket.gethostbyname(clean_url)
        print(f"[SUCCESS] Domain is ALIVE")
        print(f"  Resolved IP: {ip_address}")
        return True, ip_address
    except socket.gaierror:
        print(f"[ERROR] Domain is NOT accessible (DNS resolution failed)")
        return False, None
    except Exception as e:
        print(f"[ERROR] Error verifying domain: {e}")
        return False, None

# ============================================================================
# 4. PORT SCANNING
# ============================================================================

def scan_port(ip, port, timeout=TIMEOUT):
    """Scan a specific port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def scan_top_ports(ip, ports=TOP_PORTS):
    """Scan most common ports"""
    print_section("4. PORT SCANNING (TOP 10)")
    
    if not ip:
        print("  [ERROR] Cannot scan: IP not available")
        return []
    
    print(f"  Scanning {len(ports)} ports on {ip}...")
    print(f"  Ports to scan: {ports}\n")
    
    open_ports = []
    
    # Port to service mapping
    services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3389: "RDP"
    }
    
    for port in ports:
        is_open = scan_port(ip, port)
        status = "OPEN" if is_open else "CLOSED"
        service = services.get(port, "Unknown")
        
        if is_open:
            print(f"  [OPEN] Port {port:5} [{service:12}] - {status}")
            open_ports.append({'port': port, 'service': service})
        else:
            print(f"  [CLOSED] Port {port:5} [{service:12}] - {status}")
    
    print(f"\n  Result: {len(open_ports)} open port(s) out of {len(ports)} scanned")
    return open_ports

# ============================================================================
# 5. DNS INFORMATION (NS and MX)
# ============================================================================

def get_dns_records(domain):
    """Obtain DNS records (NS and MX)"""
    print_section("5. DNS RECORDS")
    
    clean_url = clean_domain(domain)
    dns_info = {}
    
    # Get Name Servers (NS)
    try:
        ns_records = dns.resolver.resolve(clean_url, 'NS')
        dns_info['NS'] = [str(rdata) for rdata in ns_records]
        print("  Name Servers (NS):")
        for ns in dns_info['NS']:
            print(f"    - {ns}")
    except Exception as e:
        print(f"  [ERROR] Could not obtain NS records: {e}")
        dns_info['NS'] = []
    
    # Get Mail Servers (MX)
    try:
        mx_records = dns.resolver.resolve(clean_url, 'MX')
        dns_info['MX'] = []
        print("\n  Mail Servers (MX):")
        for rdata in mx_records:
            mx_info = f"{rdata.preference} {rdata.exchange}"
            dns_info['MX'].append(mx_info)
            print(f"    - Priority {rdata.preference}: {rdata.exchange}")
    except Exception as e:
        print(f"\n  [ERROR] Could not obtain MX records: {e}")
        dns_info['MX'] = []
    
    # Get A records (additional)
    try:
        a_records = dns.resolver.resolve(clean_url, 'A')
        dns_info['A'] = [str(rdata) for rdata in a_records]
        print("\n  A Records (IPv4):")
        for a in dns_info['A']:
            print(f"    - {a}")
    except Exception as e:
        print(f"\n  [ERROR] Could not obtain A records: {e}")
        dns_info['A'] = []
    
    return dns_info

# ============================================================================
# 6. FINAL SUMMARY
# ============================================================================

def print_summary(domain, whois_info, is_alive, ip, open_ports, dns_info, breach_results):
    """Print summary of all results"""
    print_section("FINAL SUMMARY")
    
    print(f"\n  Analyzed domain: {domain}")
    print(f"  Analysis date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # WHOIS
    print("  +- WHOIS:")
    if whois_info:
        print(f"  |  [SUCCESS] Registrar: {whois_info.registrar}")
        if whois_info.emails:
            emails = whois_info.emails if isinstance(whois_info.emails, list) else [whois_info.emails]
            print(f"  |  [SUCCESS] Emails found: {len(emails)}")
    else:
        print("  |  [ERROR] Not available")
    
    # Breach check results (Customized)
    print("  |")
    print("  +- SECURITY BREACHES:")
    if breach_results['emails_checked'] > 0:
        if breach_results['breached_emails']:
            print(f"  |  [WARNING] {len(breach_results['breached_emails'])} email(s) compromised")
            print(f"  |  [WARNING] Total breaches found: {breach_results['total_breaches']}")
            for breach in breach_results['breached_emails']:
                print(f"  |    - {breach['email']}: {breach['count']} breach(es)")
        else:
            print(f"  |  [SUCCESS] No breaches found ({breach_results['emails_checked']} email(s) checked)")
    else:
        print("  |  [INFO] No emails available to check")
    
    # Domain status
    print("  |")
    print("  +- STATUS:")
    print(f"  |  {'[SUCCESS] ALIVE' if is_alive else '[ERROR] UNREACHABLE'}")
    if ip:
        print(f"  |  IP: {ip}")
    
    # Ports
    print("  |")
    print("  +- PORTS:")
    if open_ports:
        print(f"  |  [SUCCESS] {len(open_ports)} open port(s):")
        for port_info in open_ports:
            print(f"  |    - {port_info['port']} ({port_info['service']})")
    else:
        print("  |  [INFO] No open ports found")
    
    # DNS
    print("  |")
    print("  +- DNS:")
    if dns_info.get('NS'):
        print(f"     [SUCCESS] Name Servers: {len(dns_info['NS'])}")
    if dns_info.get('MX'):
        print(f"     [SUCCESS] Mail Servers: {len(dns_info['MX'])}")
    
    print("\n" + "=" * 70)

# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main function"""
    
    # Validate arguments
    if len(sys.argv) != 2:
        print(f"[ERROR] Usage: {sys.argv[0]} <domain>")
        print(f"Example: {sys.argv[0]} google.com")
        sys.exit(1)
    
    domain = sys.argv[1]
    
    print_banner()
    print(f"Starting reconnaissance for domain: {domain}\n")
    
    # 1. Obtain WHOIS
    whois_info = get_whois(domain)
    
    # 2. Verify breaches with Intelligence X
    print_section("2. EMAIL BREACH VERIFICATION (INTELLIGENCE X)")
    
    api_configured = False
    breach_results = {
        'total_emails': 0,
        'emails_checked': 0,
        'breached_emails': [],
        'total_breaches': 0
    }
    
    if whois_info and whois_info.emails:
        emails = whois_info.emails if isinstance(whois_info.emails, list) else [whois_info.emails]
        
        breach_results['total_emails'] = len(emails)
        print(f"  Found {len(emails)} email(s) in WHOIS data\n")
        
        for email in emails:
            print(f"  Checking: {email}")
            found, result = check_email_breaches_intelx(email, debug=False)
            
            if result == "NO_API_KEY":
                print(f"  [WARNING] Intelligence X API key not configured")
                print(f"  [INFO] Configure INTELX_API_KEY in script to enable breach checking")
                break
            elif result == "SEARCH_FAILED":
                print(f"  [ERROR] Search request failed - check API key and credits")
                break
            elif found is True:
                api_configured = True
                breach_results['emails_checked'] += 1
                breach_results['breached_emails'].append({
                    'email': email,
                    'count': len(result)
                })
                breach_results['total_breaches'] += len(result)
                
                print(f"  [WARNING] BREACHES FOUND for {email}")
                print(f"    Total records: {len(result)}")
                for i, record in enumerate(result[:5], 1):
                    bucket = record.get('bucket', 'Unknown')
                    date = record.get('date', 'Unknown')
                    name = record.get('name', 'No description')
                    print(f"      {i}. Source: {bucket} | Date: {date}")
                    print(f"         {name}")
                if len(result) > 5:
                    print(f"      ... and {len(result) - 5} more result(s)")
            elif found is False:
                api_configured = True
                breach_results['emails_checked'] += 1
                print(f"  [SUCCESS] No breaches found for {email}")
            else:
                print(f"  [ERROR] Could not verify {email} - {result}")
            print()
        
    else:
        print("  [INFO] No emails found in WHOIS data to check")
    
    # 3. Verify if alive
    is_alive, ip = is_domain_alive(domain)
    
    # 4. Scan ports
    open_ports = []
    if is_alive and ip:
        open_ports = scan_top_ports(ip)
    else:
        print_section("4. PORT SCANNING (TOP 10)")
        print("  [ERROR] Skipping scan: domain not accessible")
    
    # 5. Obtain DNS records
    dns_info = get_dns_records(domain)
    
    # 6. Display summary
    print_summary(domain, whois_info, is_alive, ip, open_ports, dns_info, breach_results)

if __name__ == "__main__":
    main()
