# Domain Reconnaissance Tool

A comprehensive Python-based reconnaissance tool for gathering intelligence about domains through WHOIS lookups, DNS queries, port scanning, and data breach verification using Intelligence X API.

## Features

-   **WHOIS Information**: Extract detailed domain registration data including registrar, creation/expiration dates, nameservers, and contact emails
-   **Email Breach Verification**: Check exposed emails against Intelligence X database for security breaches
-   **Domain Availability Check**: Verify if a domain is live via DNS resolution
-   **Port Scanning**: Scan the top 10 most common ports (FTP, SSH, HTTP, HTTPS, etc.)
-   **DNS Records**: Retrieve NS (Name Server), MX (Mail Exchange), and A (IPv4) records
-   **Comprehensive Summary**: Generate a detailed report of all findings

## Requirements

### Python Version

-   Python 3.6 or higher

### Dependencies

```bash
pip install python-whois
pip install dnspython
pip install requests
pip install python-dotenv
```

Or install all at once:

```bash
pip install python-whois dnspython requests python-dotenv
```

## Installation

1. Clone or download the script to your local machine
2. Install required dependencies (see above)
3. Configure Intelligence X API key (optional but recommended)

## Configuration

### Intelligence X API Setup (Optional)

To enable email breach checking, you need an Intelligence X API key:

1. Create a free account at [Intelligence X](https://intelx.io/)
2. Obtain your API key from the dashboard
3. Create a `.env` file in the same directory as the script:

```env
INTELX_API_KEY=your_api_key_here
```

Without an API key, the breach checking feature will be skipped, but all other reconnaissance features will work normally.

## Usage

### Basic Usage

```bash
python3 script.py <domain>
```

### Examples

```bash
# Analyze a domain
python3 script.py example.com

# Domain with protocol (will be automatically cleaned)
python3 script.py https://www.example.com

# Domain with subdomain
python3 script.py subdomain.example.com
```

## Output Sections

The tool provides reconnaissance results in six main sections:

### 1. WHOIS Information

-   Domain name and registrar
-   Creation and expiration dates
-   Name servers
-   Contact emails
-   Geographic information (country, state, city)

### 2. Email Breach Verification

-   Checks emails found in WHOIS against Intelligence X database
-   Reports number of breaches per email
-   Shows breach sources and dates
-   Displays top 5 results per email

### 3. Availability Verification

-   DNS resolution check
-   Resolved IP address

### 4. Port Scanning

-   Scans top 10 common ports: 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP), 110 (POP3), 143 (IMAP), 443 (HTTPS), 3389 (RDP)
-   Shows open/closed status for each port
-   Identifies associated services

### 5. DNS Records

-   NS (Name Server) records
-   MX (Mail Exchange) records with priority
-   A (IPv4 address) records

### 6. Final Summary

-   Consolidated view of all findings
-   Quick overview of domain status
-   Highlights security concerns

## Customization

### Modify Port List

Edit the `TOP_PORTS` constant at the beginning of the script:

```python
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389]
```

### Adjust Timeout

Change the connection timeout for port scanning:

```python
TIMEOUT = 2  # seconds
```

## Example Output

```
======================================================================
DOMAIN RECONNAISSANCE TOOL
Starting reconnaissance for domain: example.com
──────────────────────────────────────────────────────────────────────
► 1. WHOIS INFORMATION
──────────────────────────────────────────────────────────────────────
WHOIS obtained successfully for: example.com
Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Creation Date: 1995-08-14 04:00:00
Expiration Date: 2025-08-13 04:00:00
Name Servers: ['ns1.example.com', 'ns2.example.com']
Emails: admin@example.com
──────────────────────────────────────────────────────────────────────
► 2. EMAIL BREACH VERIFICATION (INTELLIGENCE X)
──────────────────────────────────────────────────────────────────────
Found 1 email(s) in WHOIS data
Checking: admin@example.com
[SUCCESS] No breaches found for admin@example.com
──────────────────────────────────────────────────────────────────────
► 3. AVAILABILITY VERIFICATION
──────────────────────────────────────────────────────────────────────
[SUCCESS] Domain is ALIVE
Resolved IP: 93.184.216.34
──────────────────────────────────────────────────────────────────────
► 4. PORT SCANNING (TOP 10)
──────────────────────────────────────────────────────────────────────
Scanning 10 ports on 93.184.216.34...
Ports to scan: [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389]
[CLOSED] Port 21 [FTP ] - CLOSED
[CLOSED] Port 22 [SSH ] - CLOSED
[OPEN]   Port 80 [HTTP ] - OPEN
[OPEN]   Port 443 [HTTPS] - OPEN
Result: 2 open port(s) out of 10 scanned
```

## Limitations

-   Port scanning may be blocked by firewalls or security policies
-   WHOIS information may be redacted due to GDPR/privacy protection
-   Intelligence X API has rate limits and requires credits for searches
-   Some DNS records may be private or protected
-   Scanning non-owned domains may violate terms of service or local laws

## Legal Notice

**Important**: This tool is intended for educational purposes and authorized security testing only. Always obtain proper authorization before scanning domains you do not own. Unauthorized reconnaissance may be illegal in your jurisdiction and violate terms of service.

## Troubleshooting

### "No module named 'dotenv'"

Install the package:

```bash
pip3 install python-dotenv
```

### "No module named 'whois'"

Install the package:

```bash
pip3 install python-whois
```

### Port scanning shows all closed

-   Target may have a firewall blocking scans
-   Network policies may prevent outbound connections
-   Domain IP may be behind CDN/proxy

### Intelligence X returns no results

-   Verify API key is correctly configured in `.env`
-   Check that you have available API credits
-   Ensure stable internet connection

## License

This script is provided as-is for educational and authorized security testing purposes.

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.
