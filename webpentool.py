import os
import subprocess
import json
from datetime import datetime
from urllib.parse import urlparse

# Global path to SecLists directory
SECLISTS_DIR = "/opt/SecLists"  # Ubah sesuai lokasi sebenarnya

class WebPentestTool:
    def __init__(self, url):
        self.url = url
        self.domain = urlparse(url).netloc
        self.report = {}
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.report_path = f"reports/{self.domain}_{self.timestamp}"
        os.makedirs(self.report_path, exist_ok=True)

    def run_command(self, command):
        """Execute a shell command and return the output."""
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
            return result.strip()
        except subprocess.CalledProcessError as e:
            return f"[ERROR] Command failed: {e.output.strip()}"

    def dns_enumeration(self):
        print("[*] Running DNS Enumeration...")
        dig_result = self.run_command(f"dig {self.domain}")
        nslookup_result = self.run_command(f"nslookup {self.domain}")
        self.report['dns_enumeration'] = {"dig": dig_result, "nslookup": nslookup_result}
        with open(f"{self.report_path}/dns_enumeration.txt", "w") as file:
            file.write(f"=== DIG RESULT ===\n{dig_result}\n\n=== NSLOOKUP RESULT ===\n{nslookup_result}\n")

    def subdomain_enumeration(self):
        print("[*] Running Subdomain Enumeration...")
        wordlist = f"{SECLISTS_DIR}/Discovery/DNS/subdomains-top1million-5000.txt"
        subfinder_result = self.run_command(f"subfinder -d {self.domain}")
        amass_result = self.run_command(f"amass enum -d {self.domain}")
        self.report['subdomain_enumeration'] = {"subfinder": subfinder_result, "amass": amass_result}
        with open(f"{self.report_path}/subdomain_enumeration.txt", "w") as file:
            file.write(f"=== SUBFINDER RESULT ===\n{subfinder_result}\n\n=== AMASS RESULT ===\n{amass_result}\n")

    def whois_lookup(self):
        print("[*] Running WHOIS Lookup...")
        result = self.run_command(f"whois {self.domain}")
        self.report['whois_lookup'] = result
        with open(f"{self.report_path}/whois_lookup.txt", "w") as file:
            file.write(result)

    def http_headers_tech(self):
        print("[*] Retrieving HTTP Headers...")
        result = self.run_command(f"curl -s -D - -o /dev/null {self.url}")
        self.report['http_headers'] = result
        with open(f"{self.report_path}/http_headers.txt", "w") as file:
            file.write(result)

    def owasp_injection_tests(self):
        print("[*] Performing OWASP Injection Tests (basic payload fuzz)...")
        payloads_file = f"{SECLISTS_DIR}/Fuzzing/SQLi/Generic-SQLi.txt"
        if not os.path.isfile(payloads_file):
            self.report['owasp_injection_tests'] = "[ERROR] Payload file not found."
            return

        with open(payloads_file) as f:
            payloads = f.read().splitlines()

        results = {}
        for payload in payloads[:10]:  # Limit untuk efisiensi
            test_url = f"{self.url}?test={payload}"
            response = self.run_command(f"curl -s -o /dev/null -w '%{{http_code}}' \"{test_url}\"")
            results[test_url] = f"HTTP {response}"

        self.report['owasp_injection_tests'] = results
        with open(f"{self.report_path}/owasp_injection_tests.txt", "w") as file:
            for url, res in results.items():
                file.write(f"{url}: {res}\n")

    def ssrf_vulnerability_check(self):
        print("[*] Running SSRF Vulnerability Checks...")
        ssrf_endpoints = [
            "/admin", "/internal", "/api/internal", "/metadata",
            "/.env", "/.git", "/.aws/credentials"
        ]
        results = {}
        for endpoint in ssrf_endpoints:
            full_url = f"{self.url.rstrip('/')}{endpoint}"
            print(f"[*] Testing {full_url}")
            response = self.run_command(f"curl -s -o /dev/null -w '%{{http_code}}' \"{full_url}\"")
            results[full_url] = f"HTTP {response}"
        self.report['ssrf_vulnerability_check'] = results
        with open(f"{self.report_path}/ssrf_vulnerability_check.txt", "w") as file:
            for url, message in results.items():
                file.write(f"{url}: {message}\n")

    def broken_access_control(self):
        print("[*] Testing Broken Access Control...")
        common_paths = [
            "/admin", "/dashboard", "/config", "/setup.php"
        ]
        results = {}
        for path in common_paths:
            full_url = f"{self.url.rstrip('/')}{path}"
            response = self.run_command(f"curl -s -o /dev/null -w '%{{http_code}}' \"{full_url}\"")
            results[full_url] = f"HTTP {response}"
        self.report['broken_access_control'] = results
        with open(f"{self.report_path}/broken_access_control.txt", "w") as file:
            for url, message in results.items():
                file.write(f"{url}: {message}\n")

    def security_misconfiguration(self):
        print("[*] Checking Security Misconfigurations...")
        headers = self.run_command(f"curl -s -D - -o /dev/null {self.url}")
        findings = []
        if "X-Frame-Options" not in headers:
            findings.append("Missing X-Frame-Options header")
        if "Content-Security-Policy" not in headers:
            findings.append("Missing Content-Security-Policy header")
        if "Strict-Transport-Security" not in headers:
            findings.append("Missing HSTS header")
        self.report['security_misconfiguration'] = findings
        with open(f"{self.report_path}/security_misconfiguration.txt", "w") as file:
            for finding in findings:
                file.write(f"{finding}\n")

    def vulnerable_and_outdated_components(self):
        print("[*] Detecting outdated technologies via Wappalyzer (requires installed CLI)...")
        result = self.run_command(f"wappalyzer {self.url}")
        self.report['vulnerable_and_outdated_components'] = result
        with open(f"{self.report_path}/vulnerable_components.txt", "w") as file:
            file.write(result)

    def authentication_failures(self):
        print("[*] Checking for common login pages...")
        wordlist = f"{SECLISTS_DIR}/Discovery/Web-Content/common.txt"
        if not os.path.isfile(wordlist):
            self.report['authentication_failures'] = "[ERROR] Wordlist not found."
            return

        with open(wordlist) as f:
            paths = f.read().splitlines()

        results = {}
        for path in paths[:50]:
            url = f"{self.url.rstrip('/')}/{path}"
            response = self.run_command(f"curl -s -o /dev/null -w '%{{http_code}}' \"{url}\"")
            if response in ["200", "401", "403"]:
                results[url] = f"HTTP {response}"

        self.report['authentication_failures'] = results
        with open(f"{self.report_path}/authentication_failures.txt", "w") as file:
            for url, res in results.items():
                file.write(f"{url}: {res}\n")

    def software_and_data_integrity_failures(self):
        print("[*] Checking for Git/.env leaks...")
        files = ["/.env", "/.git/config", "/composer.lock"]
        results = {}
        for path in files:
            full_url = f"{self.url.rstrip('/')}{path}"
            response = self.run_command(f"curl -s -o /dev/null -w '%{{http_code}}' \"{full_url}\"")
            results[full_url] = f"HTTP {response}"
        self.report['software_and_data_integrity_failures'] = results
        with open(f"{self.report_path}/integrity_failures.txt", "w") as file:
            for url, message in results.items():
                file.write(f"{url}: {message}\n")

    def security_logging_and_monitoring_failures(self):
        print("[*] Verifying lack of monitoring via fake 404/500 requests...")
        test_url = f"{self.url.rstrip('/')}/nonexistent_{datetime.now().timestamp()}"
        response = self.run_command(f"curl -s -o /dev/null -w '%{{http_code}}' \"{test_url}\"")
        message = "Returned 404 as expected" if response == "404" else f"Unexpected response: {response}"
        self.report['security_logging_and_monitoring_failures'] = message
        with open(f"{self.report_path}/logging_and_monitoring.txt", "w") as file:
            file.write(message)

    def save_report(self):
        with open(f"{self.report_path}/report.json", "w") as file:
            json.dump(self.report, file, indent=4)
        print(f"[+] Report saved to {self.report_path}/report.json")

    def run(self):
        print(f"[+] Starting Web Pentest on {self.url}")
        self.dns_enumeration()
        self.subdomain_enumeration()
        self.whois_lookup()
        self.http_headers_tech()
        self.owasp_injection_tests()
        self.broken_access_control()
        self.security_misconfiguration()
        self.vulnerable_and_outdated_components()
        self.authentication_failures()
        self.software_and_data_integrity_failures()
        self.security_logging_and_monitoring_failures()
        self.ssrf_vulnerability_check()
        self.save_report()
        print("[+] Web Pentest Completed Successfully.")


if __name__ == "__main__":
    url = input("Enter the target URL: ").strip()
    if not url.startswith("http"):
        url = "http://" + url
    pentest = WebPentestTool(url)
    pentest.run()
