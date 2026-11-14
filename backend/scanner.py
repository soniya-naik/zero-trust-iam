
import subprocess
import re
import socket
import ssl
import ipaddress
import urllib.request
import urllib.error
import certifi
from urllib.parse import urlparse


# =====================================
# EXISTING IP / HOSTNAME SCANNER
# =====================================

def scan_target(target):
    try:
        result = subprocess.run(
            ["nmap", "-sV", "--open", target],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:
            return {
                "success": False,
                "message": "Nmap scan failed",
                "error": result.stderr
            }

        output = result.stdout
        open_ports = []

        for line in output.splitlines():
            match = re.match(
                r"^(\d+)/(\w+)\s+open\s+(\S+)(?:\s+(.*))?$",
                line.strip()
            )

            if match:
                open_ports.append({
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "service": match.group(3),
                    "version": match.group(4) or "Unknown"
                })

        risk_score = len(open_ports) * 10

        sensitive_ports = {
            21: 20,
            23: 25,
            3389: 20,
            445: 20,
            3306: 15,
            5432: 15
        }

        for item in open_ports:
            risk_score += sensitive_ports.get(item["port"], 0)

        risk_score = min(risk_score, 100)

        return {
            "success": True,
            "target": target,
            "open_ports": open_ports,
            "total_open_ports": len(open_ports),
            "risk_score": risk_score
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "message": "Nmap scan timed out"
        }

    except FileNotFoundError:
        return {
            "success": False,
            "message": "Nmap is not installed or not in PATH"
        }

    except Exception as error:
        return {
            "success": False,
            "message": str(error)
        }


# =====================================
# WEBSITE SECURITY SCANNER
# =====================================

def scan_website(url):

    try:
        # Validate and normalize URL
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        hostname = parsed.hostname

        if (
            not hostname
            or parsed.scheme not in ("http", "https")
            or parsed.username
            or parsed.password
            or parsed.port not in (None, 80, 443)
        ):
            return {
                "success": False,
                "message": "Invalid website URL or unsupported port"
            }

        # Resolve DNS
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

        resolved_ips = list(set(
            item[4][0] for item in addresses
        ))

        if not resolved_ips:
            return {
                "success": False,
                "message": "Website DNS lookup failed"
            }

        # Reject private and non-public addresses
        for address in resolved_ips:
            ip = ipaddress.ip_address(address)

            if not ip.is_global:
                return {
                    "success": False,
                    "message": "Private or local network targets are not allowed"
                }

        # =================================
        # SSL CERTIFICATE CHECK
        # =================================

        ssl_info = {
            "https": parsed.scheme == "https",
            "certificate_valid": False,
            "expiry": None
        }

        ssl_context = ssl.create_default_context(
            cafile=certifi.where()
        )

        if parsed.scheme == "https":

            try:
                with socket.create_connection(
                    (hostname, parsed.port or 443),
                    timeout=10
                ) as sock:

                    with ssl_context.wrap_socket(
                        sock,
                        server_hostname=hostname
                    ) as secure_socket:

                        certificate = secure_socket.getpeercert()

                        ssl_info["certificate_valid"] = True
                        ssl_info["expiry"] = certificate.get(
                            "notAfter"
                        )

            except Exception as error:
                ssl_info["certificate_error"] = str(error)

        # =================================
        # HTTP SECURITY HEADER CHECK
        # =================================

        class NoRedirect(urllib.request.HTTPRedirectHandler):

            def redirect_request(
                self, req, fp, code, msg, headers, newurl
            ):
                return None

        # IMPORTANT: Use certifi for HTTPS requests too.
        https_handler = urllib.request.HTTPSHandler(
            context=ssl_context
        )

        opener = urllib.request.build_opener(
            https_handler,
            NoRedirect()
        )

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "ZeroTrustSecurityScanner/1.0"
            },
            method="GET"
        )

        try:
            response = opener.open(
                request,
                timeout=10
            )

            status_code = response.status
            headers = response.headers
            response.close()

        except urllib.error.HTTPError as error:
            status_code = error.code
            headers = error.headers

        except Exception as error:
            return {
                "success": False,
                "message": "Website connection failed",
                "error": str(error),
                "ssl": ssl_info
            }

        # =================================
        # SECURITY HEADER ANALYSIS
        # =================================

        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy"
        ]

        header_results = {}

        for header in security_headers:
            header_results[header] = header in headers

        missing_headers = [
            name
            for name, present in header_results.items()
            if not present
        ]

        # =================================
        # RISK SCORE CALCULATION
        # =================================

        risk_score = 0

        if parsed.scheme != "https":
            risk_score += 40

        if (
            parsed.scheme == "https"
            and not ssl_info["certificate_valid"]
        ):
            risk_score += 40

        risk_score += len(missing_headers) * 8
        risk_score = min(risk_score, 100)

        return {
            "success": True,
            "website": url,
            "hostname": hostname,
            "resolved_ips": resolved_ips,
            "status_code": status_code,
            "ssl": ssl_info,
            "security_headers": header_results,
            "missing_headers": missing_headers,
            "risk_score": risk_score
        }

    except Exception as error:
        return {
            "success": False,
            "message": str(error)
        }


# =====================================
# TEST WEBSITE SCANNER
# =====================================

if __name__ == "__main__":

    result = scan_website("https://example.com")

    print("\n========== WEBSITE SECURITY SCAN ==========")

    print("Success:", result.get("success"))
    print("Website:", result.get("website"))
    print("Hostname:", result.get("hostname"))
    print("IP Addresses:", result.get("resolved_ips"))
    print("Status Code:", result.get("status_code"))
    print("SSL:", result.get("ssl"))
    print("Security Headers:", result.get("security_headers"))
    print("Missing Headers:", result.get("missing_headers"))
    print("Risk Score:", result.get("risk_score"))
