import subprocess
import re


def scan_target(target):
    try:
        result = subprocess.run(
            [
                "nmap",
                "-sV",
                "--open",
                target
            ],
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
                port = int(match.group(1))
                protocol = match.group(2)
                service = match.group(3)
                version = match.group(4) or "Unknown"

                open_ports.append({
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                    "version": version
                })

        # -----------------------------
        # Risk calculation
        # -----------------------------

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
            port = item["port"]

            if port in sensitive_ports:
                risk_score += sensitive_ports[port]

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


if __name__ == "__main__":

    result = scan_target("127.0.0.1")

    print("\n========== SECURITY SCAN ==========")
    print("Target:", result.get("target"))
    print("Success:", result.get("success"))
    print("Open Ports:", result.get("open_ports"))
    print("Total Open Ports:", result.get("total_open_ports"))
    print("Risk Score:", result.get("risk_score"))