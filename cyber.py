#!/usr/bin/env python3

import os
import platform
import hashlib
import logging
import socket
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import psutil
import requests


# ---------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

HIGH_RISK_DIRS = [
    "\\temp\\",
    "\\tmp\\",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/"
]


# ---------------------------------------------------------
# Forensic Triage Engine
# ---------------------------------------------------------

class ForensicTriageEngine:

    def __init__(self):
        self.metadata = {}
        self.processes = []
        self.connections = []
        self.threat_intel_cache = {}

    # -----------------------------------------------------
    # Collect system information
    # -----------------------------------------------------

    def collect_system_metadata(self):

        try:
            boot_time = datetime.datetime.fromtimestamp(
                psutil.boot_time()
            ).strftime("%Y-%m-%d %H:%M:%S")

        except Exception:
            boot_time = "Unknown"

        self.metadata = {
            "Hostname": socket.gethostname(),
            "OS": platform.system(),
            "OS Release": platform.release(),
            "OS Version": platform.version(),
            "Architecture": platform.machine(),
            "Boot Time": boot_time,
            "CPU Count": psutil.cpu_count(),
            "RAM": f"{round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB"
        }

    # -----------------------------------------------------
    # Calculate SHA256 hash
    # -----------------------------------------------------

    @staticmethod
    def calculate_sha256(file_path):

        if not file_path:
            return "N/A"

        if not os.path.exists(file_path):
            return "N/A"

        if os.path.isdir(file_path):
            return "N/A"

        sha256 = hashlib.sha256()

        try:

            with open(file_path, "rb") as file:

                for chunk in iter(
                    lambda: file.read(4096),
                    b""
                ):
                    sha256.update(chunk)

            return sha256.hexdigest()

        except (PermissionError, OSError):
            return "ACCESS_DENIED"

        except Exception:
            return "ERROR"

    # -----------------------------------------------------
    # VirusTotal lookup
    # -----------------------------------------------------

    def check_virus_total(self, file_hash):

        if file_hash in [
            "N/A",
            "ACCESS_DENIED",
            "ERROR"
        ]:
            return {
                "status": "Unchecked",
                "malicious_count": 0
            }

        # No API key configured
        if not VT_API_KEY:

            return {
                "status": "Unchecked",
                "malicious_count": 0
            }

        # Check cache
        if file_hash in self.threat_intel_cache:
            return self.threat_intel_cache[file_hash]

        url = (
            "https://www.virustotal.com/api/v3/files/"
            + file_hash
        )

        headers = {
            "x-apikey": VT_API_KEY
        }

        try:

            response = requests.get(
                url,
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:

                data = response.json()

                stats = (
                    data
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )

                malicious = stats.get(
                    "malicious",
                    0
                )

                result = {
                    "status": (
                        "Malicious"
                        if malicious > 0
                        else "Clean"
                    ),
                    "malicious_count": malicious
                }

                self.threat_intel_cache[file_hash] = result

                return result

            elif response.status_code == 404:

                return {
                    "status": "Not Found",
                    "malicious_count": 0
                }

            elif response.status_code == 401:

                return {
                    "status": "Invalid API Key",
                    "malicious_count": 0
                }

            else:

                return {
                    "status": f"HTTP {response.status_code}",
                    "malicious_count": 0
                }

        except requests.exceptions.Timeout:

            return {
                "status": "Timeout",
                "malicious_count": 0
            }

        except requests.exceptions.RequestException:

            return {
                "status": "Connection Error",
                "malicious_count": 0
            }

        except Exception:

            return {
                "status": "Error",
                "malicious_count": 0
            }

    # -----------------------------------------------------
    # Analyze one process
    # -----------------------------------------------------

    def analyze_single_process(self, process):

        try:

            process_info = process.as_dict(
                attrs=[
                    "pid",
                    "name",
                    "username",
                    "exe",
                    "status"
                ]
            )

            pid = process_info.get("pid")

            name = process_info.get(
                "name"
            ) or "Unknown"

            username = process_info.get(
                "username"
            ) or "Unknown"

            exe_path = process_info.get(
                "exe"
            ) or ""

            status = process_info.get(
                "status"
            ) or "Unknown"

            # Check whether executable is located
            # in a potentially risky directory

            lower_path = exe_path.lower()

            is_suspicious_location = any(
                directory in lower_path
                for directory in HIGH_RISK_DIRS
            )

            # Calculate file hash

            if exe_path:

                file_hash = self.calculate_sha256(
                    exe_path
                )

            else:

                file_hash = "N/A"

            # Threat intelligence

            intel = self.check_virus_total(
                file_hash
            )

            # Determine severity

            severity = "Low"

            reason = "No obvious indicators"

            if is_suspicious_location:

                severity = "Medium"
                reason = (
                    "Executable located in "
                    "a potentially risky directory"
                )

            if intel.get(
                "malicious_count",
                0
            ) > 0:

                severity = "High"

                reason = (
                    "VirusTotal reports "
                    "malicious detections"
                )

            return {
                "pid": pid,
                "name": name,
                "username": username,
                "path": exe_path,
                "status": status,
                "hash": file_hash,
                "severity": severity,
                "reason": reason,
                "virus_total": intel.get(
                    "status",
                    "Unchecked"
                )
            }

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):

            return None

        except Exception:

            return None

    # -----------------------------------------------------
    # Analyze running processes
    # -----------------------------------------------------

    def triage_volatile_processes(self):

        print(
            "\n[+] Collecting running processes..."
        )

        processes = list(
            psutil.process_iter()
        )

        print(
            f"[+] Found {len(processes)} processes."
        )

        with ThreadPoolExecutor(
            max_workers=10
        ) as executor:

            futures = {
                executor.submit(
                    self.analyze_single_process,
                    process
                ): process
                for process in processes
            }

            for future in as_completed(
                futures
            ):

                try:

                    result = future.result()

                    if result:
                        self.processes.append(
                            result
                        )

                except Exception:
                    pass

    # -----------------------------------------------------
    # Analyze network connections
    # -----------------------------------------------------

    def triage_network_sockets(self):

        print(
            "\n[+] Collecting network connections..."
        )

        try:

            connections = psutil.net_connections(
                kind="inet"
            )

            print(
                f"[+] Found {len(connections)} "
                "network connections."
            )

            for connection in connections:

                process_name = "N/A"

                if connection.pid:

                    try:

                        process_name = (
                            psutil.Process(
                                connection.pid
                            ).name()
                        )

                    except (
                        psutil.NoSuchProcess,
                        psutil.AccessDenied
                    ):

                        process_name = "Unknown"

                # Local address

                if connection.laddr:

                    local_ip = connection.laddr.ip
                    local_port = connection.laddr.port

                else:

                    local_ip = "0.0.0.0"
                    local_port = 0

                # Remote address

                if connection.raddr:

                    remote_ip = connection.raddr.ip
                    remote_port = connection.raddr.port

                else:

                    remote_ip = "0.0.0.0"
                    remote_port = 0

                self.connections.append({

                    "pid": (
                        connection.pid
                        if connection.pid
                        else "N/A"
                    ),

                    "process": process_name,

                    "local": (
                        f"{local_ip}:{local_port}"
                    ),

                    "remote": (
                        f"{remote_ip}:{remote_port}"
                    ),

                    "state": connection.status
                })

        except psutil.AccessDenied:

            print(
                "[!] Access denied while "
                "reading network connections."
            )

        except Exception as error:

            print(
                f"[!] Network collection error: "
                f"{error}"
            )

    # -----------------------------------------------------
    # Generate HTML report
    # -----------------------------------------------------

    def generate_html_forensic_report(
        self,
        filename="forensic_triage_report.html"
    ):

        print(
            "\n[+] Generating forensic report..."
        )

        # System metadata

        metadata_rows = ""

        for key, value in self.metadata.items():

            metadata_rows += f"""
            <tr>
                <th>{key}</th>
                <td>{value}</td>
            </tr>
            """

        # Process rows

        process_rows = ""

        # Sort by severity

        severity_order = {
            "High": 0,
            "Medium": 1,
            "Low": 2
        }

        sorted_processes = sorted(
            self.processes,
            key=lambda process: severity_order.get(
                process.get("severity"),
                3
            )
        )

        for process in sorted_processes:

            process_rows += f"""
            <tr>
                <td>{process["pid"]}</td>
                <td>{process["name"]}</td>
                <td>{process["username"]}</td>
                <td>{process["path"]}</td>
                <td>{process["hash"]}</td>
                <td>{process["severity"]}</td>
                <td>{process["reason"]}</td>
                <td>{process["virus_total"]}</td>
            </tr>
            """

        # Network rows

        network_rows = ""

        for connection in self.connections:

            network_rows += f"""
            <tr>
                <td>{connection["pid"]}</td>
                <td>{connection["process"]}</td>
                <td>{connection["local"]}</td>
                <td>{connection["remote"]}</td>
                <td>{connection["state"]}</td>
            </tr>
            """

        # HTML report

        html_template = f"""
<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>Ares Forensic Triage Report</title>

    <style>

        body {{
            font-family: Arial, sans-serif;
            margin: 30px;
            background: #f4f6f8;
            color: #222;
        }}

        h1 {{
            padding: 20px;
            background: #1f2937;
            color: white;
            border-radius: 8px;
        }}

        h2 {{
            margin-top: 30px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            margin-top: 10px;
        }}

        th,
        td {{
            border: 1px solid #ccc;
            padding: 8px;
            text-align: left;
            font-size: 13px;
        }}

        th {{
            background: #e5e7eb;
        }}

        .summary {{
            display: flex;
            gap: 20px;
            margin: 20px 0;
        }}

        .card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            flex: 1;
            border: 1px solid #ddd;
        }}

        .high {{
            font-weight: bold;
        }}

        .medium {{
            font-weight: bold;
        }}

    </style>

</head>

<body>

    <h1>
        Ares Forensic Triage Report
    </h1>

    <p>
        Generated:
        {datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )}
    </p>

    <div class="summary">

        <div class="card">
            <strong>Total Processes</strong>
            <br>
            {len(self.processes)}
        </div>

        <div class="card">
            <strong>Network Connections</strong>
            <br>
            {len(self.connections)}
        </div>

        <div class="card">
            <strong>High Severity</strong>
            <br>
            {
                sum(
                    1
                    for p in self.processes
                    if p["severity"] == "High"
                )
            }
        </div>

        <div class="card">
            <strong>Medium Severity</strong>
            <br>
            {
                sum(
                    1
                    for p in self.processes
                    if p["severity"] == "Medium"
                )
            }
        </div>

    </div>

    <h2>
        System Metadata
    </h2>

    <table>

        {metadata_rows}

    </table>

    <h2>
        Running Processes
    </h2>

    <table>

        <tr>
            <th>PID</th>
            <th>Name</th>
            <th>Username</th>
            <th>Executable Path</th>
            <th>SHA256</th>
            <th>Severity</th>
            <th>Reason</th>
            <th>VirusTotal</th>
        </tr>

        {process_rows}

    </table>

    <h2>
        Network Connections
    </h2>

    <table>

        <tr>
            <th>PID</th>
            <th>Process</th>
            <th>Local Address</th>
            <th>Remote Address</th>
            <th>State</th>
        </tr>

        {network_rows}

    </table>

</body>

</html>
"""

        try:

            with open(
                filename,
                "w",
                encoding="utf-8"
            ) as report_file:

                report_file.write(
                    html_template
                )

            print(
                f"[+] Report saved as: {filename}"
            )

        except Exception as error:

            print(
                f"[!] Could not create report: "
                f"{error}"
            )

    # -----------------------------------------------------
    # Run complete forensic triage
    # -----------------------------------------------------

    def run_all(self):

        print("\n" + "=" * 60)
        print("       ARES FORENSIC TRIAGE ENGINE")
        print("=" * 60)

        print(
            "\n[+] Collecting system metadata..."
        )

        self.collect_system_metadata()

        print(
            "[+] System metadata collected."
        )

        self.triage_volatile_processes()

        self.triage_network_sockets()

        self.generate_html_forensic_report()

        print("\n" + "=" * 60)
        print("       FORENSIC TRIAGE COMPLETED")
        print("=" * 60)

        print(
            f"\nProcesses analyzed: "
            f"{len(self.processes)}"
        )

        print(
            f"Network connections: "
            f"{len(self.connections)}"
        )

        high_count = sum(
            1
            for process in self.processes
            if process["severity"] == "High"
        )

        medium_count = sum(
            1
            for process in self.processes
            if process["severity"] == "Medium"
        )

        print(
            f"High severity: {high_count}"
        )

        print(
            f"Medium severity: {medium_count}"
        )

        print(
            "\nReport: "
            "forensic_triage_report.html"
        )


# ---------------------------------------------------------
# Main program
# ---------------------------------------------------------

if __name__ == "__main__":

    engine = ForensicTriageEngine()

    engine.run_all()