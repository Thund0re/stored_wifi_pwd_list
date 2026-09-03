#!/usr/bin/env python3
"""
Wi‑Fi Profile Manager - Cross-platform
Retrieves saved wireless network profiles and their passwords.
Supports Windows, Linux, and macOS.
"""

import subprocess
import sys
import json
import csv
import argparse
import os
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import platform


class WiFiProfiler:
    """Cross-platform Wi-Fi profile manager."""
    
    def __init__(self):
        self.os_type = platform.system()
        self.profiles = []
        
    def is_admin(self) -> bool:
        """Check if running with administrator/root privileges."""
        if self.os_type == "Windows":
            try:
                return subprocess.run(
                    ["net", "session"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                ).returncode == 0
            except FileNotFoundError:
                return False
        else:  # Linux/macOS
            return os.geteuid() == 0
    
    def check_dependencies(self) -> bool:
        """Check if required system tools are available."""
        if self.os_type == "Windows":
            return self._check_netsh()
        elif self.os_type == "Linux":
            # Check for nmcli or NetworkManager
            if self._check_command("nmcli"):
                return True
            # Alternative: check for NetworkManager connections directory
            if os.path.exists("/etc/NetworkManager/system-connections/"):
                return True
            return False
        elif self.os_type == "Darwin":  # macOS
            return self._check_command("security")
        return False
    
    def _check_command(self, cmd: str) -> bool:
        """Check if a command exists in PATH."""
        try:
            subprocess.run(
                [cmd, "--version"] if cmd != "netsh" else [cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            return True
        except FileNotFoundError:
            return False
    
    def _check_netsh(self) -> bool:
        """Check if netsh is available on Windows."""
        try:
            subprocess.run(
                ["netsh", "wlan", "show", "profiles"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=2
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def get_profiles_windows(self) -> List[Dict[str, Optional[str]]]:
        """Get Wi-Fi profiles on Windows using netsh."""
        try:
            output = subprocess.check_output(
                ["netsh", "wlan", "show", "profiles"],
                text=True,
                stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError:
            return []
        
        profile_names = []
        for line in output.splitlines():
            if "All User Profile" in line:
                name = line.split(":", 1)[1].strip()
                profile_names.append(name)
        
        profiles = []
        for name in profile_names:
            try:
                output = subprocess.check_output(
                    ["netsh", "wlan", "show", "profile", name, "key=clear"],
                    text=True,
                    stderr=subprocess.PIPE
                )
                details = {
                    "SSID": name,
                    "Authentication": None,
                    "Encryption": None,
                    "Key": None
                }
                for line in output.splitlines():
                    line = line.strip()
                    if "Authentication" in line:
                        details["Authentication"] = line.split(":", 1)[1].strip()
                    elif "Encryption" in line:
                        details["Encryption"] = line.split(":", 1)[1].strip()
                    elif "Key Content" in line:
                        details["Key"] = line.split(":", 1)[1].strip()
                profiles.append(details)
            except subprocess.CalledProcessError:
                profiles.append({
                    "SSID": name,
                    "Authentication": "Error",
                    "Encryption": "Error",
                    "Key": None
                })
        
        return profiles
    
    def get_profiles_linux_nmcli(self) -> List[Dict[str, Optional[str]]]:
        """Get Wi-Fi profiles on Linux using nmcli."""
        try:
            # Get all Wi-Fi connections
            output = subprocess.check_output(
                ["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"],
                text=True,
                stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError:
            return []
        
        connections = []
        for line in output.splitlines():
            if "wifi" in line:
                name = line.split(":", 1)[0]
                connections.append(name)
        
        profiles = []
        for name in connections:
            try:
                # Get connection details
                output = subprocess.check_output(
                    ["nmcli", "-s", "connection", "show", name],
                    text=True,
                    stderr=subprocess.PIPE
                )
                details = {
                    "SSID": name,
                    "Authentication": None,
                    "Encryption": None,
                    "Key": None
                }
                for line in output.splitlines():
                    if "802-11-wireless-security.key-mgmt:" in line:
                        details["Authentication"] = line.split(":", 1)[1].strip()
                    elif "802-11-wireless.mode:" in line:
                        pass
                    elif "802-11-wireless-security.psk:" in line:
                        details["Key"] = line.split(":", 1)[1].strip()
                    elif "802-11-wireless-security.leap-password:" in line:
                        details["Key"] = line.split(":", 1)[1].strip()
                    elif "802-11-wireless-security.preauth-psk:" in line:
                        if not details["Key"]:
                            details["Key"] = line.split(":", 1)[1].strip()
                # Try to get encryption from connection details
                try:
                    enc_output = subprocess.check_output(
                        ["nmcli", "-t", "-f", "802-11-wireless-security.key-mgmt", "connection", "show", name],
                        text=True,
                        stderr=subprocess.PIPE
                    )
                    if "wpa" in enc_output.lower():
                        details["Encryption"] = "WPA/WPA2"
                    elif "wep" in enc_output.lower():
                        details["Encryption"] = "WEP"
                except:
                    pass
                profiles.append(details)
            except subprocess.CalledProcessError:
                continue
        
        return profiles
    
    def get_profiles_linux_files(self) -> List[Dict[str, Optional[str]]]:
        """Get Wi-Fi profiles from NetworkManager connection files."""
        connections_dir = Path("/etc/NetworkManager/system-connections/")
        if not connections_dir.exists():
            return []
        
        profiles = []
        for file_path in connections_dir.glob("*.nmconnection"):
            try:
                content = file_path.read_text(encoding='utf-8')
                ssid = None
                key = None
                security = "Unknown"
                
                # Parse the connection file
                for line in content.splitlines():
                    if line.startswith("ssid="):
                        ssid = line.split("=", 1)[1].strip()
                        # Decode hex if present
                        if ssid.startswith("'") and ssid.endswith("'"):
                            ssid = ssid[1:-1]
                    elif "psk=" in line or "password=" in line:
                        key = line.split("=", 1)[1].strip()
                    elif "key-mgmt=" in line:
                        mgmt = line.split("=", 1)[1].strip()
                        if "wpa" in mgmt.lower():
                            security = "WPA/WPA2"
                        elif "wep" in mgmt.lower():
                            security = "WEP"
                        else:
                            security = mgmt
                
                if ssid:
                    profiles.append({
                        "SSID": ssid,
                        "Authentication": security,
                        "Encryption": "Unknown",
                        "Key": key
                    })
            except (PermissionError, UnicodeDecodeError):
                continue
        
        return profiles
    
    def get_profiles_linux(self) -> List[Dict[str, Optional[str]]]:
        """Get Wi-Fi profiles on Linux."""
        # Try nmcli first (most reliable)
        profiles = self.get_profiles_linux_nmcli()
        if profiles:
            return profiles
        
        # Fallback to reading connection files
        return self.get_profiles_linux_files()
    
    def get_profiles_macos(self) -> List[Dict[str, Optional[str]]]:
        """Get Wi-Fi profiles on macOS using security command."""
        try:
            # Get list of saved Wi-Fi networks
            output = subprocess.check_output(
                ["security", "find-generic-password", "-l", "AirPort", "-w"],
                text=True,
                stderr=subprocess.PIPE
            )
            # This method typically doesn't list all networks
            # Alternative approach:
            output = subprocess.check_output(
                ["networksetup", "-listpreferredwirelessnetworks", "Wi-Fi"],
                text=True,
                stderr=subprocess.PIPE
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            return []
        
        ssids = []
        for line in output.splitlines():
            if line.strip() and not line.startswith("Preferred networks on"):
                ssid = line.strip()
                if ssid:
                    ssids.append(ssid)
        
        profiles = []
        for ssid in ssids:
            try:
                # Try to get password from keychain
                output = subprocess.check_output(
                    ["security", "find-generic-password", "-l", ssid, "-w"],
                    text=True,
                    stderr=subprocess.PIPE
                )
                key = output.strip()
                profiles.append({
                    "SSID": ssid,
                    "Authentication": "WPA/WPA2",  # Default guess
                    "Encryption": "Unknown",
                    "Key": key if key else None
                })
            except subprocess.CalledProcessError:
                profiles.append({
                    "SSID": ssid,
                    "Authentication": "Unknown",
                    "Encryption": "Unknown",
                    "Key": None
                })
        
        return profiles
    
    def get_profiles(self) -> List[Dict[str, Optional[str]]]:
        """Get Wi-Fi profiles based on the current OS."""
        if self.os_type == "Windows":
            return self.get_profiles_windows()
        elif self.os_type == "Linux":
            return self.get_profiles_linux()
        elif self.os_type == "Darwin":
            return self.get_profiles_macos()
        else:
            return []
    
    def format_table(self, profiles: List[Dict[str, Optional[str]]]) -> str:
        """Format profile data as a human‑readable table."""
        if not profiles:
            return "No Wi-Fi profiles found."
        
        headers = ["SSID", "Authentication", "Encryption", "Key"]
        col_widths = [len(h) for h in headers]
        for p in profiles:
            col_widths[0] = max(col_widths[0], len(p.get("SSID", "") or ""))
            col_widths[1] = max(col_widths[1], len(p.get("Authentication", "") or ""))
            col_widths[2] = max(col_widths[2], len(p.get("Encryption", "") or ""))
            col_widths[3] = max(col_widths[3], len(p.get("Key", "") or ""))
        
        lines = []
        # Header
        header_line = "  ".join(
            f"{h:<{col_widths[i]}}" for i, h in enumerate(headers)
        )
        lines.append(header_line)
        lines.append("-" * len(header_line))
        
        # Rows
        for p in profiles:
            row = [
                p.get("SSID") or "",
                p.get("Authentication") or "—",
                p.get("Encryption") or "—",
                p.get("Key") or "—",
            ]
            lines.append(
                "  ".join(f"{row[i]:<{col_widths[i]}}" for i in range(len(row)))
            )
        return "\n".join(lines)
    
    def export_json(self, profiles: List[Dict[str, Optional[str]]], filepath: Path) -> None:
        """Export profile data to a JSON file."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(profiles, f, indent=2, ensure_ascii=False)
        print(f"✅ Data exported to {filepath}")
    
    def export_csv(self, profiles: List[Dict[str, Optional[str]]], filepath: Path) -> None:
        """Export profile data to a CSV file."""
        if not profiles:
            print("No data to export.", file=sys.stderr)
            return
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=profiles[0].keys())
            writer.writeheader()
            writer.writerows(profiles)
        print(f"✅ Data exported to {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="Cross-platform Wi-Fi Profile Manager - Retrieve saved Wi-Fi passwords",
        epilog="Example: python wifi_manager.py --profile HomeWiFi --format json"
    )
    parser.add_argument(
        "--profile",
        help="Show details only for a specific profile name.",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table).",
    )
    parser.add_argument(
        "--output",
        help="Save output to a file (e.g., profiles.json, profiles.csv).",
    )
    parser.add_argument(
        "--no-key",
        action="store_true",
        help="Do not attempt to retrieve the Wi‑Fi key (password).",
    )
    args = parser.parse_args()
    
    # Initialize the Wi-Fi profiler
    profiler = WiFiProfiler()
    
    print(f"💻 Operating System: {profiler.os_type}")
    print(f"🔍 Checking system dependencies...")
    
    # Check dependencies
    if not profiler.check_dependencies():
        print(f"❌ Error: Required system tools not found for {profiler.os_type}", file=sys.stderr)
        if profiler.os_type == "Windows":
            print("   Make sure you're running on Windows with netsh available.", file=sys.stderr)
        elif profiler.os_type == "Linux":
            print("   Install NetworkManager or ensure nmcli is available.", file=sys.stderr)
            print("   sudo apt-get install network-manager  # Debian/Ubuntu", file=sys.stderr)
            print("   sudo yum install NetworkManager        # RHEL/CentOS", file=sys.stderr)
        elif profiler.os_type == "Darwin":
            print("   Make sure you're running on macOS with security command available.", file=sys.stderr)
        sys.exit(1)
    
    # Check admin privileges
    if not profiler.is_admin():
        print("⚠️  Warning: Not running with administrator/root privileges.", file=sys.stderr)
        if profiler.os_type == "Windows":
            print("   To see passwords, run this script as Administrator.", file=sys.stderr)
        else:
            print("   To see passwords, run this script with sudo.", file=sys.stderr)
        print()
    
    # Get profiles
    print("📡 Retrieving Wi-Fi profiles...")
    try:
        profiles = profiler.get_profiles()
        
        if args.profile:
            # Filter for specific profile
            filtered = [p for p in profiles if p.get("SSID", "").lower() == args.profile.lower()]
            if not filtered:
                print(f"❌ Profile '{args.profile}' not found.", file=sys.stderr)
                sys.exit(1)
            profiles = filtered
        
        if args.no_key:
            for p in profiles:
                p["Key"] = None
        
        if not profiles:
            print("❌ No Wi-Fi profiles found.", file=sys.stderr)
            sys.exit(0)
            
        print(f"✅ Found {len(profiles)} Wi-Fi profile(s)\n")
        
    except Exception as e:
        print(f"❌ Error retrieving profiles: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Prepare output
    if args.format == "table":
        output = profiler.format_table(profiles)
    elif args.format == "json":
        output = json.dumps(profiles, indent=2, ensure_ascii=False)
    elif args.format == "csv":
        if args.output:
            profiler.export_csv(profiles, Path(args.output))
            return
        else:
            if profiles:
                writer = csv.DictWriter(sys.stdout, fieldnames=profiles[0].keys())
                writer.writeheader()
                writer.writerows(profiles)
            return
    
    # Write output
    if args.output:
        out_path = Path(args.output)
        if args.format == "table":
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"✅ Output saved to {out_path}")
        elif args.format == "json":
            profiler.export_json(profiles, out_path)
    else:
        print(output)


if __name__ == "__main__":
    main()