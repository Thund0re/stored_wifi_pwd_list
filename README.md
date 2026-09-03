
Usage Examples
On any OS (basic):
# Show specific profile
python wifi_manager.py --profile "MyWiFi"

# Export to JSON
python wifi_manager.py --format json --output profiles.json

# Export to CSV (without passwords)
python wifi_manager.py --format csv --output profiles.csv --no-key

# Table format with all details
python wifi_manager.py --format table


Windows:

    Built-in netsh command

    Run as Administrator to see passwords

Linux:

    Option 1 (Recommended): NetworkManager with nmcli

        Install: sudo apt-get install network-manager (Debian/Ubuntu) or sudo yum install NetworkManager (RHEL/CentOS)

    Option 2: Direct access to /etc/NetworkManager/system-connections/ (requires root)

    Run with sudo to see passwords

macOS:

    Uses security and networksetup commands

    Run with sudo to see passwords


Features

    Cross-platform - Works on Windows, Linux, and macOS

    Automatic OS detection - Uses the right method for each platform

    Multiple output formats - Table, JSON, CSV

    Password retrieval - Shows Wi-Fi passwords (requires admin/root)

    File export - Save results to files

    Profile filtering - View specific profile details

    No-key option - Skip password retrieval for faster results

    ✅ Error handling - Graceful error messages and fallbacks

This script will now work seamlessly on any operating system with the proper dependencies
