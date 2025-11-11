from flask import Flask, jsonify, render_template, request
import subprocess
from datetime import datetime
import json
import os
from time import time
from flask import send_file


# Simple in-memory cache
CACHE = {
    "system_info": None,
    "firewall_rules": None,
    "port_scan": None,
    "timestamp": 0
}

CACHE_TTL = 300  # 5 minutes in seconds


app = Flask(__name__)

def run_command(command):
    """Helper function to run a command and return its output."""
    try:
        result = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.STDOUT)
        return result.strip()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"

def parse_system_info(output):
    """Parse the systeminfo command output into a dictionary."""
    info = {}
    lines = output.split('\n')
    
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            
            important_fields = [
                'OS Name', 'OS Version', 'OS Manufacturer', 
                'System Boot Time', 'Hotfix(s)', 'System Type',
                'Total Physical Memory', 'Available Physical Memory'
            ]
            
            if key in important_fields:
                info[key] = value
                
    return info

    
def get_uptime(boot_time_str):
    """Calculate system uptime using multiple reliable methods."""
    try:
        wmic_result = run_command('wmic os get lastbootuptime /format:value')
        if 'LastBootUpTime' in wmic_result:
            for line in wmic_result.split('\n'):
                if 'LastBootUpTime' in line:
                    time_str = line.split('=')[1].strip()
                    # Parse: 20231215143045.500000+000
                    year, month, day = int(time_str[:4]), int(time_str[4:6]), int(time_str[6:8])
                    hour, minute, second = int(time_str[8:10]), int(time_str[10:12]), int(time_str[12:14])
                    boot_time = datetime(year, month, day, hour, minute, second)
                    uptime = datetime.now() - boot_time
                    days = uptime.days
                    hours, remainder = divmod(uptime.seconds, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    return f"{days}d {hours}h {minutes}m"
        
        return "N/A"
        
    except Exception as e:
        return f"Error: {str(e)}"

def check_windows_version_vulnerabilities(os_version):
    """Basic check for well-known Windows vulnerabilities based on version."""
    vulnerabilities = []
    if '10.0.1' in os_version:
        vulnerabilities.append("Outdated Windows 10 version - multiple known vulnerabilities")
    if '6.1' in os_version:  
        vulnerabilities.append("Windows 7 - End of life, critically vulnerable")
    if '6.3' in os_version:  
        vulnerabilities.append("Windows 8.1 - Consider upgrading to Windows 10/11")
    if '19041' in os_version: 
        vulnerabilities.append("Windows 10 2004 - Ensure all latest updates are installed")
    return vulnerabilities

# FIREWALL CHECK
def check_firewall_status():
    """Check if Windows Firewall is enabled for all profiles"""
    try:
        # Run PowerShell command to get firewall status
        command = 'powershell "Get-NetFirewallProfile | Select-Object Name, Enabled"'
        result = run_command(command)
        
        firewall_status = {}
        lines = result.split('\n')
        
        for line in lines:
            if 'True' in line or 'False' in line:
                parts = line.strip().split()
                if len(parts) >= 2:
                    profile_name = parts[0]
                    is_enabled = parts[1] == 'True'
                    firewall_status[profile_name] = is_enabled
        
        return firewall_status
    
    except Exception as e:
        print(f"Firewall check error: {e}")
        return {'error': str(e)}

# REMOTE DESKTOP CHECK
def check_remote_desktop():
    try:
        command = 'powershell "Get-ItemProperty -Path \'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\' -Name fDenyTSConnections | ConvertTo-Json"'
        result = run_command(command)
        parsed = json.loads(result)
        if parsed.get('fDenyTSConnections') == 0:  # 0 means RDP enabled
            return {'enabled': True, 'status': 'Remote Desktop enabled - Medium Risk'}
        else:
            return {'enabled': False, 'status': 'Remote Desktop disabled'}
    except Exception as e:
        return {'error': str(e)}

# GET FIREWALL RULES

def get_firewall_rules():
    """Fetch firewall rules without requiring admin privileges."""
    ps_command = r'''
    $rules = Get-NetFirewallRule | Select-Object `
        Name, DisplayName, Description, Direction, Action, Enabled, Profile
    $rules | ConvertTo-Json -Depth 4
    '''

    command = ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_command]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.stderr.strip():
        print("PowerShell warning:", result.stderr)

    try:
        data = json.loads(result.stdout.strip() or "[]")
        if not isinstance(data, list):
            data = [data]

        # Add safe default values for missing fields
        for rule in data:
            rule.setdefault('Protocol', 'Any')
            rule.setdefault('LocalPort', 'Any')
            rule.setdefault('RemotePort', 'Any')

        return data
    except Exception as e:
        print("JSON error:", e)
        print("Raw output:", result.stdout)
        return []

def analyze_firewall_rule_risk(rule):
    """Analyze risk level for a firewall rule with enum mapping and normalization."""
    risk_level = "Low"
    reasons = []

    # --- Maps for numeric or string enums ---
    direction_map = {
        '1': 'Inbound', '2': 'Outbound',
        'Inbound': 'Inbound', 'Outbound': 'Outbound'
    }
    action_map = {
        '1': 'Block', '2': 'Allow',
        'Block': 'Block', 'Allow': 'Allow'
    }
    profile_map = {
        '1': 'Domain', '2': 'Private', '3': 'Public',
        'Domain': 'Domain', 'Private': 'Private', 'Public': 'Public'
    }

    # --- Normalize fields ---
    direction = direction_map.get(str(rule.get('Direction', '')).strip(), 'Unknown')
    action = action_map.get(str(rule.get('Action', '')).strip(), 'Unknown')
    profile_raw = str(rule.get('Profile', ''))
    profiles = [profile_map.get(p.strip(), p.strip()) for p in profile_raw.split(',')]
    profile_text = ', '.join(profiles)

    enabled_value = str(rule.get('Enabled', '')).strip().lower()
    local_port = str(rule.get('LocalPort', 'any')).strip().lower()

    # --- Skip disabled rules ---
    if enabled_value not in ('true', 'yes', '1'):
        return {'risk_level': 'Low', 'reasons': ['Rule is disabled']}

    # --- Inbound allow rules are risky ---
    if action == 'Allow' and direction == 'Inbound':
        risky_ports = ['3389', '23', '21', '135', '139', '445', '1433']

        if local_port in ('any', '*', '', 'none'):
            risk_level = "High"
            reasons.append("Unrestricted inbound access")

        if any(p in local_port for p in risky_ports):
            risk_level = "Medium"
            reasons.append(f"Risky port exposed ({local_port})")

        if 'public' in profile_text.lower():
            risk_level = "High"
            reasons.append("Public profile inbound rule")

    elif action == 'Allow' and direction == 'Outbound':
        reasons.append("Outbound allowed (generally safe)")

    elif action == 'Block':
        reasons.append("Blocks traffic (safe rule)")

    if not reasons:
        reasons.append("No significant risk factors detected")

    return {'risk_level': risk_level, 'reasons': reasons}

# PORT SCANNING FUNCTION - Added from friend's code
def scan_ports():
    """Enhanced port scanning with better risk assessment"""
    try:
        # Use netstat to get open ports and processes
        command = 'netstat -ano'
        result = run_command(command)
        
        ports_data = []
        lines = result.split('\n')
        
        for line in lines:
            if 'TCP' in line or 'UDP' in line:
                parts = line.strip().split()
                if len(parts) >= 5:
                    protocol = parts[0]
                    local_address = parts[1]
                    state = parts[3] if len(parts) > 3 else 'LISTENING'
                    pid = parts[-1]
                    
                    # Extract port number
                    if ':' in local_address:
                        port = local_address.split(':')[-1]
                        
                        # Get process name from PID
                        process_name = "Unknown"
                        if pid != '0':
                            try:
                                process_cmd = f'tasklist /fi "PID eq {pid}" /fo csv /nh'
                                process_result = run_command(process_cmd)
                                if ',' in process_result:
                                    process_name = process_result.split(',')[0].replace('"', '')
                            except:
                                process_name = "Unknown"
                        
                        # Enhanced risk assessment
                        risk = "Low"
                        risk_description = "Standard service port"
                        
                        # High risk ports
                        high_risk_ports = {
                            '23': 'Telnet - Unencrypted, disable immediately',
                            '21': 'FTP - Plain text credentials',
                            '135': 'RPC - Can be exploited for enumeration',
                            '139': 'NetBIOS - Information disclosure',
                            '445': 'SMB - Vulnerable to worm attacks'
                        }
                        
                        # Medium risk ports
                        medium_risk_ports = {
                            '3389': 'RDP - Ensure strong authentication',
                            '1433': 'SQL Server - Secure configuration needed',
                            '1434': 'SQL Browser - Information disclosure',
                            '5900': 'VNC - Unencrypted by default',
                            '8080': 'HTTP Proxy - Common attack target'
                        }
                        
                        if port in high_risk_ports:
                            risk = "High"
                            risk_description = high_risk_ports[port]
                        elif port in medium_risk_ports:
                            risk = "Medium"
                            risk_description = medium_risk_ports[port]
                        elif port in ['80', '443', '22']:
                            risk = "Low"
                            risk_description = "Standard web/SSH service"
                        
                        ports_data.append({
                            'port': port,
                            'protocol': protocol,
                            'status': state,
                            'process_name': process_name,
                            'pid': pid,
                            'risk': risk,
                            'risk_description': risk_description
                        })
        
        return ports_data[:50]  # Return first 50 results
        
    except Exception as e:
        return {'error': str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/system-info')
def get_system_info():
    try:
        system_info_output = run_command('systeminfo')
        system_info = parse_system_info(system_info_output)

        hotfix_output = run_command('wmic qfe list brief')
        hotfixes = []
        for line in hotfix_output.split('\n'):
            if 'KB' in line:
                parts = line.split()
                if len(parts) >= 3:
                    hotfixes.append({
                        'hotfix_id': parts[0],
                        'description': ' '.join(parts[1:-1]),
                        'installed_on': parts[-1]
                    })

        uptime = get_uptime(system_info.get('System Boot Time', ''))
        firewall_status = check_firewall_status()
        rdp_status = check_remote_desktop()

        risk_findings = []
        if rdp_status.get('enabled', False):
            risk_findings.append(rdp_status.get('status', ''))

        response = {
            'success': True,
            'system_info': system_info,
            'hotfixes': hotfixes[:5],
            'uptime': uptime,
            'firewall_status': firewall_status,
            'rdp_status': rdp_status,
            'risk_findings': risk_findings,
            'total_risks': len(risk_findings),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        CACHE["system_info"] = response
        CACHE["timestamp"] = time()
    except Exception as e:
        response = {'success': False, 'error': str(e)}
    return jsonify(response)

@app.route('/api/firewall-rules')
def get_firewall_rules_api():
    try:
        rules = get_firewall_rules()
        if isinstance(rules, dict) and 'error' in rules:
            return jsonify({'success': False, 'error': rules['error']})
        
        rules_with_risk = []
        for rule in rules:
            risk_analysis = analyze_firewall_rule_risk(rule)

            # ✅ Fix: Normalize Enabled field properly
            enabled_value = str(rule.get('Enabled')).strip().lower()
            if enabled_value in ['true', 'yes', '1']:
                enabled_status = True
            else:
                enabled_status = False

            rules_with_risk.append({
                'name': rule.get('Name', 'N/A'),
                'display_name': rule.get('DisplayName', 'N/A'),
                'description': rule.get('Description', 'N/A'),
                'direction': rule.get('Direction', 'N/A'),
                'action': rule.get('Action', 'N/A'),
                'enabled': enabled_status,  
                'profile': rule.get('Profile', 'N/A'),
                'protocol': rule.get('Protocol', 'N/A'),
                'local_port': rule.get('LocalPort', 'N/A'),
                'remote_port': rule.get('RemotePort', 'N/A'),
                'program': rule.get('Program', 'N/A'),
                'service': rule.get('Service', 'N/A'),
                'risk_level': risk_analysis['risk_level'],
                'risk_reasons': risk_analysis['reasons']
            })

        response = {
            'success': True,
            'rules': rules_with_risk,
            'total_rules': len(rules_with_risk),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    except Exception as e:
        response = {'success': False, 'error': str(e)}
    if response.get("success"):
        CACHE["firewall_rules"] = response
        CACHE["timestamp"] = time()

    return jsonify(response)

# PORT SCAN API ENDPOINT - Added from friend's code
@app.route('/api/port-scan')
def get_port_scan():
    try:
        ports_data = scan_ports()
        
        response = {
            'success': True,
            'ports': ports_data,
            'total_ports': len(ports_data),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    except Exception as e:
        response = {'success': False, 'error': str(e)}
    if response.get("success"):
        CACHE["port_scan"] = response
        CACHE["timestamp"] = time()

    return jsonify(response)

@app.route('/api/firewall-rule/toggle', methods=['POST'])
def toggle_firewall_rule():
    try:
        data = request.get_json()
        rule_name = data.get('rule_name')
        enable = data.get('enable', True)
        
        if not rule_name:
            return jsonify({'success': False, 'error': 'Rule name is required'})
        
        # PowerShell command to enable/disable firewall rule
        action = "Enable" if enable else "Disable"
        command = f'powershell "Set-NetFirewallRule -Name \'{rule_name}\' -Enabled {enable}"'
        
        result = run_command(command)
        
        # Check if the command was successful
        if "Error" not in result:
            return jsonify({
                'success': True, 
                'message': f'Firewall rule {action}d successfully',
                'rule_name': rule_name,
                'enabled': enable
            })
        else:
            return jsonify({'success': False, 'error': result})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})



@app.route('/api/generate-report', methods=['GET'])
def generate_report():
    """Generate and auto-download a full network risk report using cached data if available."""
    try:
        reports_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(reports_dir, exist_ok=True)

        now = time()
        cache_age = now - CACHE["timestamp"]

        # Use cache if fresh (<5 minutes)
        use_cache = cache_age < CACHE_TTL and all([
            CACHE["system_info"],
            CACHE["firewall_rules"],
            CACHE["port_scan"]
        ])

        if use_cache:
            print("Using cached dashboard data for report generation")
            system_data = CACHE["system_info"]
            rules_data = CACHE["firewall_rules"]
            ports_data = CACHE["port_scan"]
        else:
            print("Cache expired — regenerating full data")
            system_data = json.loads(get_system_info().data)
            rules_data = json.loads(get_firewall_rules_api().data)
            ports_data = json.loads(get_port_scan().data)

        # Extract relevant info
        system_info = system_data.get("system_info", {})
        uptime = system_data.get("uptime", "N/A")
        firewall_status = system_data.get("firewall_status", {})
        rdp_status = system_data.get("rdp_status", {})
        firewall_rules = rules_data.get("rules", [])
        ports = ports_data.get("ports", [])

        # Risk summary
        high_risk_rules = sum(1 for r in firewall_rules if r.get("risk_level") == "High")
        high_risk_ports = sum(1 for p in ports if p.get("risk") == "High")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # --- Build report text ---
        report_lines = [
            "=" * 60,
            f"Network Security Risk Report - Generated {timestamp}",
            "=" * 60,
            "",
            "[SYSTEM INFORMATION]",
            f"OS Name: {system_info.get('OS Name', 'N/A')}",
            f"OS Version: {system_info.get('OS Version', 'N/A')}",
            f"System Type: {system_info.get('System Type', 'N/A')}",
            f"Uptime: {uptime}",
            "",
            "[FIREWALL STATUS]",
            json.dumps(firewall_status, indent=4),
            "",
            "[REMOTE DESKTOP STATUS]",
            f"Enabled: {rdp_status.get('enabled', False)}",
            f"Status: {rdp_status.get('status', 'N/A')}",
            "",
            "[SUMMARY]",
            f"Total Firewall Rules: {len(firewall_rules)}",
            f"High-Risk Firewall Rules: {high_risk_rules}",
            f"Total Open Ports: {len(ports)}",
            f"High-Risk Open Ports: {high_risk_ports}",
            "",
            "-" * 60,
            "DETAILED FIREWALL RULE ANALYSIS (All Rules)",
            "-" * 60,
        ]

        # 🔥 Include all firewall rules
        for rule in firewall_rules:
            risk_level = rule.get("risk_level", "N/A")
            risk_reasons = rule.get("risk_reasons", [])
            report_lines.append(
                f"\nRule Name: {rule.get('display_name', rule.get('name', 'N/A'))}\n"
                f"Direction: {rule.get('direction', 'N/A')}\n"
                f"Action: {rule.get('action', 'N/A')}\n"
                f"Profile: {rule.get('profile', 'N/A')}\n"
                f"Enabled: {rule.get('enabled', 'N/A')}\n"
                f"Protocol: {rule.get('protocol', 'N/A')}\n"
                f"Local Ports: {rule.get('local_ports', 'N/A')}\n"
                f"Remote Ports: {rule.get('remote_ports', 'N/A')}\n"
                f"Program: {rule.get('program', 'N/A')}\n"
                f"Service: {rule.get('service', 'N/A')}\n"
                f"Risk Level: {risk_level}\n"
                f"Reasons: {', '.join(risk_reasons)}\n"
                f"{'-'*50}"
            )

        # Ports section
        report_lines.append("\n" + "-" * 60)
        report_lines.append("DETAILED PORT SCAN RESULTS (All Ports)")
        report_lines.append("-" * 60)

        for p in ports:
            report_lines.append(
                f"\nPort: {p.get('port', 'N/A')}\n"
                f"Protocol: {p.get('protocol', 'N/A')}\n"
                f"Process: {p.get('process_name', 'N/A')} (PID: {p.get('pid', 'N/A')})\n"
                f"Status: {p.get('status', 'N/A')}\n"
                f"Risk: {p.get('risk', 'N/A')} - {p.get('risk_description', '')}\n"
                f"{'-'*50}"
            )

        # Write to file
        report_text = "\n".join(report_lines)
        filename = f"network_risk_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
        filepath = os.path.join(reports_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report_text)

        # Auto-download
        return send_file(filepath, as_attachment=True, download_name=filename, mimetype="text/plain")

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Use Render's port
    app.run(host="0.0.0.0", port=port, debug=True)