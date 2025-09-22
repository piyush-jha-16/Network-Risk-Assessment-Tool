from flask import Flask, jsonify, render_template
import subprocess
from datetime import datetime
import json

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
    """Calculate system uptime from boot time string."""
    try:
        boot_time = datetime.strptime(boot_time_str, '%m/%d/%Y, %I:%M:%S %p')
        uptime = datetime.now() - boot_time
        days = uptime.days
        hours, remainder = divmod(uptime.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{days}d {hours}h {minutes}m"
    except:
        return "Could not calculate"

def check_windows_version_vulnerabilities(os_version):
    """Basic check for well-known Windows vulnerabilities based on version."""
    vulnerabilities = []
    if '10.0.1' in os_version:
        vulnerabilities.append("Outdated Windows 10 version - multiple known vulnerabilities")
    if '6.1' in os_version:  # Windows 7
        vulnerabilities.append("Windows 7 - End of life, critically vulnerable")
    if '6.3' in os_version:  # Windows 8.1
        vulnerabilities.append("Windows 8.1 - Consider upgrading to Windows 10/11")
    if '19041' in os_version:  # Windows 10 2004
        vulnerabilities.append("Windows 10 2004 - Ensure all latest updates are installed")
    return vulnerabilities

# 🔥 FIREWALL CHECK
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

# 🖥️ REMOTE DESKTOP CHECK
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

# 🔎 GET FIREWALL RULES
def get_firewall_rules():
    try:
        command = (
            'powershell "Get-NetFirewallRule | '
            'Select-Object Name, DisplayName, Description, Direction, Action, Enabled, Profile, '
            '@{Name=\'Protocol\'; Expression={$_.Protocol}}, '
            '@{Name=\'LocalPort\'; Expression={$_.LocalPort}}, '
            '@{Name=\'RemotePort\'; Expression={$_.RemotePort}}, '
            '@{Name=\'Program\'; Expression={$_.Program}}, '
            '@{Name=\'Service\'; Expression={$_.Service}} | '
            'ConvertTo-Json -Depth 3"'
        )
        result = run_command(command)
        rules = json.loads(result)
        if not isinstance(rules, list):
            rules = [rules]
        return rules
    except Exception as e:
        return {'error': str(e)}

def analyze_firewall_rule_risk(rule):
    """Analyze risk level for a firewall rule"""
    risk_level = "Low"
    reasons = []

    enabled_value = str(rule.get('Enabled')).lower()
    if enabled_value == 'true':
        if rule.get('Action') == 'Allow':
            if rule.get('Direction') == 'Inbound':
                if rule.get('LocalPort') in [None, 'Any']:
                    risk_level = "High"
                    reasons.append("Unrestricted inbound access")
                risky_ports = ['3389', '23', '21', '135', '139', '445', '1433']
                if any(port in str(rule.get('LocalPort', '')) for port in risky_ports):
                    risk_level = "Medium"
                    reasons.append("Risky port exposed")
                if 'Public' in str(rule.get('Profile', '')):
                    risk_level = "High"
                    reasons.append("Public profile inbound rule")
    return {'risk_level': risk_level, 'reasons': reasons}

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
                'enabled': enabled_status,  # fixed here
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
    return jsonify(response)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
