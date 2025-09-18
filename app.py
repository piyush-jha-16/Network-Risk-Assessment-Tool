from flask import Flask, jsonify, render_template
import subprocess
from datetime import datetime
from platform import platform, version, machine, processor

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
            
            # Only capture important fields
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
        # Parse boot time string (format: 'MM/DD/YYYY, HH:MM:SS AM/PM')
        boot_time = datetime.strptime(boot_time_str, '%m/%d/%Y, %I:%M:%S %p')
        uptime = datetime.now() - boot_time
        
        # Format uptime nicely
        days = uptime.days
        hours, remainder = divmod(uptime.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        return f"{days}d {hours}h {minutes}m"
    except:
        return "Could not calculate"

def check_windows_version_vulnerabilities(os_version):
    """Basic check for well-known Windows vulnerabilities based on version."""
    vulnerabilities = []
    
    # Simple checks based on OS version patterns
    if '10.0.1' in os_version:
        vulnerabilities.append("Outdated Windows 10 version - multiple known vulnerabilities")
    
    if '6.1' in os_version:  # Windows 7
        vulnerabilities.append("Windows 7 - End of life, critically vulnerable")
        
    if '6.3' in os_version:  # Windows 8.1
        vulnerabilities.append("Windows 8.1 - Consider upgrading to Windows 10/11")
    
    # Check for specific build numbers (example)
    if '19041' in os_version:  # Windows 10 2004
        vulnerabilities.append("Windows 10 2004 - Ensure all latest updates are installed")
    
    return vulnerabilities

#FIREWALL CHECK
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

#REMOTE DESKTOP CHECK
def check_remote_desktop():
    """Check if Remote Desktop is enabled"""
    try:
        command = 'powershell "Get-ItemProperty -Path \'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\' -Name fDenyTSConnections"'
        result = run_command(command)
        
        if '0' in result:  # 0 means RDP is enabled
            return {'enabled': True, 'status': 'Remote Desktop enabled - Medium Risk'}
        else:
            return {'enabled': False, 'status': 'Remote Desktop disabled'}
            
    except Exception as e:
        return {'error': str(e)}    

@app.route('/')
def index():
    """Serve the main dashboard page."""
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
        
        # Get all security checks
        uptime = get_uptime(system_info.get('System Boot Time', ''))
        firewall_status = check_firewall_status()
        rdp_status = check_remote_desktop()
        
        # Calculate overall risk score
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
        response = {
            'success': False,
            'error': str(e)
        }
    
    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True, port=5000)