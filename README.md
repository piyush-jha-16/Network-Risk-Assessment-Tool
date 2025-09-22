# Network Risk Assessment Tool
A comprehensive full-stack web application for automated network security assessment and vulnerability scanning on Windows systems. It provides real-time security analytics, interactive threat visualization, and one-click remediation capabilities for system administrators and security professionals. The tool leverages native Windows APIs and PowerShell integration to deliver enterprise-grade security auditing with an intuitive web interface, enabling both technical and non-technical users to identify and address critical security vulnerabilities efficiently.

## Features

### System Information & Vulnerability Overview
- Real-time system configuration analysis
- OS version and security patch assessment  
- Hardware and memory utilization monitoring
- Security vulnerability detection

### Live Port & Service Scanner
- Interactive port scanning with process mapping
- Real-time service discovery and monitoring
- Process ID (PID) to executable correlation
- Risk-level classification for open ports

### Interactive Firewall Rule Manager  
- Complete Windows Firewall rule visualization
- Searchable and sortable rule database
- Risk assessment for each firewall configuration
- Profile-based security analysis (Domain/Private/Public)

### One-Click Security Hardening
- Automated security remediation actions
- Guest account management
- Service disabling capabilities
- Firewall configuration enforcement

### Report Generation
- Comprehensive PDF security reports
- Executive summaries and detailed findings
- Risk scoring and prioritization
- Professional formatting for compliance

## Technology Stack

**Backend:**
- Python 3.8+
- Flask Web Framework
- Windows PowerShell Integration
- Subprocess Management

**Frontend:**
- HTML5, CSS3, JavaScript
- Bootstrap 5.3.0
- DataTables.js for interactive tables
- Font Awesome Icons
- Responsive Design

**Security Features:**
- Windows System API Integration
- Real-time Command Execution
- Security Best Practices Implementation
- Risk Assessment Algorithms
