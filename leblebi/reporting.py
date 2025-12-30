"""HTML report generation module for Leblebi"""

import os
import base64
import json
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime


class HTMLReportGenerator:
    """Generate HTML security reports for Leblebi"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize report generator"""
        self.config = config
        self.css_styles = self._get_css_styles()
        self.logo_emoji = self._get_logo_emoji()
    
    def _get_logo_emoji(self) -> str:
        """Get logo emoji - try to find logo.png and use leblebi emoji"""
        # Try to find logo.png in common locations to confirm it exists
        possible_paths = [
            Path(__file__).parent.parent / 'logo.png',  # Project root
            Path.cwd() / 'logo.png',  # Current working directory
            Path('/usr/share/leblebi/logo.png'),  # System-wide
            Path.home() / '.leblebi' / 'logo.png',  # User home
        ]
        
        # Check if logo.png exists (we'll use emoji instead of the image)
        logo_exists = False
        for logo_path in possible_paths:
            if logo_path.exists() and logo_path.is_file():
                logo_exists = True
                break
        
        # Use leblebi emoji (🥜) as logo
        # This emoji represents leblebi (peanut/chickpea) perfectly
        return '🥜'
    
    def _get_css_styles(self) -> str:
        """Get CSS styles for enterprise-level interactive report"""
        # Try to load from external CSS file first
        css_path = Path(__file__).parent / 'templates' / 'styles.css'
        if css_path.exists():
            try:
                return css_path.read_text(encoding='utf-8')
            except Exception:
                # Fallback to default CSS if file read fails
                pass
        
        # Fallback: return default CSS (should not normally be reached)
        return """
        * { 
            margin: 0; 
            padding: 0; 
            box-sizing: border-box; 
        }
        
        :root {
            --primary-color: #2563eb;
            --primary-dark: #1e40af;
            --secondary-color: #0f172a;
            --accent-color: #f59e0b;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --danger-color: #ef4444;
            --info-color: #3b82f6;
            --bg-primary: #ffffff;
            --bg-secondary: #f8fafc;
            --bg-tertiary: #f1f5f9;
            --text-primary: #0f172a;
            --text-secondary: #64748b;
            --text-muted: #94a3b8;
            --border-color: #e2e8f0;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
            --shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes slideIn {
            from { transform: translateX(-20px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        
        @keyframes shimmer {
            0% { background-position: -1000px 0; }
            100% { background-position: 1000px 0; }
        }
        
        @keyframes float {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-10px); }
        }
        
        @keyframes gradient {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        
        body {{
            font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #f5f7fa;
            background-attachment: fixed;
            padding: 20px;
            line-height: 1.6;
            color: var(--text-primary);
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }}
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: var(--bg-primary);
            border-radius: 20px;
            box-shadow: var(--shadow-xl);
            overflow: hidden;
            border: 1px solid var(--border-color);
            position: relative;
        }
        
        .container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #667eea, #764ba2, #f093fb, #4facfe);
            background-size: 200% 100%;
        }
        .header {
            background: linear-gradient(135deg, #1E3A5F 0%, #2C5282 100%);
            color: white;
            padding: 15px 25px;
            text-align: center;
            position: relative;
            border-bottom: 3px solid #00A8E8;
        }
        .header h1 {
            font-size: 20px;
            margin-bottom: 3px;
            font-weight: 700;
            letter-spacing: 0.5px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .header .subtitle {
            font-size: 11px;
            opacity: 0.9;
            font-weight: 400;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }
        .pro-badge {
            display: inline-block;
            background: rgba(0, 168, 232, 0.2);
            padding: 3px 10px;
            border-radius: 50px;
            font-size: 9px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 5px;
            border: 1px solid rgba(0, 168, 232, 0.3);
            backdrop-filter: blur(5px);
        }
        .content {
            padding: 40px;
        }
        .greeting {
            font-size: 15px;
            color: #555;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }
        .dashboard-container {
            display: grid;
            grid-template-columns: 280px 1fr;
            gap: 25px;
            margin-bottom: 35px;
        }
        .risk-card {
            background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
            border-radius: 12px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 4px 20px rgba(0,0,0,0.05);
            border: 1px solid #eef0f2;
        }
        .risk-score {
            font-size: 48px;
            font-weight: 800;
            line-height: 1;
            margin: 10px 0;
        }
        .stats-strip {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 15px;
        }
        .kpi-card {
            background: white;
            border-radius: 12px;
            padding: 15px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.03);
            border: 1px solid #f0f2f5;
            text-align: center;
        }
        .kpi-title {
            font-size: 11px;
            text-transform: uppercase;
            color: #64748b;
            letter-spacing: 0.5px;
            font-weight: 700;
            margin-bottom: 5px;
        }
        .kpi-value {
            font-size: 24px;
            font-weight: 800;
            color: #1e293b;
            line-height: 1.2;
        }
        .section {
            margin-bottom: 40px;
            background: #fff;
        }
        .section-title {
            font-size: 18px;
            font-weight: 700;
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 2px solid #eef0f2;
        }
        table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            margin: 20px 0;
            border: 1px solid #eef0f2;
            border-radius: 8px;
            overflow: hidden;
            font-size: 13px;
        }
        table th {
            padding: 16px;
            text-align: left;
            font-weight: 600;
            color: #4a5568;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            background: #f8fafc;
            border-bottom: 1px solid #e2e8f0;
        }
        table td {
            padding: 14px 16px;
            border-bottom: 1px solid #edf2f7;
            color: #2d3748;
        }
        table tbody tr:hover {
            background-color: #f7fafc;
        }
        .level-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }
        .level-low { background: #C6F6D5; color: #22543D; }
        .level-medium { background: #FEEBC8; color: #744210; }
        .level-high { background: #FED7D7; color: #822727; }
        .level-critical { background: #C53030; color: white; }
        .empty-state {
            text-align: center;
            padding: 40px;
            background: #f9fafb;
            border-radius: 8px;
            color: #718096;
            border: 1px dashed #cbd5e0;
        }
        .card {
            background: #fff;
            border-radius: 12px;
            border: 1px solid #e2e8f0;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
            margin-bottom: 30px;
            overflow: hidden;
        }
        .card-header {
            padding: 20px 25px;
            border-bottom: 1px solid #f1f5f9;
            background: #fff;
        }
        .card-header h3 {
            margin: 0;
            font-size: 16px;
            font-weight: 700;
            color: #1e293b;
        }
        .card-body {
            padding: 25px;
        }
        .footer {
            background: #f8fafc;
            padding: 30px;
            text-align: center;
            color: #718096;
            font-size: 12px;
            border-top: 1px solid #e2e8f0;
        }
        .heatmap-grid {
            display: grid;
            grid-template-columns: repeat(12, 1fr);
            gap: 10px;
            margin-top: 15px;
        }
        .heatmap-item {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 12px 6px;
            border-radius: 8px;
            background: #f8fafc;
            border: 1px solid #e2e8f0;
        }
        .hm-0 { background: #f8fafc; color: #94a3b8; }
        .hm-1 { background: #eff6ff; border-color: #bfdbfe; }
        .hm-2 { background: #dbeafe; border-color: #93c5fd; }
        .hm-3 { background: #bfdbfe; border-color: #60a5fa; }
        .hm-4 { background: #fef3c7; border-color: #fcd34d; }
        .hm-5 { background: #fde68a; border-color: #fbbf24; }
        .hm-6 { background: #fee2e2; border-color: #fecaca; }
        .hm-7 { background: #fecaca; border-color: #f87171; }
        .hm-8 { background: #f87171; border-color: #ef4444; color: #fff; }
        .row-critical { background-color: #fef2f2 !important; }
        .row-high { background-color: #fffaf0 !important; }
        .status-badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            margin: 4px 0;
        }
        .status-success { background: #e6fffa; color: #2c7a7b; border: 1px solid #b2f5ea; }
        .status-warning { background: #fffaf0; color: #c05621; border: 1px solid #feebc8; }
        .status-danger { background: #fff5f5; color: #c53030; border: 1px solid #fed7d7; }
        .status-info { background: #ebf8ff; color: #2b6cb0; border: 1px solid #bee3f8; }
        .executive-summary {
            background: #fff;
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 35px;
            border: 1px solid #e2e8f0;
            border-left: 4px solid #2c5364;
        }
        .info-box {
            background: #ebf8ff;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #bee3f8;
            color: #2c5282;
            margin: 20px 0;
        }
        .chart-row {
            display: flex;
            align-items: center;
            margin-bottom: 12px;
            font-size: 13px;
        }
        
        /* Enterprise Interactive Enhancements */
        .header {
            background: linear-gradient(135deg, #1E3A5F 0%, #2C5282 100%);
            position: relative;
            overflow: hidden;
            border-bottom: 3px solid #00A8E8;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(0,168,232,0.1) 0%, transparent 70%);
        }
        
        .header h1 {
            font-size: 20px;
            font-weight: 700;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
            position: relative;
            z-index: 1;
        }
        
        .kpi-card {
            position: relative;
            overflow: hidden;
        }
        
        .kpi-value {
            background: linear-gradient(135deg, #2563eb, #f59e0b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .card {
        }
        
        .card-header {
            cursor: pointer;
        }
        
        table tbody tr {
        }
        
        table tbody tr:hover {
            background-color: #f7fafc;
        }
        
        .level-critical {
        }
        
        .heatmap-item {
            cursor: pointer;
        }
        
        .risk-card {
        }
        
        .risk-score {
            font-size: 72px;
        }
        
        .executive-summary {
        }
        
        
        .section-title {
            font-size: 24px;
            font-weight: 800;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .section-title::after {
            content: '';
            flex: 1;
            height: 3px;
            background: linear-gradient(90deg, var(--primary-color, #2563eb), transparent);
        }
        
        .scroll-top-btn {
            position: fixed;
            bottom: 30px;
            right: 30px;
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            border-radius: 50%;
            cursor: pointer;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s ease;
            z-index: 1000;
            font-size: 20px;
        }
        
        .scroll-top-btn.visible {
            opacity: 1;
            visibility: visible;
        }
        
        .scroll-top-btn:hover {
            transform: translateY(-5px) scale(1.1);
            box-shadow: 0 15px 30px rgba(0,0,0,0.3);
        }
        
        .tooltip {
            position: relative;
            cursor: help;
        }
        
        .tooltip:hover::after {
            content: attr(data-tooltip);
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            padding: 8px 12px;
            background: #1e293b;
            color: white;
            border-radius: 8px;
            font-size: 12px;
            white-space: nowrap;
            z-index: 1000;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            margin-bottom: 5px;
        }
        
        .tooltip:hover::before {
            content: '';
            position: absolute;
            bottom: 95%;
            left: 50%;
            transform: translateX(-50%);
            border: 6px solid transparent;
            border-top-color: #1e293b;
            z-index: 1000;
        }
        
        .progress-bar {
            width: 100%;
            height: 12px;
            background: #f1f5f9;
            border-radius: 10px;
            overflow: hidden;
            position: relative;
            margin: 10px 0;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            border-radius: 10px;
            position: relative;
            overflow: hidden;
        }
        
        @media (max-width: 768px) {
            .content { padding: 25px; }
            .header h1 { font-size: 28px; }
            .dashboard-container { grid-template-columns: 1fr; }
            .stats-strip { grid-template-columns: repeat(2, 1fr); }
        }
        
        @media print {
            body { background: white; }
            .container { box-shadow: none; border: none; }
            .scroll-top-btn { display: none; }
        }
        """
    
    def _build_html_content(self, processor, system_info: Dict[str, Any]) -> str:
        """Build HTML content for report (shared by generate and generate_html_string)"""
        html_parts = []
        
        # Header
        html_parts.append(self._generate_header())
        html_parts.append('<div class="content">')
        
        # Greeting
        html_parts.append(self._generate_greeting())
        
        # Executive Summary (includes all dashboard metrics)
        html_parts.append(self._generate_executive_summary(processor, system_info))
        
        # Hourly Heatmap
        html_parts.append(self._generate_hourly_heatmap(processor))
        
        # SOC Analyst Section
        html_parts.append(self._generate_soc_section(processor))
        
        # User Management
        html_parts.append(self._generate_user_mgmt(processor))
        
        # System Info
        html_parts.append(self._generate_system_info(system_info))
        
        # Critical Alerts
        html_parts.append(self._generate_critical_alerts(processor))
        
        # Non-Critical Alerts
        html_parts.append(self._generate_non_critical_alerts(processor))
        
        # Highest Level Alerts
        html_parts.append(self._generate_highest_alerts(processor))
        
        # Unique Rules
        html_parts.append(self._generate_unique_rules(processor))
        
        # Alert Categories
        html_parts.append(self._generate_alert_categories(processor))
        
        # MITRE ATT&CK
        html_parts.append(self._generate_mitre(processor))
        
        # Windows Event IDs
        html_parts.append(self._generate_windows_events(processor))
        
        # Top Agents
        html_parts.append(self._generate_top_agents(processor))
        
        # Wazuh Status - Removed per user request
        
        # Rule Performance
        html_parts.append(self._generate_rule_performance(processor))
        
        # Threat Intelligence
        html_parts.append(self._generate_threat_intel(processor))
        
        # Timeline Visualizations
        html_parts.append(self._generate_attack_timeline(processor))
        html_parts.append(self._generate_correlation_timeline(processor))
        
        # Advanced API-based Reports (if API is enabled)
        if system_info.get('api_enabled'):
            # Agent Health Monitoring
            html_parts.append(self._generate_agent_health_advanced(system_info))
            
            # Rootcheck Analysis
            html_parts.append(self._generate_rootcheck_analysis(system_info))
            
            # SCA (Security Configuration Assessment) Results
            html_parts.append(self._generate_sca_assessment(system_info))
            
            # Syscheck (FIM) Analysis
            html_parts.append(self._generate_syscheck_analysis(system_info))
            
            # CIS-CAT Compliance Results
            html_parts.append(self._generate_ciscat_compliance(system_info))
            
            # Enhanced Syscollector Information
            html_parts.append(self._generate_syscollector_info(system_info))
            
            # MITRE ATT&CK Enrichment
            if system_info.get('mitre_statistics'):
                html_parts.append(self._generate_mitre_enrichment(system_info))
            
            # APT Activity Detection
            if system_info.get('apt_activities'):
                html_parts.append(self._generate_apt_activity(system_info))
            
            # Vulnerability Detection
            if system_info.get('vulnerability_summary'):
                html_parts.append(self._generate_vulnerability_analysis(system_info))
            
            # CVE Analysis
            if system_info.get('cve_data'):
                html_parts.append(self._generate_cve_analysis(system_info))
            
            # Patch Recommendations
            if system_info.get('patch_recommendations'):
                html_parts.append(self._generate_patch_recommendations(system_info))
        
        # Event Correlation
        if system_info.get('correlated_events'):
            html_parts.append(self._generate_event_correlation(system_info))
        
        # Recommendations
        html_parts.append(self._generate_recommendations(processor, system_info))
        
        # Close content
        html_parts.append('</div>')
        
        # Footer
        html_parts.append(self._generate_footer(processor, system_info))
        
        # Close container
        html_parts.append('</div>')
        html_parts.append('</body>')
        html_parts.append('</html>')
        
        return '\n'.join(html_parts)
    
    def generate(
        self,
        processor,
        system_info: Dict[str, Any],
        output_file: str
    ) -> str:
        """Generate complete HTML report and write to file"""
        html_content = self._build_html_content(processor, system_info)
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file
    
    def generate_html_string(
        self,
        processor,
        system_info: Dict[str, Any]
    ) -> str:
        """Generate HTML report as string (without writing to file)"""
        return self._build_html_content(processor, system_info)
    
    def _generate_header(self) -> str:
        """Generate HTML header with interactive features"""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Leblebi Security Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        {self.css_styles}
    </style>
</head>
<body>
    <button class="scroll-top-btn" id="scrollTopBtn" onclick="window.scrollTo({{top: 0, behavior: 'smooth'}})">↑</button>
    <div class="container">
        <div class="header">
            <div style="display: flex; align-items: center; justify-content: center; gap: 12px; margin-bottom: 5px; position: relative; z-index: 1;">
                {self._get_logo_html()}
                <h1 style="margin: 0; text-shadow: 0 2px 4px rgba(0,0,0,0.3); font-size: 20px; color: #FFFFFF;">Leblebi Security Report</h1>
            </div>
            <div class="subtitle" style="position: relative; z-index: 1; color: #E0F2FE;">Wazuh Security Reports Generator</div>
            <div class="pro-badge" style="position: relative; z-index: 1; margin-top: 8px;">CONFIDENTIAL</div>
        </div>
        <script>
            // Scroll to top button visibility
            window.addEventListener('scroll', function() {{
                const scrollBtn = document.getElementById('scrollTopBtn');
                if (window.pageYOffset > 300) {{
                    scrollBtn.classList.add('visible');
                }} else {{
                    scrollBtn.classList.remove('visible');
                }}
            }});
            
            // Smooth scroll for anchor links
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {{
                anchor.addEventListener('click', function (e) {{
                    e.preventDefault();
                    const target = document.querySelector(this.getAttribute('href'));
                    if (target) {{
                        target.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
                    }}
                }});
            }});
            
            // Collapsible card sections
            document.querySelectorAll('.card-header').forEach(header => {{
                header.addEventListener('click', function() {{
                    const card = this.closest('.card');
                    const body = card.querySelector('.card-body');
                    if (body) {{
                        const isExpanded = card.classList.contains('expanded');
                        if (isExpanded) {{
                            body.style.maxHeight = '0';
                            body.style.overflow = 'hidden';
                            card.classList.remove('expanded');
                        }} else {{
                            body.style.maxHeight = body.scrollHeight + 'px';
                            body.style.overflow = 'visible';
                            card.classList.add('expanded');
                        }}
                    }}
                }});
            }});
            
            // Table row highlight on click
            document.querySelectorAll('table tbody tr').forEach(row => {{
                row.addEventListener('click', function() {{
                    document.querySelectorAll('table tbody tr').forEach(r => r.classList.remove('selected'));
                    this.classList.add('selected');
                }});
            }});
            
            // No number animations - keep static
            
            // Heatmap tooltips
            document.querySelectorAll('.heatmap-item').forEach(item => {{
                item.addEventListener('mouseenter', function(e) {{
                    const title = this.getAttribute('title');
                    if (title) {{
                        this.setAttribute('data-tooltip', title);
                    }}
                }});
            }});
            
            // No animations - keep everything static
        </script>"""
    
    def _get_logo_html(self) -> str:
        """Get logo HTML - use emoji from logo.png file"""
        # Use leblebi emoji with enhanced styling
        emoji_size = "32px"
        return f'''<span style="
            font-size: {emoji_size};
            line-height: {emoji_size};
            display: inline-block;
            filter: drop-shadow(0 2px 4px rgba(0,0,0,0.3));
            text-shadow: 0 1px 2px rgba(0,0,0,0.2);
        ">{self.logo_emoji}</span>'''
    
    def _generate_greeting(self) -> str:
        """Generate greeting section"""
        return """<div class="greeting">
            <p><strong>System Administrator,</strong></p>
            <p>Leblebi provides comprehensive security intelligence and analysis of your Wazuh infrastructure. Please review the critical findings below.</p>
        </div>"""
    
    def _generate_executive_summary(self, processor, system_info: Dict) -> str:
        """Generate executive summary with large colored numbers"""
        risk_score, counts = processor.calculate_risk_score()
        critical_count = counts['critical']
        high_count = counts['high']
        non_critical_count = len(processor.filter_non_critical())
        total_alerts = len(processor.alerts)
        unique_rules = processor.get_unique_rules()
        agent_count = len(set(
            a.get('agent', {}).get('name') or a.get('agent', {}).get('id') or 'Unknown'
            for a in processor.alerts
        ))
        
        # Determine risk level and color
        if risk_score > 150:
            risk_label = "Critical Risk"
            risk_color = "#ef4444"
        elif risk_score > 80:
            risk_label = "High Risk"
            risk_color = "#f97316"
        elif risk_score > 40:
            risk_label = "Medium Risk"
            risk_color = "#f59e0b"
        else:
            risk_label = "Low Risk"
            risk_color = "#10b981"
        
        auth_success, auth_failure = processor.get_auth_summary()
        
        # Helper function to calculate responsive font size based on number length
        def get_font_size(number, base_size=51, min_size=20):
            """Calculate font size based on number length to fit in container"""
            num_str = f"{number:,}"
            num_length = len(num_str)
            
            # Adjust font size based on number of digits
            if num_length <= 3:
                return base_size
            elif num_length <= 5:
                return int(base_size * 0.75)  # 75% of base
            elif num_length <= 7:
                return int(base_size * 0.6)   # 60% of base
            elif num_length <= 9:
                return int(base_size * 0.5)   # 50% of base
            else:
                return max(int(base_size * 0.4), min_size)  # 40% of base, but not less than min_size
        
        # Calculate font sizes for each number
        critical_font = get_font_size(critical_count)
        high_font = get_font_size(high_count)
        non_critical_font = get_font_size(non_critical_count)
        total_font = get_font_size(total_alerts)
        unique_rules_font = get_font_size(unique_rules)
        agent_font = get_font_size(agent_count)
        risk_font = get_font_size(risk_score, base_size=58, min_size=24)
        auth_success_font = get_font_size(auth_success, base_size=38, min_size=20)
        auth_failure_font = get_font_size(auth_failure, base_size=38, min_size=20)
        
        # Get report period information
        report_period_days = system_info.get('report_period_days', 1)
        report_period_label = system_info.get('report_period_label', 'Today')
        report_start_date = system_info.get('report_start_date', '')
        report_end_date = system_info.get('report_end_date', '')
        report_start_time = system_info.get('report_start_time', '')
        report_end_time = system_info.get('report_end_time', '')
        
        # Format time range display
        time_range_info = ""
        if report_start_date and report_end_date:
            if report_start_date == report_end_date:
                time_range_info = f"<strong>Date:</strong> {report_start_date}"
                if report_start_time and report_end_time:
                    time_range_info += f" | <strong>Time Range:</strong> {report_start_time.split()[1]} - {report_end_time.split()[1]}"
            else:
                time_range_info = f"<strong>Date Range:</strong> {report_start_date} to {report_end_date}"
                if report_start_time and report_end_time:
                    time_range_info += f" | <strong>Time:</strong> {report_start_time.split()[1]} - {report_end_time.split()[1]}"
        
        return f"""<div class="executive-summary" style="animation: none !important;">
            <h3 style="margin-top: 0; color: #0f2027; display: flex; align-items: center; gap: 8px; font-size: 22px; font-weight: 800;">
                <span style="font-size: 26px;">📊</span> Executive Summary
            </h3>
            <div style="background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%); padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #0ea5e9;">
                <p style="color: #0c4a6e; margin: 0; font-size: 13px; font-weight: 600;">
                    📅 <strong>Report Period:</strong> {report_period_label} ({report_period_days} day(s)) {time_range_info and '| ' + time_range_info or ''}
                </p>
            </div>
            <p style="color: #4a5568; margin-top: 12px; margin-bottom: 24px; font-size: 13px;">Security telemetry has been analyzed across your infrastructure. The data below represents consolidated findings prioritized by risk severity.</p>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 20px; margin-top: 24px;">
                <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%); border-radius: 13px; border: 2px solid #fecaca; overflow: hidden;">
                    <div style="font-size: 11px; font-weight: 700; color: #991b1b; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Critical Alerts</div>
                    <div style="font-size: {critical_font}px; font-weight: 900; color: #dc2626; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word;">{critical_count:,}</div>
                    <div style="font-size: 10px; color: #991b1b; font-weight: 600;">High Priority Threats</div>
                </div>
                
                <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #fff7ed 0%, #ffedd5 100%); border-radius: 13px; border: 2px solid #fed7aa; overflow: hidden;">
                    <div style="font-size: 11px; font-weight: 700; color: #9a3412; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">High Severity</div>
                    <div style="font-size: {high_font}px; font-weight: 900; color: #ea580c; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word;">{high_count:,}</div>
                    <div style="font-size: 10px; color: #9a3412; font-weight: 600;">Requires Attention</div>
                </div>
                
                <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%); border-radius: 13px; border: 2px solid #e2e8f0; overflow: hidden;">
                    <div style="font-size: 11px; font-weight: 700; color: #475569; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Non-Critical</div>
                    <div style="font-size: {non_critical_font}px; font-weight: 900; color: #64748b; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word;">{non_critical_count:,}</div>
                    <div style="font-size: 10px; color: #475569; font-weight: 600;">Informational</div>
                </div>
                
                <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%); border-radius: 13px; border: 2px solid #bfdbfe; overflow: hidden;">
                    <div style="font-size: 11px; font-weight: 700; color: #1e40af; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Total Events</div>
                    <div style="font-size: {total_font}px; font-weight: 900; color: #2563eb; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word;">{total_alerts:,}</div>
                    <div style="font-size: 10px; color: #1e40af; font-weight: 600;">All Security Events</div>
                </div>
                
                <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #faf5ff 0%, #f3e8ff 100%); border-radius: 13px; border: 2px solid #e9d5ff; overflow: hidden;">
                    <div style="font-size: 11px; font-weight: 700; color: #6b21a8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Unique Rules</div>
                    <div style="font-size: {unique_rules_font}px; font-weight: 900; color: #9333ea; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word;">{unique_rules:,}</div>
                    <div style="font-size: 10px; color: #6b21a8; font-weight: 600;">Security Rules Triggered</div>
                </div>
                
                <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #ecfeff 0%, #cffafe 100%); border-radius: 13px; border: 2px solid #a5f3fc; overflow: hidden;">
                    <div style="font-size: 11px; font-weight: 700; color: #0e7490; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Active Agents</div>
                    <div style="font-size: {agent_font}px; font-weight: 900; color: #0891b2; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word;">{agent_count:,}</div>
                    <div style="font-size: 10px; color: #0e7490; font-weight: 600;">Monitored Systems</div>
                </div>
            </div>
            
            <div style="margin-top: 32px; padding: 20px; background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%); border-radius: 13px; border: 2px solid #e2e8f0; overflow: hidden;">
                <div style="display: flex; align-items: center; justify-content: space-around; flex-wrap: wrap; gap: 24px;">
                    <div style="text-align: center;">
                        <div style="font-size: 11px; font-weight: 700; color: #475569; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">Security Risk Score</div>
                        <div style="font-size: {risk_font}px; font-weight: 900; color: {risk_color}; line-height: 1; margin: 8px 0; word-break: break-word; overflow-wrap: break-word;">{risk_score}</div>
                        <div style="font-size: 13px; font-weight: 700; color: {risk_color}; padding: 6px 16px; background: rgba(0,0,0,0.05); border-radius: 16px; display: inline-block;">{risk_label}</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 11px; font-weight: 700; color: #475569; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">Authentication</div>
                        <div style="display: flex; gap: 24px; margin-top: 12px;">
                            <div>
                                <div style="font-size: 10px; color: #64748b; margin-bottom: 4px;">Success</div>
                                <div style="font-size: {auth_success_font}px; font-weight: 900; color: #10b981; line-height: 1; word-break: break-word; overflow-wrap: break-word;">{auth_success:,}</div>
                            </div>
                            <div>
                                <div style="font-size: 10px; color: #64748b; margin-bottom: 4px;">Failure</div>
                                <div style="font-size: {auth_failure_font}px; font-weight: 900; color: #ef4444; line-height: 1; word-break: break-word; overflow-wrap: break-word;">{auth_failure:,}</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>"""
    
    def _generate_dashboard(self, processor, system_info: Dict) -> str:
        """Generate dashboard with KPIs"""
        risk_score, counts = processor.calculate_risk_score()
        critical_count = counts['critical']
        high_count = counts['high']
        non_critical_count = len(processor.filter_non_critical())
        total_alerts = len(processor.alerts)
        unique_rules = processor.get_unique_rules()
        agent_count = len(set(
            a.get('agent', {}).get('name') or a.get('agent', {}).get('id') or 'Unknown'
            for a in processor.alerts
        ))
        
        # Determine risk level (updated thresholds for more realistic scoring)
        if risk_score > 150:
            risk_level = "risk-critical"
            risk_label = "Critical Risk"
            risk_color = "#ef4444"
        elif risk_score > 80:
            risk_level = "risk-high"
            risk_label = "High Risk"
            risk_color = "#f97316"
        elif risk_score > 40:
            risk_level = "risk-medium"
            risk_label = "Medium Risk"
            risk_color = "#f59e0b"
        else:
            risk_level = "risk-low"
            risk_label = "Low Risk"
            risk_color = "#10b981"
        
        auth_success, auth_failure = processor.get_auth_summary()
        
        return f"""<div class="dashboard-container">
            <div class="risk-card">
                <div style="font-size: 12px; font-weight: 700; color: #94a3b8; letter-spacing: 1px;">SECURITY RISK SCORE</div>
                <div class="risk-score {risk_level}" style="color: {risk_color};">{risk_score}</div>
                <div style="font-size: 16px; font-weight: 600; color: #334155; display: inline-block; padding: 4px 12px; background: rgba(0,0,0,0.05); border-radius: 20px;">{risk_label}</div>
            </div>
            <div class="stats-strip">
                <div class="kpi-card">
                    <div class="kpi-title">Critical Alerts</div>
                    <div class="kpi-value" style="color: #ef4444;">{critical_count}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">High Severity</div>
                    <div class="kpi-value" style="color: #f97316;">{high_count}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Non-Critical</div>
                    <div class="kpi-value" style="color: #64748b;">{non_critical_count}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Total Events</div>
                    <div class="kpi-value" style="color: #0f172a;">{total_alerts}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Unique Rules</div>
                    <div class="kpi-value" style="color: #8b5cf6;">{unique_rules}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Active Agents</div>
                    <div class="kpi-value" style="color: #0ea5e9;">{agent_count}</div>
                </div>
            </div>
        </div>
        <div style="text-align: right; font-size: 12px; color: #94a3b8; margin-top: -20px; margin-bottom: 30px;">
            Auth Success: <span style="color: #10b981;">{auth_success}</span> | Auth Failure: <span style="color: #ef4444;">{auth_failure}</span>
        </div>"""
    
    def _generate_hourly_heatmap(self, processor) -> str:
        """Generate hourly activity heatmap"""
        hourly = processor.get_hourly_distribution()
        if not hourly:
            return ""
        
        max_count = max(hourly.values()) if hourly.values() else 1
        
        heatmap_items = []
        for hour in range(24):
            count = hourly.get(hour, 0)
            intensity = min(8, int((count * 8) / max_count)) if max_count > 0 else 0
            if count > 0 and intensity == 0:
                intensity = 1
            class_name = f"hm-{intensity}"
            heatmap_items.append(
                f'<div class="heatmap-item {class_name}" title="Hour {hour:02d}:00 - {count} events" data-tooltip="Hour {hour:02d}:00 - {count} events">'
                f'<div style="font-size: 11px; color: #64748b; margin-bottom: 8px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px;">{hour:02d}:00</div>'
                f'<div style="font-size: 20px; font-weight: 900; color: #1e293b; text-shadow: 0 1px 2px rgba(0,0,0,0.1);">{count}</div>'
                f'</div>'
            )
        
        return f"""<div class="card">
            <div class="card-header"><span>⏰</span> <h3>24-Hour Activity Heatmap</h3></div>
            <div class="card-body">
                <p style="color: #64748b; font-size: 13px; margin-bottom: 15px;">Peak activity periods visualised by alert volume intensity.</p>
                <div class="heatmap-grid">
                    {''.join(heatmap_items)}
                </div>
            </div>
        </div>"""
    
    def _generate_soc_section(self, processor) -> str:
        """Generate SOC analyst section"""
        top_users = processor.get_top_targeted_users(10)
        top_ips = processor.get_top_source_ips(10)
        
        users_html = ""
        if top_users:
            users_html = "<table style='margin: 0;'><thead><tr><th>User</th><th>Alerts</th></tr></thead><tbody>"
            for count, user in top_users:
                row_class = 'class="row-high"' if count > 50 else ''
                users_html += f'<tr {row_class}><td><strong style="color:#334155;">{user}</strong></td><td><span class="level-badge level-medium">{count}</span></td></tr>'
            users_html += "</tbody></table>"
        else:
            users_html = '<div class="empty-state" style="padding: 15px;">No user data found.</div>'
        
        ips_html = ""
        if top_ips:
            ips_html = "<table style='margin: 0;'><thead><tr><th>Source IP</th><th>Alerts</th></tr></thead><tbody>"
            for count, ip in top_ips:
                row_class = 'class="row-critical"' if count > 20 else ''
                ips_html += f'<tr {row_class}><td><code style="color: #0ea5e9;">{ip}</code></td><td><span class="level-badge level-high">{count}</span></td></tr>'
            ips_html += "</tbody></table>"
        else:
            ips_html = '<div class="empty-state" style="padding: 15px;">No source IP data found.</div>'
        
        return f"""<div class="card">
            <div class="card-header"><span>🕵️</span> <h3>SOC Analyst Threat Focus</h3></div>
            <div class="card-body">
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 30px;">
                    <div>
                        <h4 style="border-bottom: 1px solid #eee; padding-bottom: 8px; margin-bottom: 12px;">👤 Top Targeted Users</h4>
                        {users_html}
                    </div>
                    <div>
                        <h4 style="border-bottom: 1px solid #eee; padding-bottom: 8px; margin-bottom: 12px;">🌐 Top Source IPs</h4>
                        {ips_html}
                    </div>
                </div>
            </div>
        </div>"""
    
    def _generate_user_mgmt(self, processor) -> str:
        """Generate user management section"""
        user_mgmt = processor.get_user_mgmt_alerts(100)
        
        if not user_mgmt:
            return """<div class="section">
            <div class="section-title"><span>👤</span> Windows User Account Activity</div>
            <div class="empty-state">No user account management activity detected.</div>
        </div>"""
        
        rows = []
        for alert in user_mgmt[:100]:
            timestamp = alert.get('timestamp', 'N/A')
            if timestamp != 'N/A':
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                except (ValueError, KeyError, AttributeError):
                    pass
            
            agent = alert.get('agent', {})
            agent_name = agent.get('name') or agent.get('id') or 'Unknown'
            agent_ip = agent.get('ip', 'N/A')
            
            rule = alert.get('rule', {})
            description = rule.get('description', 'N/A')
            
            data = alert.get('data', {})
            win_data = data.get('win', {}).get('eventdata', {})
            target_user = win_data.get('targetUserName') or data.get('dstuser') or 'N/A'
            subject_user = win_data.get('subjectUserName') or data.get('user') or 'N/A'
            
            # Determine text color only (no background)
            text_color = "#64748b"  # Default gray
            if 'created' in description.lower():
                text_color = "#10b981"  # Green
            elif 'deleted' in description.lower():
                text_color = "#ef4444"  # Red
            elif any(kw in description.lower() for kw in ['change', 'modified']):
                text_color = "#f97316"  # Orange
            
            rows.append(
                f'<tr>'
                f'<td>{timestamp}</td>'
                f'<td><strong>{agent_name}</strong></td>'
                f'<td>{agent_ip}</td>'
                f'<td><span style="color: {text_color}; font-weight: 600;">{description}</span></td>'
                f'<td><strong>{target_user}</strong></td>'
                f'<td>{subject_user}</td>'
                f'</tr>'
            )
        
        return f"""<div class="section">
            <div class="section-title"><span>👤</span> Windows User Account Activity</div>
            <p style="margin-bottom: 20px; color: #666;">Details of created, deleted, or modified user accounts.</p>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Agent Name</th>
                        <th>IP Address</th>
                        <th>Activity</th>
                        <th>Target User</th>
                        <th>Performed By</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>"""
    
    def _generate_system_info(self, system_info: Dict) -> str:
        """Generate system information sections"""
        html_parts = []
        
        # Disk Usage
        disk_info = system_info.get('disk_usage', [])
        if disk_info:
            disk_rows = []
            for disk in disk_info:
                use_percent = int(disk.get('use_percent', '0%').rstrip('%'))
                if use_percent > 80:
                    color_class = "level-critical"
                elif use_percent > 60:
                    color_class = "level-high"
                elif use_percent > 40:
                    color_class = "level-medium"
                else:
                    color_class = "level-low"
                
                disk_rows.append(
                    f'<tr>'
                    f'<td>{disk.get("filesystem", "N/A")}</td>'
                    f'<td>{disk.get("size", "N/A")}</td>'
                    f'<td>{disk.get("used", "N/A")}</td>'
                    f'<td>{disk.get("available", "N/A")}</td>'
                    f'<td><span class="level-badge {color_class}">{disk.get("use_percent", "N/A")}</span></td>'
                    f'</tr>'
                )
            
            html_parts.append(f"""<div class="section">
                <div class="section-title"><span>💾</span> Disk Usage</div>
                <table>
                    <thead>
                        <tr>
                            <th>Filesystem</th>
                            <th>Size</th>
                            <th>Used</th>
                            <th>Available</th>
                            <th>Usage %</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(disk_rows)}
                    </tbody>
                </table>
            </div>""")
        
        # Swap Usage
        swap_info = system_info.get('swap_info', {})
        if swap_info:
            html_parts.append(f"""<div class="section">
                <div class="section-title"><span>🔄</span> Swap Usage</div>
                <table>
                    <thead>
                        <tr>
                            <th>Total</th>
                            <th>Used</th>
                            <th>Free</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>{swap_info.get("total", "N/A")}</td>
                            <td>{swap_info.get("used", "N/A")}</td>
                            <td>{swap_info.get("free", "N/A")}</td>
                        </tr>
                    </tbody>
                </table>
            </div>""")
        
        return '\n'.join(html_parts)
    
    def _generate_critical_alerts(self, processor) -> str:
        """Generate critical alerts section"""
        critical_alerts = processor.get_top_alerts_by_rule(
            processor.filter_critical(),
            self.config.get('top_alerts_count', 100)
        )
        
        if not critical_alerts:
            return """<div class="section">
            <div class="section-title"><span>🚨</span> Top Critical Alerts</div>
            <div class="empty-state"><span class="status-badge status-success">✅ No critical alerts found. System is secure!</span></div>
        </div>"""
        
        rows = []
        for count, level, rule_id, desc in critical_alerts:
            # Text color only, no background
            level_color = "#ef4444" if level >= 15 else "#f97316" if level >= 12 else "#f59e0b"
            count_color = "#b91c1c"
            rows.append(
                f'<tr>'
                f'<td><strong style="color: {count_color};">{count}</strong></td>'
                f'<td><span style="color: {level_color}; font-weight: 700; white-space: nowrap;">Level {level}</span></td>'
                f'<td><code>{rule_id}</code></td>'
                f'<td>{desc}</td>'
                f'</tr>'
            )
        
        return f"""<div class="section">
            <div class="section-title"><span>🚨</span> Top Critical Alerts (Level ≥ {self.config.get('level', 12)})</div>
            <p style="margin-bottom: 15px; color: #666;">Summary of most frequent critical security alerts detected.</p>
            <table>
                <thead>
                    <tr>
                        <th>Count</th>
                        <th>Level</th>
                        <th>Rule ID</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>"""
    
    def _generate_non_critical_alerts(self, processor) -> str:
        """Generate non-critical alerts section"""
        non_critical_count = len(processor.filter_non_critical())
        
        return f"""<div class="section">
            <div class="section-title"><span>⚠️</span> Non-Critical Alerts Overview</div>
            <div class="info-box">
                <strong>Total Non-Critical Alerts: </strong> {non_critical_count}<br>
                <small style="color: #666;">Detailed listing omitted for brevity.</small>
            </div>
        </div>"""
    
    def _generate_highest_alerts(self, processor) -> str:
        """Generate highest level alerts section"""
        highest = processor.get_highest_level_alerts(5)
        
        if not highest:
            return """<div class="section">
            <div class="section-title"><span>🔥</span> Highest Severity Alerts</div>
            <div class="empty-state">No high severity alerts found.</div>
        </div>"""
        
        rows = []
        for alert in highest:
            level = processor.get_rule_level(alert)
            rule = alert.get('rule', {})
            rule_id = rule.get('id', 'N/A')
            description = rule.get('description', 'N/A')
            agent = alert.get('agent', {})
            agent_name = agent.get('name') or agent.get('id') or 'Unknown'
            
            # Text color only, no background
            level_color = "#ef4444" if level >= 15 else "#f97316"
            
            rows.append(
                f'<tr>'
                f'<td><span style="color: {level_color}; font-weight: 700; white-space: nowrap;">Level {level}</span></td>'
                f'<td><code>{rule_id}</code></td>'
                f'<td>{description}</td>'
                f'<td><strong>{agent_name}</strong></td>'
                f'</tr>'
            )
        
        return f"""<div class="section">
            <div class="section-title"><span>🔥</span> Highest Severity Alerts</div>
            <p style="margin-bottom: 15px; color: #666;">These are the most severe security events detected and require immediate attention.</p>
            <table>
                <thead>
                    <tr>
                        <th>Severity Level</th>
                        <th>Rule ID</th>
                        <th>Description</th>
                        <th>Affected Agent</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>"""
    
    def _generate_unique_rules(self, processor) -> str:
        """Generate unique rules section"""
        unique_rules = processor.get_top_alerts_by_rule(
            processor.alerts,
            self.config.get('top_alerts_count', 100)
        )
        
        rows = []
        for count, level, rule_id, desc in unique_rules[:self.config.get('top_alerts_count', 100)]:
            # Text color only, no background
            if level >= 12:
                level_color = "#f97316"
            elif level >= 8:
                level_color = "#f59e0b"
            else:
                level_color = "#10b981"
            
            rows.append(
                f'<tr>'
                f'<td><strong>{count}</strong></td>'
                f'<td style="min-width: 80px; white-space: nowrap;"><span style="color: {level_color}; font-weight: 700;">Level {level}</span></td>'
                f'<td><code>{rule_id}</code></td>'
                f'<td>{desc}</td>'
                f'</tr>'
            )
        
        return f"""<div class="section">
            <div class="section-title"><span>📜</span> Unique Rules Triggered</div>
            <table>
                <thead>
                    <tr>
                        <th>Count</th>
                        <th style="min-width: 80px;">Level</th>
                        <th>Rule ID</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>"""
    
    def _generate_alert_categories(self, processor) -> str:
        """Generate alert categories section with modern visualization"""
        categories = processor.get_alert_categories(12)
        
        if not categories:
            return """<div class="card">
            <div class="card-header"><span>📁</span> <h3>Alert Categories Distribution</h3></div>
            <div class="card-body">
                <div class="empty-state">No category data available.</div>
            </div>
        </div>"""
        
        total_count = sum(count for count, _ in categories)
        max_count = categories[0][0] if categories else 1
        
        # Modern color palette (Wazuh-inspired)
        colors = [
            {'bg': '#1E3A5F', 'light': '#2C5282', 'accent': '#00A8E8'},
            {'bg': '#2C5282', 'light': '#3A6BA8', 'accent': '#00A8E8'},
            {'bg': '#1E3A5F', 'light': '#2C5282', 'accent': '#00A8E8'},
            {'bg': '#2C5282', 'light': '#3A6BA8', 'accent': '#00A8E8'},
            {'bg': '#1E3A5F', 'light': '#2C5282', 'accent': '#00A8E8'},
        ]
        
        category_cards = []
        for idx, (count, category) in enumerate(categories):
            color = colors[idx % len(colors)]
            pct = (count / total_count * 100) if total_count > 0 else 0
            bar_pct = (count / max_count * 100) if max_count > 0 else 0
            
            # Truncate long category names
            display_category = category[:30] + '...' if len(category) > 30 else category
            
            category_cards.append(f'''
            <div style="background: linear-gradient(135deg, #FFFFFF 0%, #F8FAFC 100%); border-radius: 12px; padding: 20px; border: 1px solid #E2E8F0; border-left: 4px solid {color['bg']}; transition: all 0.3s ease; box-shadow: 0 2px 8px rgba(0,0,0,0.04);">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 12px;">
                    <div style="flex: 1;">
                        <div style="font-weight: 700; font-size: 14px; color: #1E293B; margin-bottom: 4px;">{display_category}</div>
                        <div style="font-size: 11px; color: #64748B;">{pct:.1f}% of total alerts</div>
                    </div>
                    <div style="text-align: right;">
                        <div style="font-size: 24px; font-weight: 800; color: {color['bg']}; line-height: 1;">{count:,}</div>
                    </div>
                </div>
                <div style="background: #F1F5F9; height: 8px; border-radius: 10px; overflow: hidden; position: relative;">
                    <div style="background: linear-gradient(90deg, {color['bg']}, {color['light']}); height: 100%; width: {bar_pct:.1f}%; border-radius: 10px; transition: width 0.5s ease; box-shadow: 0 2px 4px rgba(0,0,0,0.1);"></div>
                </div>
            </div>
            ''')
        
        return f"""<div class="card">
            <div class="card-header"><span>📁</span> <h3>Alert Categories Distribution</h3></div>
            <div class="card-body">
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px;">
                    {''.join(category_cards)}
                </div>
            </div>
        </div>"""
    
    def _generate_mitre(self, processor) -> str:
        """Generate MITRE ATT&CK section with modern visualization"""
        tactics = processor.get_mitre_tactics(12)
        
        if not tactics:
            return """<div class="card">
            <div class="card-header"><span>🛡️</span> <h3>MITRE ATT&CK Tactics</h3></div>
            <div class="card-body">
                <div class="empty-state">No MITRE data available.</div>
            </div>
        </div>"""
        
        total_count = sum(count for count, _ in tactics)
        max_count = tactics[0][0] if tactics else 1
        
        # MITRE ATT&CK color scheme (red/orange for threats)
        mitre_colors = [
            {'primary': '#DC2626', 'secondary': '#EF4444', 'light': '#FEE2E2'},
            {'primary': '#EA580C', 'secondary': '#F97316', 'light': '#FFEDD5'},
            {'primary': '#DC2626', 'secondary': '#EF4444', 'light': '#FEE2E2'},
            {'primary': '#EA580C', 'secondary': '#F97316', 'light': '#FFEDD5'},
            {'primary': '#DC2626', 'secondary': '#EF4444', 'light': '#FEE2E2'},
        ]
        
        tactic_items = []
        for idx, (count, tactic) in enumerate(tactics):
            color = mitre_colors[idx % len(mitre_colors)]
            pct = (count / total_count * 100) if total_count > 0 else 0
            bar_pct = (count / max_count * 100) if max_count > 0 else 0
            
            # Truncate long tactic names
            display_tactic = tactic[:35] + '...' if len(tactic) > 35 else tactic
            
            tactic_items.append(f'''
            <div style="display: flex; align-items: center; gap: 16px; padding: 16px; background: linear-gradient(135deg, #FFFFFF 0%, {color['light']}15 100%); border-radius: 10px; border: 1px solid #E2E8F0; border-left: 4px solid {color['primary']}; transition: all 0.3s ease; margin-bottom: 12px;">
                <div style="flex-shrink: 0; width: 48px; height: 48px; background: linear-gradient(135deg, {color['primary']}, {color['secondary']}); border-radius: 10px; display: flex; align-items: center; justify-content: center; color: white; font-weight: 800; font-size: 16px; box-shadow: 0 4px 8px {color['primary']}40;">
                    {count}
                </div>
                <div style="flex: 1; min-width: 0;">
                    <div style="font-weight: 600; font-size: 14px; color: #1E293B; margin-bottom: 6px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{display_tactic}</div>
                    <div style="background: #F1F5F9; height: 6px; border-radius: 10px; overflow: hidden; position: relative;">
                        <div style="background: linear-gradient(90deg, {color['primary']}, {color['secondary']}); height: 100%; width: {bar_pct:.1f}%; border-radius: 10px; transition: width 0.5s ease;"></div>
                    </div>
                    <div style="font-size: 11px; color: #64748B; margin-top: 4px;">{pct:.1f}% of total tactics</div>
                </div>
            </div>
            ''')
        
        return f"""<div class="card">
            <div class="card-header"><span>🛡️</span> <h3>MITRE ATT&CK Tactics</h3></div>
            <div class="card-body">
                <div style="max-height: 600px; overflow-y: auto; padding-right: 8px;">
                    {''.join(tactic_items)}
                </div>
            </div>
        </div>"""
    
    def _generate_windows_events(self, processor) -> str:
        """Generate Windows Event IDs section with modern visualization"""
        from leblebi.windows_events import get_event_description
        
        event_ids = processor.get_windows_event_ids(12)
        
        if not event_ids:
            return ""
        
        total_count = sum(count for count, _ in event_ids)
        max_count = event_ids[0][0] if event_ids else 1
        
        # Windows Event ID color scheme (blue/purple for Windows)
        windows_colors = [
            {'primary': '#1E3A5F', 'secondary': '#2C5282', 'accent': '#00A8E8', 'light': '#E0F2FE'},
            {'primary': '#2C5282', 'secondary': '#3A6BA8', 'accent': '#00A8E8', 'light': '#DBEAFE'},
            {'primary': '#1E3A5F', 'secondary': '#2C5282', 'accent': '#00A8E8', 'light': '#E0F2FE'},
            {'primary': '#2C5282', 'secondary': '#3A6BA8', 'accent': '#00A8E8', 'light': '#DBEAFE'},
            {'primary': '#1E3A5F', 'secondary': '#2C5282', 'accent': '#00A8E8', 'light': '#E0F2FE'},
        ]
        
        event_items = []
        for idx, (count, eid) in enumerate(event_ids):
            color = windows_colors[idx % len(windows_colors)]
            desc = get_event_description(eid)
            pct = (count / total_count * 100) if total_count > 0 else 0
            bar_pct = (count / max_count * 100) if max_count > 0 else 0
            
            # Truncate long descriptions
            display_desc = desc[:40] + '...' if len(desc) > 40 else desc
            
            event_items.append(f'''
            <div style="display: flex; align-items: center; gap: 16px; padding: 18px; background: linear-gradient(135deg, #FFFFFF 0%, {color['light']} 100%); border-radius: 12px; border: 1px solid #E2E8F0; border-left: 4px solid {color['primary']}; transition: all 0.3s ease; margin-bottom: 12px; box-shadow: 0 2px 6px rgba(0,0,0,0.04);">
                <div style="flex-shrink: 0; width: 56px; height: 56px; background: linear-gradient(135deg, {color['primary']}, {color['secondary']}); border-radius: 12px; display: flex; flex-direction: column; align-items: center; justify-content: center; color: white; font-weight: 800; box-shadow: 0 4px 12px {color['primary']}40;">
                    <div style="font-size: 10px; opacity: 0.9;">ID</div>
                    <div style="font-size: 18px; line-height: 1;">{eid}</div>
                </div>
                <div style="flex: 1; min-width: 0;">
                    <div style="font-weight: 600; font-size: 14px; color: #1E293B; margin-bottom: 8px;">{display_desc}</div>
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <div style="flex: 1; background: #F1F5F9; height: 8px; border-radius: 10px; overflow: hidden; position: relative;">
                            <div style="background: linear-gradient(90deg, {color['primary']}, {color['accent']}); height: 100%; width: {bar_pct:.1f}%; border-radius: 10px; transition: width 0.5s ease; box-shadow: 0 2px 4px rgba(0,0,0,0.1);"></div>
                        </div>
                        <div style="font-size: 20px; font-weight: 800; color: {color['primary']}; min-width: 60px; text-align: right;">{count:,}</div>
                    </div>
                    <div style="font-size: 11px; color: #64748B; margin-top: 6px;">{pct:.1f}% of total events</div>
                </div>
            </div>
            ''')
        
        return f"""<div class="card">
            <div class="card-header"><span>🪟</span> <h3>Top Windows Event IDs</h3></div>
            <div class="card-body">
                <div style="max-height: 600px; overflow-y: auto; padding-right: 8px;">
                    {''.join(event_items)}
                </div>
            </div>
        </div>"""
    
    def _generate_top_agents(self, processor) -> str:
        """Generate top agents section with visual charts"""
        top_agents = processor.get_top_agents(self.config.get('top_alerts_count', 100))
        
        if not top_agents:
            return """<div class="section">
            <div class="section-title"><span>🤖</span> Top Alerting Agents</div>
            <div class="empty-state">No agents reported any alerts.</div>
        </div>"""
        
        max_count = top_agents[0][0] if top_agents else 1
        
        agent_cards = []
        for rank, (count, agent_name) in enumerate(top_agents[:10], 1):  # Top 10
            # Determine color based on count
            if count > 100:
                bar_color = "#ef4444"
                text_color = "#ef4444"
            elif count > 50:
                bar_color = "#f97316"
                text_color = "#f97316"
            elif count > 20:
                bar_color = "#f59e0b"
                text_color = "#f59e0b"
            else:
                bar_color = "#10b981"
                text_color = "#10b981"
            
            pct = (count / max_count * 100) if max_count > 0 else 0
            
            # Medal emoji for top 3
            medal = "🥇" if rank == 1 else "🥈" if rank == 2 else "🥉" if rank == 3 else f"#{rank}"
            
            agent_cards.append(
                f'<div style="margin-bottom: 20px; padding: 20px; background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%); border-radius: 16px; border: 2px solid {bar_color}33; box-shadow: 0 4px 12px rgba(0,0,0,0.08);">'
                f'<div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 15px;">'
                f'<div style="display: flex; align-items: center; gap: 15px;">'
                f'<span style="font-size: 32px; filter: drop-shadow(0 2px 4px rgba(0,0,0,0.2));">{medal}</span>'
                f'<strong style="font-size: 18px; color: #1e293b; font-weight: 800;">{agent_name}</strong>'
                f'</div>'
                f'<span style="font-size: 24px; font-weight: 900; color: {text_color}; text-shadow: 0 2px 4px {bar_color}33;">{count:,}</span>'
                f'</div>'
                f'<div style="background: #f1f5f9; height: 16px; border-radius: 10px; overflow: hidden; box-shadow: inset 0 2px 4px rgba(0,0,0,0.1); position: relative;">'
                f'<div class="progress-fill" style="width: {pct:.1f}%; height: 100%; background: linear-gradient(90deg, {bar_color}, {bar_color}dd); border-radius: 10px;"></div>'
                f'</div>'
                f'</div>'
            )
        
        return f"""<div class="card">
            <div class="card-header"><span>🤖</span> <h3>Top Alerting Agents</h3></div>
            <div class="card-body">
                <p style="color: #64748b; font-size: 13px; margin-bottom: 20px;">Agents generating the most security alerts. High alert counts may indicate compromised systems or misconfigured agents.</p>
                {''.join(agent_cards)}
            </div>
        </div>"""
    
    def _generate_wazuh_status(self, system_info: Dict, processor) -> str:
        """Generate Wazuh status section"""
        wazuh_version = system_info.get('wazuh_version', 'Unknown')
        agent_count = system_info.get('agent_count', 0)
        active_agents = len(set(
            a.get('agent', {}).get('name') or a.get('agent', {}).get('id') or 'Unknown'
            for a in processor.alerts
        ))
        
        return f"""<div class="card">
            <div class="card-header"><span>🛡️</span> <h3>Wazuh Manager Status</h3></div>
            <div class="card-body">
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px;">
                    <div class="kpi-card">
                        <div class="kpi-title">Manager Status</div>
                        <div class="kpi-value" style="color: #10b981;">✅ Running</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-title">Wazuh Version</div>
                        <div class="kpi-value" style="color: #0ea5e9;">{wazuh_version}</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-title">Total Agents</div>
                        <div class="kpi-value" style="color: #8b5cf6;">{agent_count}</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-title">Active Agents</div>
                        <div class="kpi-value" style="color: #10b981;">{active_agents}</div>
                    </div>
                </div>
            </div>
        </div>"""
    
    def _generate_rule_performance(self, processor) -> str:
        """Generate rule performance section"""
        rule_perf = processor.get_top_alerts_by_rule(processor.alerts, 15)
        
        if not rule_perf:
            return """<div class="card">
            <div class="card-header"><span>⚡</span> <h3>Wazuh Rule Performance Analysis</h3></div>
            <div class="card-body">
                <div class="empty-state">No rule performance data available.</div>
            </div>
        </div>"""
        
        rows = []
        for count, level, rule_id, desc in rule_perf:
            # Text color only, no background
            if level >= 12:
                level_color = "#f97316"
            elif level >= 8:
                level_color = "#f59e0b"
            else:
                level_color = "#10b981"
            
            count_color = "#ef4444" if count > 100 else "#64748b"
            
            rows.append(
                f'<tr>'
                f'<td><strong style="color: {count_color};">{count}</strong></td>'
                f'<td><code>{rule_id}</code></td>'
                f'<td style="min-width: 80px; white-space: nowrap;"><span style="color: {level_color}; font-weight: 700;">Level {level}</span></td>'
                f'<td>{desc}</td>'
                f'</tr>'
            )
        
        return f"""<div class="card">
            <div class="card-header"><span>⚡</span> <h3>Wazuh Rule Performance Analysis</h3></div>
            <div class="card-body">
                <p style="color: #64748b; font-size: 13px; margin-bottom: 15px;">Most frequently triggered security rules.</p>
                <table style="margin: 0;">
                    <thead>
                        <tr>
                            <th>Trigger Count</th>
                            <th>Rule ID</th>
                            <th>Severity</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>"""
    
    def _generate_threat_intel(self, processor) -> str:
        """Generate threat intelligence section"""
        html_parts = ['<div class="card">']
        html_parts.append('<div class="card-header"><span>🔍</span> <h3>Advanced Threat Intelligence</h3></div>')
        html_parts.append('<div class="card-body">')
        
        has_data = False
        
        # CVE Alerts
        cve_alerts = []
        try:
            cve_alerts = processor.get_cve_alerts(10)
            if cve_alerts and len(cve_alerts) > 0:
                has_data = True
                rows = []
                for count, cve_data in cve_alerts:
                    cve = cve_data.get('cve', 'N/A')
                    desc = cve_data.get('description', 'N/A')
                    level = cve_data.get('level', 0)
                    level_color = "#ef4444" if level >= 12 else "#f97316"
                    rows.append(
                        f'<tr>'
                        f'<td><strong style="color: #ef4444;">{count}</strong></td>'
                        f'<td><code style="color: #dc2626;">{cve}</code></td>'
                        f'<td style="min-width: 80px; white-space: nowrap;"><span style="color: {level_color}; font-weight: 700;">Level {level}</span></td>'
                        f'<td>{desc}</td>'
                        f'</tr>'
                    )
                
                html_parts.append('<h4 style="margin-bottom: 15px;">🔴 CVE-Related Alerts</h4>')
                html_parts.append('<table style="margin: 0;"><thead><tr><th>Count</th><th>CVE ID</th><th>Severity</th><th>Description</th></tr></thead><tbody>')
                html_parts.extend(rows)
                html_parts.append('</tbody></table>')
        except Exception as e:
            html_parts.append(f'<p style="color: #999; font-size: 12px;">CVE alerts processing error: {str(e)}</p>')
        
        # Malware Alerts
        malware_alerts = []
        try:
            malware_alerts = processor.get_malware_alerts(5)
            if malware_alerts and len(malware_alerts) > 0:
                has_data = True
                rows = []
                for count, malware_data in malware_alerts:
                    rule_id = malware_data.get('rule_id', 'N/A')
                    desc = malware_data.get('description', 'N/A')
                    level = malware_data.get('level', 0)
                    level_color = "#ef4444"
                    rows.append(
                        f'<tr>'
                        f'<td><strong style="color: #ef4444;">{count}</strong></td>'
                        f'<td><code>{rule_id}</code></td>'
                        f'<td style="min-width: 80px; white-space: nowrap;"><span style="color: {level_color}; font-weight: 700;">Level {level}</span></td>'
                        f'<td>{desc}</td>'
                        f'</tr>'
                    )
                
                html_parts.append('<h4 style="margin-top: 25px; margin-bottom: 15px;">🦠 Malware Detection Alerts</h4>')
                html_parts.append('<table style="margin: 0;"><thead><tr><th>Count</th><th>Rule ID</th><th>Severity</th><th>Description</th></tr></thead><tbody>')
                html_parts.extend(rows)
                html_parts.append('</tbody></table>')
        except Exception as e:
            html_parts.append(f'<p style="color: #999; font-size: 12px;">Malware alerts processing error: {str(e)}</p>')
        
        # Intrusion Alerts
        intrusion_alerts = []
        try:
            intrusion_alerts = processor.get_intrusion_alerts(5)
            if intrusion_alerts and len(intrusion_alerts) > 0:
                has_data = True
                rows = []
                for count, intrusion_data in intrusion_alerts:
                    rule_id = intrusion_data.get('rule_id', 'N/A')
                    desc = intrusion_data.get('description', 'N/A')
                    level = intrusion_data.get('level', 0)
                    level_color = "#f97316"
                    rows.append(
                        f'<tr>'
                        f'<td><strong style="color: #f97316;">{count}</strong></td>'
                        f'<td><code>{rule_id}</code></td>'
                        f'<td style="min-width: 80px; white-space: nowrap;"><span style="color: {level_color}; font-weight: 700;">Level {level}</span></td>'
                        f'<td>{desc}</td>'
                        f'</tr>'
                    )
                
                html_parts.append('<h4 style="margin-top: 25px; margin-bottom: 15px;">🚨 Intrusion Detection Alerts</h4>')
                html_parts.append('<table style="margin: 0;"><thead><tr><th>Count</th><th>Rule ID</th><th>Severity</th><th>Description</th></tr></thead><tbody>')
                html_parts.extend(rows)
                html_parts.append('</tbody></table>')
        except Exception as e:
            html_parts.append(f'<p style="color: #999; font-size: 12px;">Intrusion alerts processing error: {str(e)}</p>')
        
        if not has_data:
            html_parts.append('<div class="empty-state">No advanced threat intelligence data available in this report period.</div>')
        
        html_parts.append('</div></div>')
        return '\n'.join(html_parts)
    
    def _generate_mitre_enrichment(self, system_info: Dict) -> str:
        """Generate MITRE ATT&CK enrichment section"""
        mitre_stats = system_info.get('mitre_statistics', {})
        
        if not mitre_stats or (mitre_stats.get('total_techniques', 0) == 0 and 
                               mitre_stats.get('total_tactics', 0) == 0 and 
                               mitre_stats.get('total_groups', 0) == 0):
            return '''
        <div class="section">
            <div class="card">
                <div class="card-header">
                    <h3>🛡️ MITRE ATT&CK Framework Analysis</h3>
                </div>
                <div class="card-body">
                    <div class="info-box">
                        <strong>No MITRE ATT&CK data found:</strong> The alerts in this report period do not contain MITRE ATT&CK mappings. 
                        This is normal if your Wazuh rules don't have MITRE technique/tactic mappings configured. 
                        To enable MITRE enrichment, ensure your Wazuh rules include MITRE ATT&CK framework mappings.
                    </div>
                </div>
            </div>
        </div>
        '''
        
        top_techniques = mitre_stats.get('top_techniques', [])[:10]
        top_tactics = mitre_stats.get('top_tactics', [])[:10]
        top_groups = mitre_stats.get('top_groups', [])[:10]
        
        techniques_html = ''
        for tech_id, count in top_techniques:
            techniques_html += f'<tr><td style="padding: 10px;"><code>{tech_id}</code></td><td style="padding: 10px;"><strong>{count}</strong></td></tr>'
        
        tactics_html = ''
        for tactic_id, count in top_tactics:
            tactics_html += f'<tr><td style="padding: 10px;"><code>{tactic_id}</code></td><td style="padding: 10px;"><strong>{count}</strong></td></tr>'
        
        groups_html = ''
        for group_id, count in top_groups:
            groups_html += f'<tr><td style="padding: 10px;"><code>{group_id}</code></td><td style="padding: 10px;"><strong>{count}</strong></td></tr>'
        
        # Get MITRE statistics
        total_techniques = mitre_stats.get('total_techniques', 0)
        total_tactics = mitre_stats.get('total_tactics', 0)
        total_groups = mitre_stats.get('total_groups', 0)
        
        # Helper function to calculate responsive font size based on number length
        def get_font_size(number, base_size=51, min_size=20):
            """Calculate font size based on number length to fit in container"""
            num_str = f"{number:,}"
            num_length = len(num_str)
            
            # Adjust font size based on number of digits
            if num_length <= 3:
                return base_size
            elif num_length <= 5:
                return int(base_size * 0.75)  # 75% of base
            elif num_length <= 7:
                return int(base_size * 0.6)   # 60% of base
            elif num_length <= 9:
                return int(base_size * 0.5)   # 50% of base
            else:
                return max(int(base_size * 0.4), min_size)  # 40% of base, but not less than min_size
        
        # Calculate font sizes for each number
        techniques_font = get_font_size(total_techniques)
        tactics_font = get_font_size(total_tactics)
        groups_font = get_font_size(total_groups)
        
        return f'''
        <div class="section">
            <div class="card">
                <div class="card-header">
                    <h3>🛡️ MITRE ATT&CK Framework Analysis</h3>
                </div>
                <div class="card-body">
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 20px; margin-bottom: 25px;">
                        <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #faf5ff 0%, #f3e8ff 100%); border-radius: 13px; border: 2px solid #e9d5ff; overflow: hidden;">
                            <div style="font-size: 11px; font-weight: 700; color: #6b21a8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Techniques Detected</div>
                            <div style="font-size: {techniques_font}px; font-weight: 900; color: #9333ea; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word;">{total_techniques:,}</div>
                            <div style="font-size: 10px; color: #6b21a8; font-weight: 600;">Attack Techniques</div>
                        </div>
                        
                        <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%); border-radius: 13px; border: 2px solid #bfdbfe; overflow: hidden;">
                            <div style="font-size: 11px; font-weight: 700; color: #1e40af; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Tactics Identified</div>
                            <div style="font-size: {tactics_font}px; font-weight: 900; color: #2563eb; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word;">{total_tactics:,}</div>
                            <div style="font-size: 10px; color: #1e40af; font-weight: 600;">Attack Tactics</div>
                        </div>
                        
                        <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%); border-radius: 13px; border: 2px solid #fecaca; overflow: hidden;">
                            <div style="font-size: 11px; font-weight: 700; color: #991b1b; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">APT Groups</div>
                            <div style="font-size: {groups_font}px; font-weight: 900; color: #ef4444; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word;">{total_groups:,}</div>
                            <div style="font-size: 10px; color: #991b1b; font-weight: 600;">Threat Groups</div>
                        </div>
                    </div>
                    
                    {f'''
                    <h4 style="margin-top: 25px; margin-bottom: 15px; color: #1e293b;">Top MITRE Techniques</h4>
                    <table>
                        <thead><tr><th>Technique ID</th><th>Alert Count</th></tr></thead>
                        <tbody>{techniques_html}</tbody>
                    </table>
                    ''' if top_techniques else ''}
                    
                    {f'''
                    <h4 style="margin-top: 25px; margin-bottom: 15px; color: #1e293b;">Top MITRE Tactics</h4>
                    <table>
                        <thead><tr><th>Tactic ID</th><th>Alert Count</th></tr></thead>
                        <tbody>{tactics_html}</tbody>
                    </table>
                    ''' if top_tactics else ''}
                    
                    {f'''
                    <h4 style="margin-top: 25px; margin-bottom: 15px; color: #1e293b;">Related APT Groups</h4>
                    <table>
                        <thead><tr><th>Group ID</th><th>Alert Count</th></tr></thead>
                        <tbody>{groups_html}</tbody>
                    </table>
                    ''' if top_groups else ''}
                </div>
            </div>
        </div>
        '''
    
    def _generate_apt_activity(self, system_info: Dict) -> str:
        """Generate APT activity detection section"""
        apt_activities = system_info.get('apt_activities', [])
        
        if not apt_activities:
            return ''
        
        activities_html = ''
        for idx, activity in enumerate(apt_activities[:10], 1):
            techniques_str = ', '.join(activity.get('techniques', [])[:5])
            if len(activity.get('techniques', [])) > 5:
                techniques_str += f' (+{len(activity.get("techniques", [])) - 5} more)'
            
            activities_html += f'''
            <div style="padding: 20px; background: linear-gradient(135deg, #fff5f5 0%, #fed7d7 100%); border-radius: 12px; border-left: 4px solid #ef4444; margin-bottom: 15px;">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px;">
                    <div>
                        <h4 style="margin: 0; color: #1e293b;">{activity.get('group_name', 'Unknown APT Group')}</h4>
                        <div style="font-size: 12px; color: #64748b; margin-top: 5px;">
                            Group ID: <code>{activity.get('group_id', 'N/A')}</code>
                        </div>
                    </div>
                    <div style="background: #ef4444; color: white; padding: 8px 16px; border-radius: 6px; font-weight: 700;">
                        {activity.get('alert_count', 0)} alerts
                    </div>
                </div>
                <div style="margin-top: 15px;">
                    <div style="font-size: 12px; color: #64748b; margin-bottom: 5px;"><strong>Techniques Used:</strong></div>
                    <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                        {''.join([f'<span style="background: white; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 600;">{t}</span>' for t in activity.get('techniques', [])[:10]])}
                    </div>
                </div>
                {f'<div style="margin-top: 10px;"><a href="{activity.get("group_url", "#")}" target="_blank" style="color: #2563eb; text-decoration: none; font-size: 12px;">View on MITRE ATT&CK →</a></div>' if activity.get('group_url') else ''}
            </div>
            '''
        
        return f'''
        <div class="section">
            <div class="card">
                <div class="card-header">
                    <h3>🎯 APT Group Activity Detection</h3>
                </div>
                <div class="card-body">
                    <div class="info-box">
                        <strong>⚠️ Potential APT Activity Detected:</strong> {len(apt_activities)} APT group(s) identified based on MITRE technique patterns.
                    </div>
                    {activities_html}
                </div>
            </div>
        </div>
        '''
    
    def _generate_vulnerability_analysis(self, system_info: Dict) -> str:
        """Generate vulnerability analysis section with Executive Summary style boxes"""
        vuln_summary = system_info.get('vulnerability_summary', {})
        
        if not vuln_summary or not vuln_summary.get('enabled'):
            return ''
        
        # Get vulnerability counts
        total_agents_checked = vuln_summary.get('total_agents_checked', 0)
        agents_with_vulns = vuln_summary.get('agents_with_vulnerabilities', 0)
        total_vulnerabilities = vuln_summary.get('total_vulnerabilities', 0)
        critical_vulns = vuln_summary.get('critical_vulnerabilities', 0)
        high_vulns = vuln_summary.get('high_vulnerabilities', 0)
        medium_vulns = vuln_summary.get('medium_vulnerabilities', 0)
        low_vulns = vuln_summary.get('low_vulnerabilities', 0)
        
        # Helper function to calculate responsive font size based on number length
        def get_font_size(number, base_size=51, min_size=20):
            """Calculate font size based on number length to fit in container"""
            num_str = f"{number:,}"
            num_length = len(num_str)
            
            # Adjust font size based on number of digits
            if num_length <= 3:
                return base_size
            elif num_length <= 5:
                return int(base_size * 0.75)  # 75% of base
            elif num_length <= 7:
                return int(base_size * 0.6)   # 60% of base
            elif num_length <= 9:
                return int(base_size * 0.5)   # 50% of base
            else:
                return max(int(base_size * 0.4), min_size)  # 40% of base, but not less than min_size
        
        # Calculate font sizes for each number
        agents_checked_font = get_font_size(total_agents_checked)
        agents_with_vulns_font = get_font_size(agents_with_vulns)
        total_vulns_font = get_font_size(total_vulnerabilities)
        critical_font = get_font_size(critical_vulns)
        high_font = get_font_size(high_vulns) if high_vulns > 0 else 51
        medium_font = get_font_size(medium_vulns) if medium_vulns > 0 else 51
        
        agents_vuln_html = ''
        for agent_vuln in vuln_summary.get('vulnerabilities_by_agent', [])[:10]:
            agents_vuln_html += f'''
            <tr>
                <td style="padding: 10px;"><strong>{agent_vuln.get('agent_name', 'N/A')}</strong><br><span style="font-size: 11px; color: #64748b;">ID: {agent_vuln.get('agent_id', 'N/A')}</span></td>
                <td style="padding: 10px;"><span style="color: #ef4444; font-weight: 700; font-size: 18px;">{agent_vuln.get('total_failed_checks', 0)}</span></td>
                <td style="padding: 10px;"><span style="color: #10b981; font-weight: 700;">{agent_vuln.get('total_passed_checks', 0)}</span></td>
                <td style="padding: 10px;">{len(agent_vuln.get('policies', []))}</td>
            </tr>
            '''
        
        return f'''
        <div class="section">
            <div class="card">
                <div class="card-header">
                    <h3>🔍 Vulnerability Detection Summary</h3>
                </div>
                <div class="card-body">
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 20px; margin-bottom: 25px;">
                        <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%); border-radius: 13px; border: 2px solid #bfdbfe; overflow: hidden;">
                            <div style="font-size: 11px; font-weight: 700; color: #1e40af; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Agents Checked</div>
                            <div style="font-size: {agents_checked_font}px; font-weight: 900; color: #2563eb; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word;">{total_agents_checked:,}</div>
                            <div style="font-size: 10px; color: #1e40af; font-weight: 600;">Total Monitored</div>
                        </div>
                        
                        <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #fff7ed 0%, #ffedd5 100%); border-radius: 13px; border: 2px solid #fed7aa; overflow: hidden;">
                            <div style="font-size: 11px; font-weight: 700; color: #9a3412; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Agents with Vulns</div>
                            <div style="font-size: {agents_with_vulns_font}px; font-weight: 900; color: #ea580c; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word;">{agents_with_vulns:,}</div>
                            <div style="font-size: 10px; color: #9a3412; font-weight: 600;">Affected Systems</div>
                        </div>
                        
                        <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%); border-radius: 13px; border: 2px solid #fecaca; overflow: hidden;">
                            <div style="font-size: 11px; font-weight: 700; color: #991b1b; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Total Vulnerabilities</div>
                            <div style="font-size: {total_vulns_font}px; font-weight: 900; color: #ef4444; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word;">{total_vulnerabilities:,}</div>
                            <div style="font-size: 10px; color: #991b1b; font-weight: 600;">All Severities</div>
                        </div>
                        
                        <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%); border-radius: 13px; border: 2px solid #dc2626; overflow: hidden;">
                            <div style="font-size: 11px; font-weight: 700; color: #fecaca; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Critical</div>
                            <div style="font-size: {critical_font}px; font-weight: 900; color: #dc2626; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word; text-shadow: 0 1px 2px rgba(0,0,0,0.1);">{critical_vulns:,}</div>
                            <div style="font-size: 10px; color: #fecaca; font-weight: 600;">Immediate Action</div>
                        </div>
                    </div>
                    
                    {(f'''
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 20px; margin-bottom: 25px; margin-top: 20px;">
                        <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #fff7ed 0%, #ffedd5 100%); border-radius: 13px; border: 2px solid #fed7aa; overflow: hidden;">
                            <div style="font-size: 11px; font-weight: 700; color: #9a3412; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">High</div>
                            <div style="font-size: {high_font}px; font-weight: 900; color: #ea580c; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word;">{high_vulns:,}</div>
                            <div style="font-size: 10px; color: #9a3412; font-weight: 600;">High Priority</div>
                        </div>
                        
                        <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #fefce8 0%, #fef9c3 100%); border-radius: 13px; border: 2px solid #fde047; overflow: hidden;">
                            <div style="font-size: 11px; font-weight: 700; color: #854d0e; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Medium</div>
                            <div style="font-size: {medium_font}px; font-weight: 900; color: #ca8a04; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word;">{medium_vulns:,}</div>
                            <div style="font-size: 10px; color: #854d0e; font-weight: 600;">Medium Priority</div>
                        </div>
                    </div>
                    ''' if (high_vulns > 0 or medium_vulns > 0) else '')}
                    
                    <h4 style="margin-top: 25px; margin-bottom: 15px; color: #1e293b;">Vulnerabilities by Agent</h4>
                    <table>
                        <thead><tr><th>Agent</th><th>Failed Checks</th><th>Passed Checks</th><th>Policies Affected</th></tr></thead>
                        <tbody>{agents_vuln_html}</tbody>
                    </table>
                </div>
            </div>
        </div>
        '''
    
    def _generate_cve_analysis(self, system_info: Dict) -> str:
        """Generate CVE analysis section"""
        cve_data = system_info.get('cve_data', {})
        
        if not cve_data or cve_data.get('total_cve_alerts', 0) == 0:
            return ''
        
        top_cves_html = ''
        for cve, count in cve_data.get('top_cves', [])[:15]:
            top_cves_html += f'<tr><td style="padding: 10px;"><code>{cve}</code></td><td style="padding: 10px;"><strong>{count}</strong></td></tr>'
        
        return f'''
        <div class="section">
            <div class="card">
                <div class="card-header">
                    <h3>📋 CVE Analysis</h3>
                </div>
                <div class="card-body">
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 25px;">
                        <div class="kpi-card">
                            <div class="kpi-title">CVE Alerts</div>
                            <div class="kpi-value">{cve_data.get('total_cve_alerts', 0)}</div>
                        </div>
                        <div class="kpi-card">
                            <div class="kpi-title">Unique CVEs</div>
                            <div class="kpi-value">{cve_data.get('total_unique_cves', 0)}</div>
                        </div>
                    </div>
                    
                    <h4 style="margin-top: 25px; margin-bottom: 15px; color: #1e293b;">Top CVEs by Alert Count</h4>
                    <table>
                        <thead><tr><th>CVE ID</th><th>Alert Count</th></tr></thead>
                        <tbody>{top_cves_html}</tbody>
                    </table>
                </div>
            </div>
        </div>
        '''
    
    def _generate_patch_recommendations(self, system_info: Dict) -> str:
        """Generate patch recommendations section"""
        recommendations = system_info.get('patch_recommendations', [])
        
        if not recommendations:
            return ''
        
        recs_html = ''
        priority_colors = {
            'critical': '#ef4444',
            'high': '#f97316',
            'medium': '#f59e0b',
            'low': '#64748b'
        }
        
        for rec in recommendations[:20]:
            priority = rec.get('priority', 'low')
            color = priority_colors.get(priority, '#64748b')
            policy_details = rec.get('policy_details', [])
            
            # Build policy details HTML
            policy_details_html = ''
            if policy_details:
                for policy in policy_details:
                    policy_details_html += f'''
                    <div style="padding: 10px; background: white; border-radius: 6px; margin-bottom: 8px; border-left: 3px solid {color};">
                        <div style="font-weight: 600; color: #1e293b; margin-bottom: 5px;">{policy.get('name', 'Unknown Policy')}</div>
                        <div style="font-size: 11px; color: #64748b;">
                            Failed: <strong style="color: #ef4444;">{policy.get('failed_checks', 0)}</strong> | 
                            Passed: <strong style="color: #10b981;">{policy.get('passed_checks', 0)}</strong>
                        </div>
                    </div>
                    '''
            
            recs_html += f'''
            <div style="padding: 15px; background: #f8fafc; border-radius: 8px; border-left: 4px solid {color}; margin-bottom: 15px;">
                <div style="display: flex; justify-content: space-between; align-items: start;">
                    <div style="flex: 1;">
                        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 5px;">
                            <span style="background: {color}; color: white; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase;">{priority}</span>
                            <strong style="color: #1e293b; font-size: 14px;">{rec.get('agent_name', 'N/A')}</strong>
                        </div>
                        <div style="font-size: 12px; color: #64748b; margin-top: 5px; margin-bottom: 10px;">
                            {rec.get('recommendation', '')}
                        </div>
                        <div style="font-size: 11px; color: #94a3b8; margin-bottom: 10px;">
                            Failed Checks: <strong>{rec.get('failed_checks', 0)}</strong> | Policies Affected: <strong>{rec.get('policies_affected', 0)}</strong>
                        </div>
                        {f'''
                        <div style="margin-top: 10px;">
                            <div style="font-size: 11px; font-weight: 600; color: #64748b; margin-bottom: 8px; text-transform: uppercase;">Affected Policies:</div>
                            {policy_details_html}
                        </div>
                        ''' if policy_details_html else ''}
                    </div>
                </div>
            </div>
            '''
        
        return f'''
        <div class="section">
            <div class="card">
                <div class="card-header">
                    <h3>🔧 Patch Priority Recommendations</h3>
                </div>
                <div class="card-body">
                    <div class="info-box">
                        <strong>Priority-based patch recommendations</strong> based on vulnerability analysis. Focus on critical and high priority items first.
                    </div>
                    {recs_html}
                </div>
            </div>
        </div>
        '''
    
    def _generate_event_correlation(self, system_info: Dict) -> str:
        """Generate event correlation section"""
        correlated_events = system_info.get('correlated_events', [])
        
        if not correlated_events:
            return ''
        
        # Use existing correlation timeline generation if available
        # Otherwise create a simplified version
        correlation_html = ''
        for idx, group in enumerate(correlated_events[:10], 1):
            events = group.get('events', [])
            
            # Build events table with descriptions
            events_rows = ''
            for event in events[:10]:  # Show first 10 events
                level = event.get('level', 0)
                level_color = '#ef4444' if level >= 15 else '#f97316' if level >= 12 else '#f59e0b'
                description = event.get('description', 'N/A')
                if len(description) > 80:
                    description = description[:80] + '...'
                
                rule_id = event.get('rule_id', 'N/A')
                agent_name = event.get('agent_name', 'N/A')
                src_ip = event.get('src_ip', 'N/A')
                
                # Format timestamp
                timestamp = event.get('timestamp', '')
                time_str = 'N/A'
                if timestamp:
                    try:
                        if 'T' in timestamp:
                            time_str = timestamp.split('T')[1].split('.')[0] if '.' in timestamp else timestamp.split('T')[1]
                        else:
                            time_str = timestamp
                    except (ValueError, KeyError, AttributeError):
                        time_str = timestamp[:19] if len(timestamp) > 19 else timestamp
                
                events_rows += f'''
                <tr style="border-bottom: 1px solid #e2e8f0;">
                    <td style="padding: 10px; font-size: 11px; color: #64748b;">{time_str}</td>
                    <td style="padding: 10px;"><span style="color: {level_color}; font-weight: 700; font-size: 12px;">{level}</span></td>
                    <td style="padding: 10px; font-size: 12px; color: #1e293b;"><strong>{description}</strong></td>
                    <td style="padding: 10px; font-size: 11px;"><code>{rule_id}</code></td>
                    <td style="padding: 10px; font-size: 11px; color: #64748b;">{agent_name}</td>
                    <td style="padding: 10px; font-size: 11px; color: #64748b;">{src_ip}</td>
                </tr>
                '''
            
            # Get correlation keys
            correlation_keys = group.get('correlation_keys', {})
            keys_html = ''
            for key, value in correlation_keys.items():
                if value and value != 'N/A':
                    keys_html += f'<span style="background: white; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-right: 8px;"><strong>{key}:</strong> {value}</span>'
            
            correlation_html += f'''
            <div style="padding: 20px; background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%); border-radius: 12px; border: 2px solid #e2e8f0; border-left: 4px solid #3b82f6; margin-bottom: 20px;">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 15px;">
                    <div>
                        <h4 style="margin: 0 0 10px 0; color: #1e293b;">Correlation Group #{idx}</h4>
                        <div style="font-size: 12px; color: #64748b;">
                            <strong>{group.get('event_count', 0)}</strong> correlated events | 
                            Duration: <strong>{group.get('duration_minutes', 0):.1f}</strong> minutes
                        </div>
                    </div>
                    <div style="background: #3b82f6; color: white; padding: 8px 16px; border-radius: 6px; font-weight: 700; font-size: 18px;">
                        {group.get('event_count', 0)}
                    </div>
                </div>
                
                {f'''
                <div style="margin-bottom: 15px; padding: 12px; background: #f1f5f9; border-radius: 8px;">
                    <div style="font-size: 11px; color: #64748b; margin-bottom: 5px; font-weight: 600;">CORRELATION KEYS</div>
                    <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                        {keys_html}
                    </div>
                </div>
                ''' if keys_html else ''}
                
                <div style="font-size: 12px; color: #64748b; margin-bottom: 15px;">
                    <strong>Time Range:</strong> {group.get('start_time', 'N/A')} - {group.get('end_time', 'N/A')}
                </div>
                
                {f'''
                <div style="max-height: 300px; overflow-y: auto;">
                    <table style="width: 100%; font-size: 11px; border-collapse: collapse;">
                        <thead>
                            <tr style="background: #f8fafc; border-bottom: 2px solid #e2e8f0;">
                                <th style="padding: 10px; text-align: left; font-weight: 600; color: #64748b;">Time</th>
                                <th style="padding: 10px; text-align: left; font-weight: 600; color: #64748b;">Level</th>
                                <th style="padding: 10px; text-align: left; font-weight: 600; color: #64748b;">Description</th>
                                <th style="padding: 10px; text-align: left; font-weight: 600; color: #64748b;">Rule ID</th>
                                <th style="padding: 10px; text-align: left; font-weight: 600; color: #64748b;">Agent</th>
                                <th style="padding: 10px; text-align: left; font-weight: 600; color: #64748b;">Source IP</th>
                            </tr>
                        </thead>
                        <tbody>
                            {events_rows}
                        </tbody>
                    </table>
                </div>
                ''' if events_rows else '<div style="padding: 20px; text-align: center; color: #94a3b8;">No event details available</div>'}
            </div>
            '''
        
        return f'''
        <div class="section">
            <div class="card">
                <div class="card-header">
                    <h3>🔗 Event Correlation Analysis</h3>
                </div>
                <div class="card-body">
                    <div class="info-box">
                        <strong>Correlated Security Events:</strong> {len(correlated_events)} event group(s) detected with shared correlation keys (IP, agent, rule).
                    </div>
                    {correlation_html}
                </div>
            </div>
        </div>
        '''
    
    def _generate_recommendations(self, processor, system_info: Dict) -> str:
        """Generate security recommendations based on report analysis"""
        risk_score, counts = processor.calculate_risk_score()
        critical_count = counts['critical']
        high_count = counts['high']
        medium_count = counts['medium']
        total_alerts = len(processor.alerts)
        ubuntu_updates = system_info.get('system_updates', 0)
        agent_count = system_info.get('agent_count', 0)
        
        recommendations = []
        priority_level = "LOW"
        
        # Determine priority level
        if critical_count > 0:
            priority_level = "CRITICAL"
        elif high_count > 10 or risk_score > 150:
            priority_level = "HIGH"
        elif high_count > 0 or risk_score > 80:
            priority_level = "MEDIUM"
        
        # Critical alerts recommendations
        if critical_count > 0:
            recommendations.append(f"""
            <div style="background: #fef2f2; border-left: 4px solid #ef4444; padding: 15px; margin-bottom: 15px; border-radius: 4px;">
                <p style="margin: 0 0 10px 0; font-weight: 700; color: #991b1b; font-size: 14px;">⚠️ IMMEDIATE ACTIONS REQUIRED - Priority: CRITICAL</p>
                <ul style="margin: 0; padding-left: 20px; color: #7f1d1d;">
                    <li>Review and investigate all <strong>{critical_count} critical alerts</strong> immediately - these represent the highest severity threats</li>
                    <li>Verify the integrity of affected systems and check for signs of active compromise or data exfiltration</li>
                    <li>Review firewall rules and network access controls for suspicious activity patterns</li>
                    <li>Isolate affected systems if indicators of compromise (IOCs) are confirmed</li>
                    <li>Document all findings and escalate to incident response team if necessary</li>
                </ul>
            </div>""")
        
        # High severity recommendations
        if high_count > 0:
            recommendations.append(f"""
            <div style="background: #fff7ed; border-left: 4px solid #f97316; padding: 15px; margin-bottom: 15px; border-radius: 4px;">
                <p style="margin: 0 0 10px 0; font-weight: 700; color: #9a3412; font-size: 14px;">🔍 INVESTIGATION NEEDED - {high_count} High Severity Alerts</p>
                <ul style="margin: 0; padding-left: 20px; color: #7c2d12;">
                    <li>Investigate <strong>{high_count} high severity alerts</strong> within 24 hours - these may indicate security policy violations or potential threats</li>
                    <li>Review alert patterns to identify common sources, IP addresses, or user accounts</li>
                    <li>Check for correlation between high severity alerts and critical alerts</li>
                    <li>Update security policies if recurring patterns indicate configuration issues</li>
                </ul>
            </div>""")
        
        # Risk score recommendations
        if risk_score > 150:
            recommendations.append(f"""
            <div style="background: #fef2f2; border-left: 4px solid #dc2626; padding: 15px; margin-bottom: 15px; border-radius: 4px;">
                <p style="margin: 0 0 10px 0; font-weight: 700; color: #991b1b; font-size: 14px;">📊 ELEVATED RISK SCORE: {risk_score}</p>
                <ul style="margin: 0; padding-left: 20px; color: #7f1d1d;">
                    <li>Current risk score of <strong>{risk_score}</strong> indicates CRITICAL security concerns requiring immediate attention</li>
                    <li>Conduct a comprehensive security audit of systems generating the most alerts</li>
                    <li>Review and update security policies, monitoring rules, and access controls</li>
                    <li>Consider implementing additional security controls or increasing monitoring frequency</li>
                </ul>
            </div>""")
        elif risk_score > 80:
            recommendations.append(f"""
            <div style="background: #fff7ed; border-left: 4px solid #f97316; padding: 15px; margin-bottom: 15px; border-radius: 4px;">
                <p style="margin: 0 0 10px 0; font-weight: 700; color: #9a3412; font-size: 14px;">📊 ELEVATED RISK SCORE: {risk_score}</p>
                <ul style="margin: 0; padding-left: 20px; color: #7c2d12;">
                    <li>Current risk score of <strong>{risk_score}</strong> indicates elevated security concerns</li>
                    <li>Conduct a thorough security audit of systems generating the most alerts</li>
                    <li>Review and update security policies and monitoring rules</li>
                </ul>
            </div>""")
        
        # System updates
        if ubuntu_updates > 0:
            recommendations.append(f"""
            <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin-bottom: 15px; border-radius: 4px;">
                <p style="margin: 0 0 10px 0; font-weight: 700; color: #92400e; font-size: 14px;">🔄 SYSTEM MAINTENANCE REQUIRED</p>
                <ul style="margin: 0; padding-left: 20px; color: #78350f;">
                    <li><strong>{ubuntu_updates} system updates</strong> are available. Apply security patches promptly to address known vulnerabilities</li>
                    <li>Prioritize security-related updates and patches</li>
                    <li>Schedule maintenance windows for non-critical updates</li>
                    <li>Test updates in a staging environment before production deployment</li>
                </ul>
            </div>""")
        
        # Agent health
        if agent_count == 0:
            recommendations.append(f"""
            <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin-bottom: 15px; border-radius: 4px;">
                <p style="margin: 0 0 10px 0; font-weight: 700; color: #92400e; font-size: 14px;">🤖 AGENT MONITORING</p>
                <ul style="margin: 0; padding-left: 20px; color: #78350f;">
                    <li>No active agents detected in this report period. Verify agent connectivity and Wazuh manager configuration</li>
                    <li>Check agent registration status and network connectivity</li>
                </ul>
            </div>""")
        
        # Volume-based recommendations
        if total_alerts > 100000:
            recommendations.append(f"""
            <div style="background: #eff6ff; border-left: 4px solid #3b82f6; padding: 15px; margin-bottom: 15px; border-radius: 4px;">
                <p style="margin: 0 0 10px 0; font-weight: 700; color: #1e40af; font-size: 14px;">📈 HIGH ALERT VOLUME</p>
                <ul style="margin: 0; padding-left: 20px; color: #1e3a8a;">
                    <li>Processing <strong>{total_alerts:,} alerts</strong> in this period. Consider tuning alert rules to reduce noise and focus on actionable security events</li>
                    <li>Review and optimize Wazuh rules to reduce false positives</li>
                    <li>Implement alert correlation and aggregation to reduce alert fatigue</li>
                </ul>
            </div>""")
        
        # Positive status
        if critical_count == 0 and high_count == 0 and risk_score < 40:
            recommendations.append(f"""
            <div style="background: #f0fdf4; border-left: 4px solid #10b981; padding: 15px; margin-bottom: 15px; border-radius: 4px;">
                <p style="margin: 0 0 10px 0; font-weight: 700; color: #065f46; font-size: 14px;">✅ SYSTEM STATUS: HEALTHY</p>
                <ul style="margin: 0; padding-left: 20px; color: #047857;">
                    <li>No critical or high severity alerts detected. System security posture appears healthy</li>
                    <li>Continue monitoring and maintain current security practices</li>
                    <li>Regular security reviews and updates are still recommended</li>
                </ul>
            </div>""")
        
        # General recommendations (always include)
        recommendations.append(f"""
            <div style="background: #f8fafc; border-left: 4px solid #64748b; padding: 15px; margin-bottom: 15px; border-radius: 4px;">
                <p style="margin: 0 0 10px 0; font-weight: 700; color: #475569; font-size: 14px;">ℹ️ GENERAL SECURITY BEST PRACTICES</p>
                <ul style="margin: 0; padding-left: 20px; color: #334155;">
                    <li>Continue regular monitoring and review of security alerts on a daily basis</li>
                    <li>Keep Wazuh manager and agents up to date with latest security patches</li>
                    <li>Review and tune alert rules periodically to reduce false positives and improve detection accuracy</li>
                    <li>Document security incidents and maintain an incident response playbook</li>
                    <li>Conduct regular security awareness training for staff</li>
                    <li>Perform periodic security assessments and penetration testing</li>
                </ul>
            </div>""")
        
        return f"""<div class="section">
            <div class="section-title"><span>💡</span> Security Recommendations</div>
            <div class="recommendations" style="padding: 20px; background: #ffffff; border-radius: 8px;">
                <p style="color: #64748b; font-size: 13px; margin-bottom: 20px;">The following recommendations are based on automated analysis of your security telemetry. Priority level: <strong>{priority_level}</strong></p>
                {''.join(recommendations)}
            </div>
        </div>"""
    
    def _generate_footer(self, processor, system_info: Dict) -> str:
        """Generate footer section"""
        report_date = datetime.now().strftime('%B %d, %Y at %H:%M:%S %Z')
        total_alerts = len(processor.alerts)
        unique_rules = processor.get_unique_rules()
        wazuh_version = system_info.get('wazuh_version', 'Unknown')
        report_period = system_info.get('report_period', '1d')
        report_period_days = system_info.get('report_period_days', 1)
        report_period_label = system_info.get('report_period_label', 'Today')
        
        # Format report type with days
        if report_period_days == 1:
            report_type = f"Daily ({report_period_days} day)"
        else:
            report_type = f"{report_period_label} ({report_period_days} days)"
        
        return f"""<div class="footer">
            <p><strong>📧 Automated Security Report</strong></p>
            <p>Generated by Leblebi - Wazuh Security Reports Generator on {report_date}</p>
            <p style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #dee2e6;">
                <strong>Report Type:</strong> {report_type} | 
                <strong>Total Events Analyzed:</strong> {total_alerts:,} | 
                <strong>Unique Security Rules:</strong> {unique_rules}
            </p>
            <p style="margin-top: 10px; color: #999; font-size: 11px;">
                For questions, concerns, or to report false positives, please contact your security team.<br>
                This report is generated automatically by Leblebi and should be reviewed by qualified security personnel.
            </p>
        </div>"""
    
    def _generate_agent_health_advanced(self, system_info: Dict) -> str:
        """Generate advanced agent health section using API data"""
        api_data = system_info.get('api_data', {})
        agent_summary = api_data.get('agent_summary', {})
        disconnected = api_data.get('disconnected_agents', [])
        critical_agents = api_data.get('critical_agents', [])
        agents_by_version = api_data.get('agents_by_version', {})
        agents_by_os = api_data.get('agents_by_os', {})
        
        if not agent_summary.get('enabled'):
            return ""
        
        # Summary KPIs
        total = agent_summary.get('total', 0)
        active = agent_summary.get('active', 0)
        disconnected_count = agent_summary.get('disconnected', 0)
        health_pct = agent_summary.get('health_percentage', 0)
        
        # Helper function to calculate responsive font size based on number length
        def get_font_size(number, base_size=51, min_size=20):
            """Calculate font size based on number length to fit in container"""
            num_str = f"{number:,}"
            num_length = len(num_str)
            
            # Adjust font size based on number of digits
            if num_length <= 3:
                return base_size
            elif num_length <= 5:
                return int(base_size * 0.75)  # 75% of base
            elif num_length <= 7:
                return int(base_size * 0.6)   # 60% of base
            elif num_length <= 9:
                return int(base_size * 0.5)   # 50% of base
            else:
                return max(int(base_size * 0.4), min_size)  # 40% of base, but not less than min_size
        
        # Calculate font sizes for each number
        total_font = get_font_size(total)
        active_font = get_font_size(active)
        disconnected_font = get_font_size(disconnected_count)
        health_font = get_font_size(int(health_pct), base_size=45, min_size=20)
        
        # Determine health color
        if health_pct > 80:
            health_color = "#10b981"
            health_bg = "linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%)"
            health_border = "#86efac"
            health_text = "#166534"
        elif health_pct > 50:
            health_color = "#f97316"
            health_bg = "linear-gradient(135deg, #fff7ed 0%, #ffedd5 100%)"
            health_border = "#fed7aa"
            health_text = "#9a3412"
        else:
            health_color = "#ef4444"
            health_bg = "linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%)"
            health_border = "#fecaca"
            health_text = "#991b1b"
        
        html_parts = ['<div class="card">']
        html_parts.append('<div class="card-header"><span>🤖</span> <h3>Advanced Agent Health Monitoring</h3></div>')
        html_parts.append('<div class="card-body">')
        
        html_parts.append('<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 20px; margin-bottom: 25px;">')
        
        # Total Agents
        html_parts.append(f'''
            <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%); border-radius: 13px; border: 2px solid #bfdbfe; overflow: hidden;">
                <div style="font-size: 11px; font-weight: 700; color: #1e40af; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Total Agents</div>
                <div style="font-size: {total_font}px; font-weight: 900; color: #2563eb; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word;">{total:,}</div>
                <div style="font-size: 10px; color: #1e40af; font-weight: 600;">All Agents</div>
            </div>
        ''')
        
        # Active Agents
        html_parts.append(f'''
            <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%); border-radius: 13px; border: 2px solid #86efac; overflow: hidden;">
                <div style="font-size: 11px; font-weight: 700; color: #166534; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Active</div>
                <div style="font-size: {active_font}px; font-weight: 900; color: #10b981; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word;">{active:,}</div>
                <div style="font-size: 10px; color: #166534; font-weight: 600;">Online Agents</div>
            </div>
        ''')
        
        # Disconnected Agents
        html_parts.append(f'''
            <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%); border-radius: 13px; border: 2px solid #fecaca; overflow: hidden;">
                <div style="font-size: 11px; font-weight: 700; color: #991b1b; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Disconnected</div>
                <div style="font-size: {disconnected_font}px; font-weight: 900; color: #ef4444; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word;">{disconnected_count:,}</div>
                <div style="font-size: 10px; color: #991b1b; font-weight: 600;">Offline Agents</div>
            </div>
        ''')
        
        # Health Percentage
        html_parts.append(f'''
            <div style="text-align: center; padding: 20px; background: {health_bg}; border-radius: 13px; border: 2px solid {health_border}; overflow: hidden;">
                <div style="font-size: 11px; font-weight: 700; color: {health_text}; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">Health</div>
                <div style="font-size: {health_font}px; font-weight: 900; color: {health_color}; line-height: 1; margin: 12px 0; word-break: break-word; overflow-wrap: break-word;">{health_pct:.1f}%</div>
                <div style="font-size: 10px; color: {health_text}; font-weight: 600;">System Health</div>
            </div>
        ''')
        
        html_parts.append('</div>')
        
        # Disconnected Agents
        if disconnected:
            html_parts.append('<h4 style="margin-bottom: 15px; color: #ef4444;">⚠️ Disconnected Agents</h4>')
            html_parts.append('<table style="margin: 0;"><thead><tr><th>Agent Name</th><th>Status</th><th>Hours Offline</th><th>Last Keepalive</th><th>OS</th></tr></thead><tbody>')
            for agent in disconnected[:10]:  # Top 10
                hours = agent.get('hours_offline', 0)
                row_class = 'class="row-critical"' if hours > 72 else 'class="row-high"' if hours > 24 else ''
                html_parts.append(
                    f'<tr {row_class}>'
                    f'<td><strong>{agent.get("name", "N/A")}</strong></td>'
                    f'<td><span class="level-badge level-high">{agent.get("status", "N/A")}</span></td>'
                    f'<td><strong style="color: #ef4444;">{hours:.1f}</strong></td>'
                    f'<td>{agent.get("last_keepalive", "N/A")}</td>'
                    f'<td>{agent.get("os", "N/A")}</td>'
                    f'</tr>'
                )
            html_parts.append('</tbody></table>')
        
        # Agents by Version
        if agents_by_version:
            html_parts.append('<h4 style="margin-top: 25px; margin-bottom: 15px;">📊 Agents by Version</h4>')
            html_parts.append('<table style="margin: 0;"><thead><tr><th>Version</th><th>Count</th></tr></thead><tbody>')
            for version, count in sorted(agents_by_version.items(), key=lambda x: x[1], reverse=True):
                html_parts.append(f'<tr><td><code>{version}</code></td><td><strong>{count}</strong></td></tr>')
            html_parts.append('</tbody></table>')
        
        # Agents by OS
        if agents_by_os:
            html_parts.append('<h4 style="margin-top: 25px; margin-bottom: 15px;">💻 Agents by Operating System</h4>')
            html_parts.append('<table style="margin: 0;"><thead><tr><th>Operating System</th><th>Count</th></tr></thead><tbody>')
            for os_name, count in sorted(agents_by_os.items(), key=lambda x: x[1], reverse=True):
                html_parts.append(f'<tr><td><strong>{os_name}</strong></td><td><strong>{count}</strong></td></tr>')
            html_parts.append('</tbody></table>')
        
        html_parts.append('</div></div>')
        return '\n'.join(html_parts)
    
    def _generate_rootcheck_analysis(self, system_info: Dict) -> str:
        """Generate rootcheck analysis section"""
        api_data = system_info.get('api_data', {})
        rootcheck_data = api_data.get('rootcheck', [])
        
        if not rootcheck_data:
            return ""
        
        # Check if we have valid data (title and severity not all N/A)
        has_valid_data = False
        for agent_data in rootcheck_data[:5]:  # Check first 5 agents
            results = agent_data.get('results', [])
            if not results or len(results) == 0:
                continue
            
            for result in results[:10]:  # Check top 10 per agent
                title = result.get('title', 'N/A')
                severity = result.get('severity', 'N/A')
                # If at least one result has valid title or severity, we have valid data
                if (title and title != 'N/A' and title.strip()) or (severity and severity != 'N/A' and severity.strip()):
                    has_valid_data = True
                    break
            if has_valid_data:
                break
        
        if not has_valid_data:
            return ""
        
        html_parts = ['<div class="card">']
        html_parts.append('<div class="card-header"><span>🔍</span> <h3>Rootcheck Analysis</h3></div>')
        html_parts.append('<div class="card-body">')
        html_parts.append('<p style="color: #64748b; font-size: 13px; margin-bottom: 20px;">Rootcheck results detecting rootkits, malware, and system integrity issues.</p>')
        
        agent_count = 0
        for agent_data in rootcheck_data[:5]:  # First 5 agents
            agent_name = agent_data.get('agent_name', 'N/A')
            results = agent_data.get('results', [])
            
            if not results or len(results) == 0:
                continue
            
            # Filter results to only show those with valid title or severity
            valid_results = []
            for result in results[:10]:  # Top 10 per agent
                title = result.get('title', 'N/A')
                severity = result.get('severity', 'N/A')
                if (title and title != 'N/A' and title.strip()) or (severity and severity != 'N/A' and severity.strip()):
                    valid_results.append(result)
            
            if not valid_results:
                continue
            
            agent_count += 1
            html_parts.append(f'<h4 style="margin-top: 20px; margin-bottom: 10px;">Agent: {agent_name}</h4>')
            html_parts.append('<table style="margin: 0;"><thead><tr><th>Title</th><th>Status</th><th>Severity</th></tr></thead><tbody>')
            
            for result in valid_results:
                title = result.get('title', 'N/A')
                status = result.get('status', 'N/A')
                severity = result.get('severity', 'N/A')
                
                status_color = "#ef4444" if status.lower() in ['bad', 'failed'] else "#10b981"
                
                title_display = title[:80] + ("..." if len(title) > 80 else "") if title and title != 'N/A' else 'N/A'
                severity_display = severity if severity and severity != 'N/A' else 'N/A'
                
                html_parts.append(
                    f'<tr>'
                    f'<td>{title_display}</td>'
                    f'<td><span style="color: {status_color}; font-weight: 700;">{status.upper()}</span></td>'
                    f'<td>{severity_display}</td>'
                    f'</tr>'
                )
            
            html_parts.append('</tbody></table>')
        
        if agent_count == 0:
            return ""
        
        html_parts.append('</div></div>')
        return '\n'.join(html_parts)
    
    def _generate_sca_assessment(self, system_info: Dict) -> str:
        """Generate SCA (Security Configuration Assessment) section"""
        api_data = system_info.get('api_data', {})
        sca_data = api_data.get('sca', [])
        
        if not sca_data:
            return ""
        
        html_parts = ['<div class="card">']
        html_parts.append('<div class="card-header"><span>🔒</span> <h3>Security Configuration Assessment (SCA)</h3></div>')
        html_parts.append('<div class="card-body">')
        html_parts.append('<p style="color: #64748b; font-size: 13px; margin-bottom: 20px;">Security Configuration Assessment policy compliance results.</p>')
        
        for agent_data in sca_data[:5]:  # First 5 agents
            agent_name = agent_data.get('agent_name', 'N/A')
            agent_id = agent_data.get('agent_id', 'N/A')
            policies = agent_data.get('policies', [])
            
            if not policies:
                continue
            
            html_parts.append(f'<h4 style="margin-top: 20px; margin-bottom: 10px;">Agent: {agent_name} (ID: {agent_id})</h4>')
            html_parts.append('<table style="margin: 0;"><thead><tr><th>Policy Name</th><th>Score</th><th>Pass</th><th>Fail</th><th>Total Checks</th></tr></thead><tbody>')
            
            for policy in policies[:10]:  # Top 10 policies
                name = policy.get('name', 'N/A')
                score = policy.get('score', 0)
                pass_count = policy.get('pass', 0)
                fail_count = policy.get('fail', 0)
                total_checks = policy.get('total_checks', 0)
                
                # Score color coding
                if score >= 80:
                    score_color = "#10b981"
                elif score >= 60:
                    score_color = "#f59e0b"
                else:
                    score_color = "#ef4444"
                
                html_parts.append(
                    f'<tr>'
                    f'<td><strong>{name[:60]}{"..." if len(name) > 60 else ""}</strong></td>'
                    f'<td><span style="color: {score_color}; font-weight: 700;">{score}%</span></td>'
                    f'<td><span style="color: #10b981;">{pass_count}</span></td>'
                    f'<td><span style="color: #ef4444;">{fail_count}</span></td>'
                    f'<td>{total_checks}</td>'
                    f'</tr>'
                )
            
            html_parts.append('</tbody></table>')
        
        html_parts.append('</div></div>')
        return '\n'.join(html_parts)
    
    def _generate_syscheck_analysis(self, system_info: Dict) -> str:
        """Generate Syscheck (FIM) analysis section"""
        api_data = system_info.get('api_data', {})
        syscheck_data = api_data.get('syscheck', [])
        
        if not syscheck_data:
            return ""
        
        html_parts = ['<div class="card">']
        html_parts.append('<div class="card-header"><span>📁</span> <h3>File Integrity Monitoring (FIM) Analysis</h3></div>')
        html_parts.append('<div class="card-body">')
        html_parts.append('<p style="color: #64748b; font-size: 13px; margin-bottom: 20px;">File Integrity Monitoring (Syscheck) findings detecting file changes and modifications.</p>')
        
        for agent_data in syscheck_data[:5]:  # First 5 agents
            agent_name = agent_data.get('agent_name', 'N/A')
            agent_id = agent_data.get('agent_id', 'N/A')
            findings = agent_data.get('findings', [])
            last_scan = agent_data.get('last_scan', {})
            
            if not findings and not last_scan:
                continue
            
            html_parts.append(f'<h4 style="margin-top: 20px; margin-bottom: 10px;">Agent: {agent_name} (ID: {agent_id})</h4>')
            
            # Last scan info
            if last_scan:
                start_time = last_scan.get('start', 'N/A')
                end_time = last_scan.get('end', 'N/A')
                html_parts.append(f'<p style="margin-bottom: 10px; color: #64748b;"><strong>Last Scan:</strong> Start: {start_time}, End: {end_time if end_time != "unknown" else "In Progress"}</p>')
            
            if findings:
                html_parts.append(f'<p style="margin-bottom: 10px; color: #64748b;"><strong>Findings:</strong> {len(findings)} file changes detected</p>')
                html_parts.append('<table style="margin: 0;"><thead><tr><th>File Path</th><th>Type</th><th>Changes</th><th>Date</th></tr></thead><tbody>')
                
                for finding in findings[:10]:  # Top 10 findings
                    file_path = finding.get('file', 'N/A')
                    file_type = finding.get('type', 'N/A')
                    changes = finding.get('changes', 0)
                    date = finding.get('date', 'N/A')
                    
                    changes_color = "#ef4444" if changes > 0 else "#10b981"
                    
                    html_parts.append(
                        f'<tr>'
                        f'<td><code style="color: #0ea5e9;">{file_path[:60]}{"..." if len(file_path) > 60 else ""}</code></td>'
                        f'<td>{file_type}</td>'
                        f'<td><span style="color: {changes_color}; font-weight: 700;">{changes}</span></td>'
                        f'<td>{date}</td>'
                        f'</tr>'
                    )
                
                html_parts.append('</tbody></table>')
            else:
                html_parts.append('<p style="color: #10b981; font-weight: 600;">✅ No file changes detected</p>')
        
        html_parts.append('</div></div>')
        return '\n'.join(html_parts)
    
    def _generate_ciscat_compliance(self, system_info: Dict) -> str:
        """Generate CIS-CAT compliance section"""
        api_data = system_info.get('api_data', {})
        ciscat_data = api_data.get('ciscat', [])
        
        if not ciscat_data:
            return ""
        
        html_parts = ['<div class="card">']
        html_parts.append('<div class="card-header"><span>✅</span> <h3>CIS-CAT Compliance Results</h3></div>')
        html_parts.append('<div class="card-body">')
        html_parts.append('<p style="color: #64748b; font-size: 13px; margin-bottom: 20px;">CIS-CAT (CIS Configuration Assessment Tool) benchmark compliance results.</p>')
        
        html_parts.append('<table style="margin: 0;"><thead><tr><th>Agent ID</th><th>Benchmark</th><th>Profile</th><th>Score</th><th>Pass</th><th>Fail</th><th>Scan Time</th></tr></thead><tbody>')
        
        for result in ciscat_data[:10]:  # Top 10 results
            agent_id = result.get('agent_id', 'N/A')
            benchmark = result.get('benchmark', 'N/A')
            profile = result.get('profile', 'N/A')
            score = result.get('score', 0)
            pass_count = result.get('pass', 0)
            fail_count = result.get('fail', 0)
            scan = result.get('scan', {})
            scan_time = scan.get('time', 'N/A') if scan else 'N/A'
            
            # Score color coding
            if score >= 80:
                score_color = "#10b981"
            elif score >= 60:
                score_color = "#f59e0b"
            else:
                score_color = "#ef4444"
            
            # Shorten profile name if too long
            profile_short = profile[:40] + "..." if len(profile) > 40 else profile
            
            html_parts.append(
                f'<tr>'
                f'<td><strong>{agent_id}</strong></td>'
                f'<td>{benchmark[:50]}{"..." if len(benchmark) > 50 else ""}</td>'
                f'<td title="{profile}">{profile_short}</td>'
                f'<td><span style="color: {score_color}; font-weight: 700;">{score}%</span></td>'
                f'<td><span style="color: #10b981;">{pass_count}</span></td>'
                f'<td><span style="color: #ef4444;">{fail_count}</span></td>'
                f'<td>{scan_time}</td>'
                f'</tr>'
            )
        
        html_parts.append('</tbody></table>')
        html_parts.append('</div></div>')
        return '\n'.join(html_parts)
    
    def _generate_syscollector_info(self, system_info: Dict) -> str:
        """Generate enhanced Syscollector information section"""
        api_data = system_info.get('api_data', {})
        syscollector_data = api_data.get('syscollector', [])
        
        if not syscollector_data:
            return ""
        
        html_parts = ['<div class="card">']
        html_parts.append('<div class="card-header"><span>💻</span> <h3>Enhanced System Information (Syscollector)</h3></div>')
        html_parts.append('<div class="card-body">')
        html_parts.append('<p style="color: #64748b; font-size: 13px; margin-bottom: 20px;">Detailed system information collected from agents via Syscollector module.</p>')
        
        for agent_data in syscollector_data[:3]:  # First 3 agents
            agent_name = agent_data.get('agent_name', 'N/A')
            agent_id = agent_data.get('agent_id', 'N/A')
            hardware = agent_data.get('hardware', {})
            network = agent_data.get('network_interfaces', [])
            packages_count = agent_data.get('packages_count', 0)
            packages_sample = agent_data.get('packages_sample', [])
            ports = agent_data.get('listening_ports', [])
            processes = agent_data.get('running_processes', [])
            
            html_parts.append(f'<h4 style="margin-top: 20px; margin-bottom: 15px; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px;">Agent: {agent_name} (ID: {agent_id})</h4>')
            
            # Hardware information
            if hardware and isinstance(hardware, dict):
                cpu_name = str(hardware.get('cpu_name', 'N/A')) if hardware.get('cpu_name') else 'N/A'
                cpu_cores = str(hardware.get('cpu_cores', 'N/A')) if hardware.get('cpu_cores') is not None else 'N/A'
                ram_total = str(hardware.get('ram_total', 'N/A')) if hardware.get('ram_total') else 'N/A'
                ram_free = str(hardware.get('ram_free', 'N/A')) if hardware.get('ram_free') else 'N/A'
                ram_usage = str(hardware.get('ram_usage', 'N/A')) if hardware.get('ram_usage') else 'N/A'
                
                html_parts.append('<div style="margin-bottom: 15px; padding: 15px; background: #f8fafc; border-radius: 8px;">')
                html_parts.append('<strong style="color: #1e293b;">Hardware Information:</strong><br>')
                html_parts.append(f'CPU: {cpu_name} ({cpu_cores} cores)<br>')
                html_parts.append(f'RAM: {ram_total} total, {ram_free} free, {ram_usage} usage')
                html_parts.append('</div>')
            
            # Network interfaces
            if network:
                html_parts.append('<div style="margin-bottom: 15px;"><strong style="color: #1e293b;">Network Interfaces:</strong></div>')
                html_parts.append('<table style="margin: 0; font-size: 12px;"><thead><tr><th>Interface</th><th>State</th><th>MTU</th><th>MAC</th></tr></thead><tbody>')
                for iface in network[:5]:  # Top 5 interfaces
                    if not isinstance(iface, dict):
                        continue
                    name = iface.get('name', 'N/A') if isinstance(iface.get('name'), str) else str(iface.get('name', 'N/A'))
                    state = iface.get('state', 'N/A') if isinstance(iface.get('state'), str) else str(iface.get('state', 'N/A'))
                    mtu = iface.get('mtu', 'N/A') if isinstance(iface.get('mtu'), (str, int)) else str(iface.get('mtu', 'N/A'))
                    mac = iface.get('mac', 'N/A') if isinstance(iface.get('mac'), str) else str(iface.get('mac', 'N/A'))
                    state_color = "#10b981" if str(state).lower() == 'up' else "#ef4444"
                    html_parts.append(
                        f'<tr>'
                        f'<td><code>{name}</code></td>'
                        f'<td><span style="color: {state_color};">{state}</span></td>'
                        f'<td>{mtu}</td>'
                        f'<td><code>{mac}</code></td>'
                        f'</tr>'
                    )
                html_parts.append('</tbody></table>')
            
            # Packages summary
            if packages_count > 0:
                html_parts.append(f'<div style="margin-top: 15px; margin-bottom: 10px;"><strong style="color: #1e293b;">Installed Packages:</strong> {packages_count} total</div>')
                if packages_sample:
                    package_names = []
                    for p in packages_sample[:10]:
                        if isinstance(p, dict):
                            package_names.append(p.get('name', 'N/A'))
                        else:
                            package_names.append(str(p))
                    if package_names:
                        html_parts.append('<div style="font-size: 12px; color: #64748b;">Sample packages: ' + ', '.join(package_names) + '</div>')
            
            # Listening ports
            if ports:
                html_parts.append('<div style="margin-top: 15px; margin-bottom: 10px;"><strong style="color: #1e293b;">Listening Ports:</strong></div>')
                html_parts.append('<table style="margin: 0; font-size: 12px;"><thead><tr><th>Port</th><th>Protocol</th><th>Process</th></tr></thead><tbody>')
                for port in ports[:10]:  # Top 10 ports
                    if not isinstance(port, dict):
                        continue
                    
                    # Safely extract port number
                    local = port.get('local', {})
                    if isinstance(local, dict):
                        port_num = local.get('port', 'N/A')
                    else:
                        port_num = str(local) if local else 'N/A'
                    
                    protocol = port.get('protocol', 'N/A')
                    
                    # Safely extract process name
                    process_data = port.get('process', {})
                    if isinstance(process_data, dict):
                        process = process_data.get('name', 'N/A')
                    elif isinstance(process_data, str):
                        process = process_data
                    else:
                        process = 'N/A'
                    
                    html_parts.append(
                        f'<tr>'
                        f'<td><code>{port_num}</code></td>'
                        f'<td>{protocol}</td>'
                        f'<td>{process}</td>'
                        f'</tr>'
                    )
                html_parts.append('</tbody></table>')
            
            # Running processes
            if processes:
                html_parts.append('<div style="margin-top: 15px; margin-bottom: 10px;"><strong style="color: #1e293b;">Running Processes (Sample):</strong></div>')
                process_names = []
                for p in processes[:10]:
                    if isinstance(p, dict):
                        process_names.append(p.get('name', 'N/A'))
                    else:
                        process_names.append(str(p))
                if process_names:
                    html_parts.append('<div style="font-size: 12px; color: #64748b;">' + ', '.join(process_names) + '</div>')
        
        html_parts.append('</div></div>')
        return '\n'.join(html_parts)
    
    def _generate_timeline_visualization(self, processor) -> str:
        """Generate interactive timeline visualization"""
        timeline_data = processor.get_timeline_data(limit=1000)
        
        if not timeline_data:
            return """<div class="card">
            <div class="card-header"><span>📅</span> <h3>Event Timeline</h3></div>
            <div class="card-body">
                <div class="empty-state">No timeline data available.</div>
            </div>
        </div>"""
        
        # Group events by hour for visualization
        from collections import defaultdict
        events_by_hour = defaultdict(list)
        
        for event in timeline_data[:500]:  # Limit to 500 for performance
            try:
                # Parse timestamp and get hour
                timestamp_str = event.get('timestamp', '')
                if timestamp_str:
                    # Extract hour from ISO format: 2025-12-27T15:41:05 -> 2025-12-27T15
                    hour_key = timestamp_str[:13] if 'T' in timestamp_str else timestamp_str[:10]
                    events_by_hour[hour_key].append(event)
            except Exception:
                continue
        
        if not events_by_hour:
            return """<div class="card">
            <div class="card-header"><span>📅</span> <h3>Event Timeline</h3></div>
            <div class="card-body">
                <div class="empty-state">No valid timeline data available.</div>
            </div>
        </div>"""
        
        # Build timeline visualization HTML
        timeline_bars = []
        sorted_hours = sorted(events_by_hour.keys())
        
        for hour in sorted_hours:
            events = events_by_hour[hour]
            max_level = max((e.get('level', 0) for e in events), default=0)
            event_count = len(events)
            
            # Calculate height based on event count (max 100%)
            height_pct = min(100, max(20, (event_count / 10) * 100))
            
            # Determine color based on max level
            if max_level >= 15:
                color = '#ef4444'
            elif max_level >= 12:
                color = '#f97316'
            elif max_level >= 8:
                color = '#f59e0b'
            else:
                color = '#10b981'
            
            # Format hour for display
            display_hour = hour.replace('T', ' ') if 'T' in hour else hour
            
            timeline_bars.append(f'''<div style="flex: 1; background: {color}; min-width: 4px; height: {height_pct}%; border-radius: 2px; cursor: pointer; position: relative; transition: all 0.3s ease;" 
                title="{display_hour}: {event_count} events (Max Level: {max_level})"
                onmouseover="this.style.opacity='0.8'; this.style.transform='scaleY(1.1)'"
                onmouseout="this.style.opacity='1'; this.style.transform='scaleY(1)'"
                onclick="showHourDetails_{id(self)}('{hour}', {event_count}, {max_level})">
            </div>''')
        
        # Create details function for this timeline
        timeline_id = id(self)
        details_script = f'''
        <script>
            function showHourDetails_{timeline_id}(hour, count, maxLevel) {{
                alert('Hour: ' + hour + '\\nEvents: ' + count + '\\nMax Level: ' + maxLevel);
            }}
        </script>
        '''
        
        return f"""<div class="card">
            <div class="card-header"><span>📅</span> <h3>Interactive Event Timeline</h3></div>
            <div class="card-body">
                <p style="color: #64748b; font-size: 13px; margin-bottom: 20px;">Timeline visualization of all security events grouped by hour. Hover over bars for details.</p>
                <div style="height: 400px; margin: 20px 0; border: 1px solid #e2e8f0; border-radius: 8px; background: #f8fafc; padding: 20px; overflow-x: auto;">
                    <div style="display: flex; align-items: flex-end; height: 100%; gap: 2px; min-width: {len(sorted_hours) * 20}px;">
                        {''.join(timeline_bars)}
                    </div>
                </div>
                <div style="margin-top: 15px; font-size: 12px; color: #64748b;">
                    <strong>Total Events:</strong> {len(timeline_data)} | 
                    <strong>Time Range:</strong> {sorted_hours[0] if sorted_hours else 'N/A'} to {sorted_hours[-1] if sorted_hours else 'N/A'}
                </div>
                {details_script}
            </div>
        </div>"""
    
    def _generate_attack_timeline(self, processor) -> str:
        """Generate attack timeline visualization"""
        attack_events = processor.get_attack_timeline(min_level=12, limit=500)
        
        if not attack_events:
            return """<div class="card">
            <div class="card-header"><span>⚔️</span> <h3>Attack Timeline</h3></div>
            <div class="card-body">
                <div class="empty-state">No attack events detected in this period.</div>
            </div>
        </div>"""
        
        # Group by attack type
        attack_types = {}
        for event in attack_events:
            attack_type = event.get('attack_type', 'Unknown')
            if attack_type not in attack_types:
                attack_types[attack_type] = []
            attack_types[attack_type].append(event)
        
        # Build attack type distribution HTML
        type_cards = []
        for attack_type, events in attack_types.items():
            type_cards.append(f'''<div style="padding: 15px; background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%); border-radius: 8px; border-left: 4px solid #ef4444;">
                <div style="font-size: 12px; color: #64748b; margin-bottom: 5px;">{attack_type}</div>
                <div style="font-size: 24px; font-weight: 800; color: #1e293b;">{len(events)}</div>
            </div>''')
        
        # Build attack events HTML
        events_html = []
        for event in attack_events[:50]:
            severity_color = '#ef4444' if event['severity'] == 'critical' else '#f97316' if event['severity'] == 'high' else '#f59e0b'
            date_str = event['timestamp'].split('T')[0]
            time_str = event['timestamp'].split('T')[1].split('.')[0]
            desc = event['description'][:80] + ('...' if len(event['description']) > 80 else '')
            
            events_html.append(f'''<div style="display: flex; align-items: center; gap: 15px; padding: 12px; background: white; border-radius: 8px; border-left: 4px solid {severity_color};">
                <div style="min-width: 150px; font-size: 12px; color: #64748b;">{date_str}<br>{time_str}</div>
                <div style="flex: 1;">
                    <div style="font-weight: 700; color: #1e293b; margin-bottom: 5px;">{desc}</div>
                    <div style="font-size: 12px; color: #64748b;">
                        <span style="background: #f1f5f9; padding: 2px 8px; border-radius: 4px; margin-right: 8px;">{event['attack_type']}</span>
                        <span style="background: #f1f5f9; padding: 2px 8px; border-radius: 4px; margin-right: 8px;">{event['agent_name']}</span>
                        <span style="background: #f1f5f9; padding: 2px 8px; border-radius: 4px;">Level {event['level']}</span>
                    </div>
                </div>
            </div>''')
        
        return f"""<div class="card">
            <div class="card-header"><span>⚔️</span> <h3>Attack Timeline Analysis</h3></div>
            <div class="card-body">
                <p style="color: #64748b; font-size: 13px; margin-bottom: 20px;">Timeline of critical security events and attack patterns.</p>
                
                <div style="margin-bottom: 20px;">
                    <h4 style="margin-bottom: 10px;">Attack Type Distribution</h4>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px;">
                        {''.join(type_cards)}
                    </div>
                </div>
                
                <div id="attack-timeline-container" style="height: 500px; margin: 20px 0; border: 1px solid #e2e8f0; border-radius: 8px; background: #f8fafc; position: relative; overflow-x: auto;">
                    <div style="padding: 20px;">
                        <div style="display: flex; flex-direction: column; gap: 10px;">
                            {''.join(events_html)}
                        </div>
                    </div>
                </div>
            </div>
        </div>"""
    
    def _generate_correlation_timeline(self, processor) -> str:
        """Generate event correlation timeline"""
        correlated_groups = processor.get_correlated_events(time_window_minutes=60, correlation_keys=['src_ip', 'agent_name', 'rule_id'])
        
        if not correlated_groups:
            return """<div class="card">
            <div class="card-header"><span>🔗</span> <h3>Event Correlation Timeline</h3></div>
            <div class="card-body">
                <div class="empty-state">No correlated event groups found.</div>
            </div>
        </div>"""
        
        # Build correlation groups HTML
        groups_html = []
        for idx, group in enumerate(correlated_groups[:10]):
            # Build correlation keys HTML
            keys_html = []
            for key, value in group['correlation_keys'].items():
                keys_html.append(f'<span style="background: white; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600;"><strong>{key}:</strong> {value}</span>')
            
            # Build events table rows
            events_rows = []
            for event in group['events'][:10]:
                level_color = '#ef4444' if event['level'] >= 15 else '#f97316' if event['level'] >= 12 else '#f59e0b'
                desc = event['description'][:60] + ('...' if len(event['description']) > 60 else '')
                time_str = event['timestamp'].split('T')[1].split('.')[0]
                events_rows.append(f'''<tr>
                    <td style="padding: 8px;">{time_str}</td>
                    <td style="padding: 8px;"><span style="color: {level_color}; font-weight: 700;">{event['level']}</span></td>
                    <td style="padding: 8px;">{desc}</td>
                    <td style="padding: 8px;">{event['agent_name']}</td>
                </tr>''')
            
            start_date = group['start_time'].split('T')[0]
            start_time = group['start_time'].split('T')[1].split('.')[0]
            end_time = group['end_time'].split('T')[1].split('.')[0]
            
            group_html = f'''<div style="padding: 20px; background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%); border-radius: 12px; border: 2px solid #e2e8f0; border-left: 4px solid #ef4444;">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 15px;">
                    <div>
                        <h4 style="margin: 0 0 10px 0; color: #1e293b;">Correlation Group #{idx + 1}</h4>
                        <div style="font-size: 12px; color: #64748b;">
                            <strong>{group['event_count']}</strong> correlated events | 
                            Duration: <strong>{group['duration_minutes']:.1f}</strong> minutes
                        </div>
                    </div>
                    <div style="background: #ef4444; color: white; padding: 8px 16px; border-radius: 6px; font-weight: 700; font-size: 18px;">
                        {group['event_count']}
                    </div>
                </div>
                
                <div style="margin-bottom: 15px; padding: 12px; background: #f1f5f9; border-radius: 8px;">
                    <div style="font-size: 11px; color: #64748b; margin-bottom: 5px;">CORRELATION KEYS</div>
                    <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                        {''.join(keys_html)}
                    </div>
                </div>
                
                <div style="font-size: 12px; color: #64748b; margin-bottom: 10px;">
                    <strong>Time Range:</strong> {start_date} {start_time} - {end_time}
                </div>
                
                <div style="max-height: 200px; overflow-y: auto;">
                    <table style="width: 100%; font-size: 12px;">
                        <thead>
                            <tr style="background: #f8fafc;">
                                <th style="padding: 8px; text-align: left;">Time</th>
                                <th style="padding: 8px; text-align: left;">Level</th>
                                <th style="padding: 8px; text-align: left;">Description</th>
                                <th style="padding: 8px; text-align: left;">Agent</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(events_rows)}
                        </tbody>
                    </table>
                </div>
            </div>'''
            groups_html.append(group_html)
        
        return f"""<div class="card">
            <div class="card-header"><span>🔗</span> <h3>Event Correlation Timeline</h3></div>
            <div class="card-body">
                <p style="color: #64748b; font-size: 13px; margin-bottom: 20px;">Groups of related security events detected within 60-minute time windows.</p>
                
                <div style="display: grid; gap: 20px;">
                    {''.join(groups_html)}
                </div>
            </div>
        </div>"""
    
