"""
PDF Report Generator for Attack Detection System.
Generates comprehensive PDF reports with statistics, charts, and attack details.
"""

import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path
import logging

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
    from reportlab.platypus.flowables import HRFlowable
    from reportlab.pdfgen import canvas
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib.backends.backend_pdf import PdfPages
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

logger = logging.getLogger(__name__)


class PDFReportGenerator:
    """
    Generates comprehensive PDF reports for attack detection system.
    """
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize PDF report generator.
        
        Args:
            output_dir: Directory to save generated reports
        """
        if not REPORTLAB_AVAILABLE:
            raise ImportError("reportlab is required. Install with: pip install reportlab")
        
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles."""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2d3436'),
            spaceAfter=30,
            alignment=TA_CENTER
        ))
        
        # Heading style
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#D4A373'),
            spaceAfter=12,
            spaceBefore=12
        ))
        
        # Subheading style
        self.styles.add(ParagraphStyle(
            name='CustomSubHeading',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#636e72'),
            spaceAfter=8
        ))
        
        # Body text style
        self.styles.add(ParagraphStyle(
            name='CustomBody',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#2d3436'),
            spaceAfter=6
        ))
    
    def generate_report(
        self,
        attacks: List[Dict],
        report_type: str = "comprehensive",
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        title: Optional[str] = None
    ) -> str:
        """
        Generate a comprehensive PDF report.
        
        Args:
            attacks: List of attack dictionaries
            report_type: Type of report ("comprehensive", "summary", "detailed")
            start_date: Start date for report (None = all time)
            end_date: End date for report (None = all time)
            title: Custom report title (None = auto-generated)
            
        Returns:
            Path to generated PDF file
        """
        # Filter attacks by date range
        if start_date or end_date:
            filtered_attacks = []
            for attack in attacks:
                attack_time = datetime.fromisoformat(attack["timestamp"]) if isinstance(attack["timestamp"], str) else attack["timestamp"]
                if start_date and attack_time < start_date:
                    continue
                if end_date and attack_time > end_date:
                    continue
                filtered_attacks.append(attack)
            attacks = filtered_attacks
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"attack_report_{timestamp}.pdf"
        filepath = self.output_dir / filename
        
        # Generate report
        doc = SimpleDocTemplate(str(filepath), pagesize=letter)
        story = []
        
        # Title page
        story.extend(self._generate_title_page(title, attacks, start_date, end_date))
        story.append(PageBreak())
        
        # Executive Summary
        story.extend(self._generate_executive_summary(attacks))
        story.append(PageBreak())
        
        # Attack Statistics
        story.extend(self._generate_statistics_section(attacks))
        story.append(PageBreak())
        
        # Attack Timeline
        if MATPLOTLIB_AVAILABLE:
            story.extend(self._generate_timeline_chart(attacks))
        
        # Top Attackers
        story.extend(self._generate_top_attackers(attacks))
        story.append(PageBreak())
        
        # Attack Details
        if report_type in ["comprehensive", "detailed"]:
            story.extend(self._generate_attack_details(attacks))
        
        # Shodan Intelligence Summary
        story.extend(self._generate_shodan_summary(attacks))
        
        # Recommendations
        story.extend(self._generate_recommendations(attacks))
        
        # Footer
        story.extend(self._generate_footer())
        
        # Build PDF
        doc.build(story)
        
        logger.info(f"PDF report generated: {filepath}")
        return str(filepath)
    
    def _generate_title_page(self, title: Optional[str], attacks: List[Dict], 
                            start_date: Optional[datetime], end_date: Optional[datetime]) -> List:
        """Generate title page."""
        story = []
        
        if not title:
            title = "Attack Detection System Report"
        
        story.append(Spacer(1, 2*inch))
        story.append(Paragraph("🛡️", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph(title, self.styles['CustomTitle']))
        story.append(Spacer(1, 0.5*inch))
        
        # Report metadata
        metadata = [
            ["Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Total Attacks:", str(len(attacks))],
        ]
        
        if start_date:
            metadata.append(["Start Date:", start_date.strftime("%Y-%m-%d %H:%M:%S")])
        if end_date:
            metadata.append(["End Date:", end_date.strftime("%Y-%m-%d %H:%M:%S")])
        
        metadata_table = Table(metadata, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#636e72')),
            ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#2d3436')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        story.append(metadata_table)
        story.append(Spacer(1, 1*inch))
        
        return story
    
    def _generate_executive_summary(self, attacks: List[Dict]) -> List:
        """Generate executive summary section."""
        story = []
        
        story.append(Paragraph("Executive Summary", self.styles['CustomHeading']))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#D4A373')))
        story.append(Spacer(1, 0.2*inch))
        
        # Calculate statistics
        total_attacks = len(attacks)
        critical = sum(1 for a in attacks if a.get("severity") == "CRITICAL")
        high = sum(1 for a in attacks if a.get("severity") == "HIGH")
        unique_ips = len(set(a.get("src_ip", "Unknown") for a in attacks))
        
        # Attack types
        attack_types = {}
        for attack in attacks:
            atype = attack.get("attack_type", "Unknown")
            attack_types[atype] = attack_types.get(atype, 0) + 1
        
        summary_text = f"""
        This report provides a comprehensive analysis of {total_attacks} security incidents detected by the 
        Real-Time Attack Detection System. The system monitored network traffic, system logs, and process 
        activities to identify potential threats and attacks.
        
        <b>Key Findings:</b>
        <br/>• Total Attacks Detected: {total_attacks}
        <br/>• Critical Severity: {critical}
        <br/>• High Severity: {high}
        <br/>• Unique Attacking IPs: {unique_ips}
        <br/>• Attack Types: {len(attack_types)}
        """
        
        story.append(Paragraph(summary_text, self.styles['CustomBody']))
        story.append(Spacer(1, 0.3*inch))
        
        return story
    
    def _generate_statistics_section(self, attacks: List[Dict]) -> List:
        """Generate statistics section."""
        story = []
        
        story.append(Paragraph("Attack Statistics", self.styles['CustomHeading']))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#D4A373')))
        story.append(Spacer(1, 0.2*inch))
        
        # Calculate statistics
        total = len(attacks)
        by_severity = {}
        by_type = {}
        
        for attack in attacks:
            severity = attack.get("severity", "UNKNOWN")
            atype = attack.get("attack_type", "Unknown")
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_type[atype] = by_type.get(atype, 0) + 1
        
        # Severity table
        story.append(Paragraph("By Severity", self.styles['CustomSubHeading']))
        severity_data = [["Severity", "Count", "Percentage"]]
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = by_severity.get(severity, 0)
            percentage = (count / total * 100) if total > 0 else 0
            severity_data.append([severity, str(count), f"{percentage:.1f}%"])
        
        severity_table = Table(severity_data, colWidths=[2*inch, 2*inch, 2*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#D4A373')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ]))
        story.append(severity_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Attack types table
        story.append(Paragraph("By Attack Type", self.styles['CustomSubHeading']))
        type_data = [["Attack Type", "Count", "Percentage"]]
        for atype, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            type_data.append([atype, str(count), f"{percentage:.1f}%"])
        
        type_table = Table(type_data, colWidths=[3*inch, 2*inch, 2*inch])
        type_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#CCD5AE')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#FEFAE0')),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ]))
        story.append(type_table)
        
        return story
    
    def _generate_timeline_chart(self, attacks: List[Dict]) -> List:
        """Generate timeline chart using matplotlib."""
        story = []
        
        if not attacks:
            return story
        
        story.append(Paragraph("Attack Timeline", self.styles['CustomHeading']))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#D4A373')))
        story.append(Spacer(1, 0.2*inch))
        
        try:
            # Prepare data
            timestamps = []
            severities = []
            for attack in attacks:
                ts = datetime.fromisoformat(attack["timestamp"]) if isinstance(attack["timestamp"], str) else attack["timestamp"]
                timestamps.append(ts)
                severities.append(attack.get("severity", "MEDIUM"))
            
            # Create chart
            fig, ax = plt.subplots(figsize=(8, 4))
            
            # Color mapping
            color_map = {
                "CRITICAL": "#e74c3c",
                "HIGH": "#e67e22",
                "MEDIUM": "#D4A373",
                "LOW": "#CCD5AE"
            }
            
            # Plot attacks
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                severity_times = [ts for ts, sev in zip(timestamps, severities) if sev == severity]
                if severity_times:
                    ax.scatter(
                        severity_times,
                        [severity] * len(severity_times),
                        c=color_map.get(severity, "#666"),
                        label=severity,
                        s=50,
                        alpha=0.7
                    )
            
            ax.set_xlabel("Time", fontsize=10)
            ax.set_ylabel("Severity", fontsize=10)
            ax.set_title("Attack Timeline", fontsize=12, fontweight='bold')
            ax.legend()
            ax.grid(True, alpha=0.3)
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            # Save to temporary file
            chart_path = self.output_dir / f"timeline_chart_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(chart_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            # Add to PDF
            img = Image(str(chart_path), width=6*inch, height=3*inch)
            story.append(img)
            story.append(Spacer(1, 0.2*inch))
            
            # Clean up
            chart_path.unlink()
            
        except Exception as e:
            logger.error(f"Error generating timeline chart: {e}")
            story.append(Paragraph(f"Error generating chart: {e}", self.styles['CustomBody']))
        
        return story
    
    def _generate_top_attackers(self, attacks: List[Dict]) -> List:
        """Generate top attackers section."""
        story = []
        
        story.append(Paragraph("Top Attacking IPs", self.styles['CustomHeading']))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#D4A373')))
        story.append(Spacer(1, 0.2*inch))
        
        # Calculate top attackers
        ip_stats = {}
        for attack in attacks:
            ip = attack.get("src_ip", "Unknown")
            if ip not in ip_stats:
                ip_stats[ip] = {
                    "count": 0,
                    "severities": [],
                    "types": []
                }
            ip_stats[ip]["count"] += 1
            ip_stats[ip]["severities"].append(attack.get("severity", "MEDIUM"))
            ip_stats[ip]["types"].append(attack.get("attack_type", "Unknown"))
        
        # Sort by count
        top_ips = sorted(ip_stats.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
        
        if top_ips:
            attacker_data = [["IP Address", "Attack Count", "Most Common Severity", "Attack Types"]]
            for ip, stats in top_ips:
                severity_counts = {}
                for sev in stats["severities"]:
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                most_common_sev = max(severity_counts.items(), key=lambda x: x[1])[0] if severity_counts else "N/A"
                
                unique_types = len(set(stats["types"]))
                types_str = f"{unique_types} type(s)"
                
                attacker_data.append([ip, str(stats["count"]), most_common_sev, types_str])
            
            attacker_table = Table(attacker_data, colWidths=[2*inch, 1.5*inch, 1.5*inch, 2*inch])
            attacker_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#D4A373')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#FEFAE0')),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ]))
            story.append(attacker_table)
        else:
            story.append(Paragraph("No attacker data available.", self.styles['CustomBody']))
        
        return story
    
    def _generate_attack_details(self, attacks: List[Dict]) -> List:
        """Generate detailed attack list."""
        story = []
        
        story.append(Paragraph("Detailed Attack Log", self.styles['CustomHeading']))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#D4A373')))
        story.append(Spacer(1, 0.2*inch))
        
        # Sort by timestamp (most recent first)
        sorted_attacks = sorted(
            attacks,
            key=lambda x: datetime.fromisoformat(x["timestamp"]) if isinstance(x["timestamp"], str) else x["timestamp"],
            reverse=True
        )[:50]  # Limit to 50 most recent
        
        for i, attack in enumerate(sorted_attacks, 1):
            story.append(Paragraph(f"Attack #{i}", self.styles['CustomSubHeading']))
            
            ts = datetime.fromisoformat(attack["timestamp"]) if isinstance(attack["timestamp"], str) else attack["timestamp"]
            details = attack.get("details", {})
            
            attack_info = [
                ["Timestamp:", ts.strftime("%Y-%m-%d %H:%M:%S")],
                ["Attack Type:", attack.get("attack_type", "Unknown")],
                ["Source IP:", attack.get("src_ip", "Unknown")],
                ["Severity:", attack.get("severity", "MEDIUM")],
            ]
            
            if details.get("packet_count"):
                attack_info.append(["Packet Count:", str(details["packet_count"])])
            if details.get("packet_rate"):
                attack_info.append(["Packet Rate:", f"{details['packet_rate']:.2f} PPS"])
            if details.get("protocol"):
                attack_info.append(["Protocol:", details["protocol"]])
            
            info_table = Table(attack_info, colWidths=[2*inch, 4*inch])
            info_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#E9EDC9')),
                ('BACKGROUND', (1, 0), (1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ]))
            story.append(info_table)
            story.append(Spacer(1, 0.2*inch))
        
        return story
    
    def _generate_shodan_summary(self, attacks: List[Dict]) -> List:
        """Generate Shodan intelligence summary."""
        story = []
        
        story.append(Paragraph("Shodan Threat Intelligence Summary", self.styles['CustomHeading']))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#D4A373')))
        story.append(Spacer(1, 0.2*inch))
        
        # Collect Shodan data
        shodan_ips = []
        total_cves = 0
        total_ports = 0
        
        for attack in attacks:
            details = attack.get("details", {})
            shodan_data = details.get("shodan_data")
            if shodan_data:
                ip_info = shodan_data.get("ip_info", {})
                if ip_info:
                    shodan_ips.append({
                        "ip": attack.get("src_ip", "Unknown"),
                        "org": ip_info.get("org", "Unknown"),
                        "country": ip_info.get("location", {}).get("country", "Unknown"),
                        "ports": len(ip_info.get("open_ports", [])),
                        "cves": len(ip_info.get("vulnerabilities", []))
                    })
                    total_cves += len(ip_info.get("vulnerabilities", []))
                    total_ports += len(ip_info.get("open_ports", []))
        
        if shodan_ips:
            story.append(Paragraph(f"Enriched IPs: {len(shodan_ips)}", self.styles['CustomSubHeading']))
            story.append(Paragraph(f"Total CVEs Found: {total_cves}", self.styles['CustomBody']))
            story.append(Paragraph(f"Total Open Ports: {total_ports}", self.styles['CustomBody']))
            story.append(Spacer(1, 0.2*inch))
            
            # Shodan data table
            shodan_data_table = [["IP", "Organization", "Country", "Open Ports", "CVEs"]]
            for shodan_ip in shodan_ips[:10]:  # Top 10
                shodan_data_table.append([
                    shodan_ip["ip"],
                    shodan_ip["org"][:30] if len(shodan_ip["org"]) > 30 else shodan_ip["org"],
                    shodan_ip["country"],
                    str(shodan_ip["ports"]),
                    str(shodan_ip["cves"])
                ])
            
            table = Table(shodan_data_table, colWidths=[1.5*inch, 2*inch, 1*inch, 1*inch, 1*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#CCD5AE')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#FEFAE0')),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ]))
            story.append(table)
        else:
            story.append(Paragraph("No Shodan enrichment data available.", self.styles['CustomBody']))
        
        return story
    
    def _generate_recommendations(self, attacks: List[Dict]) -> List:
        """Generate security recommendations."""
        story = []
        
        story.append(Paragraph("Security Recommendations", self.styles['CustomHeading']))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#D4A373')))
        story.append(Spacer(1, 0.2*inch))
        
        recommendations = []
        
        # Analyze attacks for recommendations
        critical_count = sum(1 for a in attacks if a.get("severity") == "CRITICAL")
        ddos_count = sum(1 for a in attacks if "DDoS" in a.get("attack_type", ""))
        port_scan_count = sum(1 for a in attacks if "Port Scanning" in a.get("attack_type", ""))
        
        if critical_count > 0:
            recommendations.append(
                f"<b>Critical Attacks Detected ({critical_count}):</b> "
                "Immediate action required. Review firewall rules and consider blocking source IPs."
            )
        
        if ddos_count > 0:
            recommendations.append(
                f"<b>DDoS Attacks ({ddos_count}):</b> "
                "Consider implementing rate limiting and DDoS protection services."
            )
        
        if port_scan_count > 0:
            recommendations.append(
                f"<b>Port Scanning Activity ({port_scan_count}):</b> "
                "Review exposed services and close unnecessary ports."
            )
        
        if not recommendations:
            recommendations.append("No specific recommendations based on current attack data.")
        
        for rec in recommendations:
            story.append(Paragraph(rec, self.styles['CustomBody']))
            story.append(Spacer(1, 0.1*inch))
        
        return story
    
    def _generate_footer(self) -> List:
        """Generate footer section."""
        story = []
        
        story.append(Spacer(1, 0.5*inch))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        story.append(Spacer(1, 0.2*inch))
        
        footer_text = f"""
        <i>Report generated by Real-Time Attack Detection System</i><br/>
        <i>Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</i><br/>
        <i>For security inquiries, contact your system administrator.</i>
        """
        
        story.append(Paragraph(footer_text, self.styles['CustomBody']))
        
        return story

