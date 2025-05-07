from flask import render_template, request, redirect, url_for, flash, jsonify, session, abort, Response, send_file
from app import app, db
from models import Scan, User
from forms import ScanForm
from scanner import perform_scan, get_scan_progress
import logging
import json
import csv
import io
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

@app.route('/')
def index():
    """Landing page with scan form"""
    form = ScanForm()
    return render_template('index.html', form=form)

@app.route('/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    form = ScanForm()
    
    if form.validate_on_submit():
        target_url = form.target_url.data
        
        # Create new scan record
        scan = Scan(
            target_url=target_url,
            is_complete=False
        )
        db.session.add(scan)
        db.session.commit()
        
        # Start the scan in background
        perform_scan(scan.id)
        
        # Redirect to scan progress page
        return redirect(url_for('scan_progress', scan_id=scan.id))
    
    # If form validation failed
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{field}: {error}", "danger")
    
    return redirect(url_for('index'))

@app.route('/scan/<int:scan_id>/progress')
def scan_progress(scan_id):
    """Show scan progress page"""
    scan = Scan.query.get_or_404(scan_id)
    findings = []
    
    # Also collect findings for in-progress scans to show partial results
    if scan.is_complete:
        scan_components = [
            scan.ip_scan, scan.dns_scan, scan.ssl_scan, scan.http_scan,
            scan.port_scan, scan.cors_scan, scan.whois_scan,
            scan.cookie_scan, scan.disclosure_scan
        ]
        
        logging.debug(f"Processing {len([c for c in scan_components if c])} scan components for scan {scan_id}")
        
        for component in scan_components:
            if component:
                component_findings = component.get_findings()
                logging.debug(f"Got {len(component_findings)} findings from {component.__class__.__name__}")
                findings.extend(component_findings)
                
        # Sort findings by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        findings.sort(key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5))
    
    return render_template('scan_result.html', scan=scan, is_complete=scan.is_complete, findings=findings)

@app.route('/api/scan/<int:scan_id>/progress')
def scan_progress_api(scan_id):
    """API endpoint to get scan progress"""
    progress = get_scan_progress(scan_id)
    return jsonify(progress)

@app.route('/scan/<int:scan_id>/result')
def scan_result(scan_id):
    """Show scan results page"""
    scan = Scan.query.get_or_404(scan_id)
    
    if not scan.is_complete:
        flash("Scan is still in progress", "warning")
        return redirect(url_for('scan_progress', scan_id=scan_id))
    
    # Collect findings from all scan components
    findings = []
    scan_components = [
        scan.ip_scan, scan.dns_scan, scan.ssl_scan, scan.http_scan,
        scan.port_scan, scan.cors_scan, scan.whois_scan,
        scan.cookie_scan, scan.disclosure_scan
    ]
    
    logging.debug(f"Processing {len([c for c in scan_components if c])} scan components for scan {scan_id}")
    
    for component in scan_components:
        if component:
            component_findings = component.get_findings()
            logging.debug(f"Got {len(component_findings)} findings from {component.__class__.__name__}")
            findings.extend(component_findings)
    
    # Sort findings by severity
    severity_order = {
        'critical': 0,
        'high': 1,
        'medium': 2,
        'low': 3,
        'info': 4
    }
    
    findings.sort(key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5))
    
    logging.debug(f"Total findings for scan {scan_id}: {len(findings)}")
    for i, finding in enumerate(findings):
        logging.debug(f"Finding {i+1}: {finding.get('title')} - {finding.get('severity')}")
    
    return render_template('scan_result.html', scan=scan, findings=findings, is_complete=True)

@app.route('/dashboard')
def dashboard():
    """Show dashboard with scan statistics"""
    # Get recent scans
    recent_scans = Scan.query.order_by(Scan.scan_date.desc()).limit(10).all()
    
    # Count vulnerabilities by severity across all scans
    vulnerability_counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0
    }
    
    for scan in recent_scans:
        vulnerability_counts['critical'] += scan.critical_count
        vulnerability_counts['high'] += scan.high_count
        vulnerability_counts['medium'] += scan.medium_count
        vulnerability_counts['low'] += scan.low_count
        vulnerability_counts['info'] += scan.info_count
    
    return render_template('dashboard.html', recent_scans=recent_scans, vulnerability_counts=vulnerability_counts)

@app.route('/history')
def scan_history():
    """Show scan history"""
    scans = Scan.query.order_by(Scan.scan_date.desc()).all()
    return render_template('history.html', scans=scans)

@app.route('/scan/<int:scan_id>/delete', methods=['POST'])
def delete_scan(scan_id):
    """Delete a scan and all related data"""
    scan = Scan.query.get_or_404(scan_id)
    
    try:
        # Delete the scan (cascade will handle related records)
        db.session.delete(scan)
        db.session.commit()
        flash('Scan deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting scan: {str(e)}', 'danger')
        logging.error(f"Error deleting scan {scan_id}: {str(e)}")
    
    return redirect(url_for('scan_history'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    logging.error(f"Server error: {e}")
    return render_template('500.html'), 500

@app.route('/scan/<int:scan_id>/export/<format>')
def export_scan_report(scan_id, format):
    """Export scan report in different formats (PDF, JSON, CSV)"""
    scan = Scan.query.get_or_404(scan_id)
    
    if not scan.is_complete:
        flash("Cannot export report for an incomplete scan", "warning")
        return redirect(url_for('scan_progress', scan_id=scan_id))
    
    # Collect findings from all scan components
    findings = []
    scan_components = [
        scan.ip_scan, scan.dns_scan, scan.ssl_scan, scan.http_scan,
        scan.port_scan, scan.cors_scan, scan.whois_scan,
        scan.cookie_scan, scan.disclosure_scan
    ]
    
    for component in scan_components:
        if component:
            component_findings = component.get_findings()
            findings.extend(component_findings)
    
    # Sort findings by severity
    severity_order = {
        'critical': 0,
        'high': 1,
        'medium': 2,
        'low': 3,
        'info': 4
    }
    
    findings.sort(key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5))
    
    # Generate report based on the requested format
    if format.lower() == 'pdf':
        return create_pdf_report(scan, findings)
    elif format.lower() == 'json':
        return create_json_report(scan, findings)
    elif format.lower() == 'csv':
        return create_csv_report(scan, findings)
    else:
        flash(f"Unsupported export format: {format}", "danger")
        return redirect(url_for('scan_result', scan_id=scan_id))

def create_pdf_report(scan, findings):
    """Create a PDF report of scan findings"""
    buffer = io.BytesIO()
    
    # Create the PDF document
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Add custom styles
    custom_title_style = ParagraphStyle(name='CustomTitle', 
                             parent=styles['Heading1'], 
                             fontName='Helvetica-Bold',
                             fontSize=16,
                             spaceAfter=16)
    
    custom_heading_style = ParagraphStyle(name='CustomHeading', 
                             parent=styles['Heading2'], 
                             fontName='Helvetica-Bold',
                             fontSize=14,
                             spaceAfter=10)
    
    custom_normal_style = ParagraphStyle(name='CustomNormal', 
                             parent=styles['Normal'], 
                             fontName='Helvetica',
                             fontSize=10)
    
    # Initialize story elements
    elements = []
    
    # Add report title
    elements.append(Paragraph(f"Security Scan Report: {scan.target_url}", custom_title_style))
    elements.append(Spacer(1, 0.25 * inch))
    
    # Add scan details
    elements.append(Paragraph("Scan Details:", custom_heading_style))
    scan_date = scan.scan_date.strftime('%Y-%m-%d %H:%M:%S UTC')
    elements.append(Paragraph(f"<b>Target URL:</b> {scan.target_url}", custom_normal_style))
    elements.append(Paragraph(f"<b>Scan Date:</b> {scan_date}", custom_normal_style))
    elements.append(Spacer(1, 0.25 * inch))
    
    # Add vulnerability summary
    elements.append(Paragraph("Vulnerability Summary:", custom_heading_style))
    summary_data = [
        ["Severity", "Count"],
        ["Critical", str(scan.critical_count)],
        ["High", str(scan.high_count)],
        ["Medium", str(scan.medium_count)],
        ["Low", str(scan.low_count)],
        ["Info", str(scan.info_count)]
    ]
    
    summary_table = Table(summary_data, colWidths=[2 * inch, 1 * inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (1, 0), 12),
        ('BACKGROUND', (0, 1), (0, 1), colors.darkred),
        ('BACKGROUND', (0, 2), (0, 2), colors.orange),
        ('BACKGROUND', (0, 3), (0, 3), colors.blue),
        ('BACKGROUND', (0, 4), (0, 4), colors.lightblue),
        ('BACKGROUND', (0, 5), (0, 5), colors.grey),
        ('TEXTCOLOR', (0, 1), (0, 5), colors.whitesmoke),
        ('GRID', (0, 0), (1, 5), 1, colors.black),
        ('ALIGN', (1, 1), (1, 5), 'CENTER'),
        ('VALIGN', (0, 0), (1, 5), 'MIDDLE')
    ]))
    
    elements.append(summary_table)
    elements.append(Spacer(1, 0.25 * inch))
    
    # Add detailed findings
    elements.append(Paragraph("Detailed Findings:", custom_heading_style))
    if findings:
        for i, finding in enumerate(findings):
            # Add severity indicator
            severity = finding.get('severity', 'info').lower()
            severity_color = {
                'critical': colors.darkred,
                'high': colors.orange,
                'medium': colors.blue,
                'low': colors.lightblue,
                'info': colors.grey
            }.get(severity, colors.grey)
            
            # Create a severity indicator table
            severity_table = Table([[severity.upper()]], colWidths=[1 * inch])
            severity_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, 0), severity_color),
                ('TEXTCOLOR', (0, 0), (0, 0), colors.whitesmoke),
                ('ALIGNMENT', (0, 0), (0, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (0, 0), 10),
                ('BOTTOMPADDING', (0, 0), (0, 0), 6),
                ('TOPPADDING', (0, 0), (0, 0), 6),
            ]))
            
            elements.append(severity_table)
            elements.append(Spacer(1, 0.1 * inch))
            
            # Finding title
            elements.append(Paragraph(f"<b>{finding.get('title', 'Unknown Issue')}</b>", custom_normal_style))
            
            # Finding description
            if 'description' in finding:
                elements.append(Paragraph(f"<b>Description:</b> {finding.get('description')}", custom_normal_style))
            
            # Finding recommendation
            if 'recommendation' in finding:
                elements.append(Paragraph(f"<b>Recommendation:</b> {finding.get('recommendation')}", custom_normal_style))
            
            # Finding component
            if 'component' in finding:
                elements.append(Paragraph(f"<b>Component:</b> {finding.get('component')}", custom_normal_style))
            
            elements.append(Spacer(1, 0.15 * inch))
    else:
        elements.append(Paragraph("No findings to report.", custom_normal_style))
    
    # Build the PDF document
    doc.build(elements)
    
    # Set up the response
    buffer.seek(0)
    scan_date_for_filename = scan.scan_date.strftime('%Y%m%d_%H%M%S')
    target_for_filename = scan.target_url.replace('https://', '').replace('http://', '').replace('/', '_').replace('.', '_')
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"security_scan_{target_for_filename}_{scan_date_for_filename}.pdf",
        mimetype='application/pdf'
    )

def create_json_report(scan, findings):
    """Create a JSON report of scan findings"""
    # Convert scan data to a more json-friendly structure
    scan_date = scan.scan_date.strftime('%Y-%m-%d %H:%M:%S UTC')
    
    # Create report structure
    report_data = {
        'scan_id': scan.id,
        'target_url': scan.target_url,
        'scan_date': scan_date,
        'vulnerability_summary': {
            'critical': scan.critical_count,
            'high': scan.high_count,
            'medium': scan.medium_count,
            'low': scan.low_count,
            'info': scan.info_count,
            'total': scan.critical_count + scan.high_count + scan.medium_count + scan.low_count + scan.info_count
        },
        'findings': findings
    }
    
    # Format the JSON
    formatted_json = json.dumps(report_data, indent=4)
    
    # Generate the filename
    scan_date_for_filename = scan.scan_date.strftime('%Y%m%d_%H%M%S')
    target_for_filename = scan.target_url.replace('https://', '').replace('http://', '').replace('/', '_').replace('.', '_')
    filename = f"security_scan_{target_for_filename}_{scan_date_for_filename}.json"
    
    # Create response
    response = Response(
        formatted_json,
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment; filename={filename}'
        }
    )
    
    return response

def create_csv_report(scan, findings):
    """Create a CSV report of scan findings"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'Severity', 'Title', 'Description', 'Recommendation', 'Component', 'Scan Date', 'Target URL'
    ])
    
    # Write scan data rows
    scan_date = scan.scan_date.strftime('%Y-%m-%d %H:%M:%S UTC')
    
    if findings:
        for finding in findings:
            writer.writerow([
                finding.get('severity', 'Unknown'),
                finding.get('title', 'Unknown Issue'),
                finding.get('description', ''),
                finding.get('recommendation', ''),
                finding.get('component', ''),
                scan_date,
                scan.target_url
            ])
    else:
        writer.writerow(['Info', 'No findings', 'No security issues were found', '', '', scan_date, scan.target_url])
    
    # Reset the io position and create the response
    output.seek(0)
    
    # Generate the filename
    scan_date_for_filename = scan.scan_date.strftime('%Y%m%d_%H%M%S')
    target_for_filename = scan.target_url.replace('https://', '').replace('http://', '').replace('/', '_').replace('.', '_')
    filename = f"security_scan_{target_for_filename}_{scan_date_for_filename}.csv"
    
    # Create response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename={filename}'
        }
    )
