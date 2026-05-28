import os
import json
import threading
from flask import Blueprint, render_template, flash, redirect, url_for, session, current_app, Response, jsonify, request
from werkzeug.utils import secure_filename
from flask_login import login_required, current_user
from web.forms import ScanForm
from scanner.input_handler import InputHandler
from scanner.code_extractor import CodeExtractor
from scanner.core_engine import CoreAnalysisEngine
from scanner.report_generator import ReportGenerator
from models import db, ScanResult, User, ManagerLink

main_bp = Blueprint('main', __name__)

_scan_jobs = {}


def _run_scan_background(app, user_id, source, input_method, max_depth=6, js_only=False):
    """Run scan in background thread."""
    with app.app_context():
        try:
            input_handler = InputHandler()
            extractor = CodeExtractor()
            engine = CoreAnalysisEngine()
            all_extracted_urls = []

            if os.path.isdir(source):
                file_paths = input_handler.get_files_from_folder(source, max_depth=max_depth, js_only=js_only)
                if not file_paths:
                    _scan_jobs[user_id] = {'status': 'error', 'message': 'No supported files found.'}
                    return
                all_parts = []
                for fp in file_paths:
                    try:
                        data = input_handler.accept_input(fp)
                        if data is None:
                            continue
                        parts = extractor.extract_with_origins(data['html'], external_js=data['external_js'])
                        if parts:
                            all_parts.extend([(fp, code, off) for _, code, off in parts])
                    except Exception:
                        continue
                if not all_parts:
                    _scan_jobs[user_id] = {'status': 'error', 'message': 'No JavaScript code found.'}
                    return
                vulnerabilities, extracted_urls, testing_report, code_info = engine.scan(all_parts, source)
                all_extracted_urls = extracted_urls
            else:
                input_data = input_handler.accept_input(source)
                if input_data is None:
                    _scan_jobs[user_id] = {'status': 'error', 'message': 'Invalid source.'}
                    return
                parts = extractor.extract_with_origins(input_data['html'], external_js=input_data['external_js'])
                if not parts:
                    _scan_jobs[user_id] = {'status': 'error', 'message': 'No JavaScript code found.'}
                    return
                vulnerabilities, extracted_urls, testing_report, code_info = engine.scan(parts, source)
                all_extracted_urls = extracted_urls

            summary = ReportGenerator.generate_summary(vulnerabilities)
            vuln_dicts = ReportGenerator.to_dict_list(vulnerabilities)

            scan_result = ScanResult(
                user_id=user_id,
                source=source,
                input_method=input_method,
                total_vulns=len(vulnerabilities),
                critical_count=summary['severity_counts']['Critical'],
                high_count=summary['severity_counts']['High'],
                medium_count=summary['severity_counts']['Medium'],
                low_count=summary['severity_counts']['Low'],
                extracted_urls=json.dumps(all_extracted_urls),
                results_json=json.dumps(vuln_dicts),
                summary_json=json.dumps(summary),
                testing_json=json.dumps(testing_report),
                is_minified=code_info.get('is_minified', False),
                is_obfuscated=code_info.get('is_obfuscated', False),
                was_beautified=code_info.get('was_beautified', False),
                deobfuscation_method=code_info.get('deobfuscation_method'),
            )
            db.session.add(scan_result)
            db.session.commit()

            _scan_jobs[user_id] = {'status': 'done', 'scan_id': scan_result.id, 'total': len(vulnerabilities)}

        except Exception as e:
            _scan_jobs[user_id] = {'status': 'error', 'message': str(e)}


@main_bp.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if current_user.is_manager:
        return redirect(url_for('main.manager_panel'))

    form = ScanForm()
    recent_scans = ScanResult.query.filter_by(user_id=current_user.id)\
        .order_by(ScanResult.scanned_at.desc()).limit(10).all()

    if form.validate_on_submit():
        source = None
        input_method = 'file'
        if form.file_upload.data:
            file = form.file_upload.data
            filename = secure_filename(file.filename)
            upload_folder = current_app.config['UPLOAD_FOLDER']
            os.makedirs(upload_folder, exist_ok=True)
            filepath = os.path.join(upload_folder, filename)
            file.save(filepath)
            source = filepath
            input_method = 'file'
        elif form.url_input.data:
            source = form.url_input.data.strip()
            input_method = 'url'
        elif form.folder_path.data:
            folder = form.folder_path.data.strip()
            if os.path.isdir(folder):
                source = folder
                input_method = 'folder'
            else:
                flash('Invalid folder path.', 'danger')
                return render_template('index.html', form=form, recent_scans=recent_scans)

        if source:
            _scan_jobs[current_user.id] = {'status': 'running'}
            app = current_app._get_current_object()
            max_depth = int(form.scan_depth.data) if form.folder_path.data else 6
            js_only = form.js_only.data if form.folder_path.data else False
            t = threading.Thread(target=_run_scan_background, args=(app, current_user.id, source, input_method, max_depth, js_only))
            t.daemon = True
            t.start()
            return render_template('index.html', form=form, recent_scans=recent_scans, scan_started=True)
        else:
            flash('Please provide a file, URL, or folder path.', 'warning')

    return render_template('index.html', form=form, recent_scans=recent_scans)


@main_bp.route('/scan/status')
@login_required
def scan_status():
    job = _scan_jobs.get(current_user.id)
    if not job:
        return jsonify({'status': 'idle'})
    return jsonify(job)


@main_bp.route('/scan/<int:scan_id>')
@login_required
def view_scan(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)
    if not current_user.is_manager and scan_result.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))
    # Manager can only view linked developers' scans
    if current_user.is_manager:
        link = ManagerLink.query.filter_by(manager_id=current_user.id, developer_id=scan_result.user_id).first()
        if not link:
            flash('Access denied. Developer not linked.', 'danger')
            return redirect(url_for('main.manager_panel'))

    _scan_jobs.pop(current_user.id, None)

    vulnerabilities = scan_result.get_vulnerabilities()
    summary = scan_result.get_summary()
    extracted_urls = scan_result.get_extracted_urls()
    testing_report = scan_result.get_testing_report()

    # Manager sees general/summary view, developer sees full technical detail
    if current_user.is_manager:
        return render_template('manager_scan_view.html',
                               vulnerabilities=vulnerabilities,
                               summary=summary,
                               source=scan_result.source,
                               testing_report=testing_report,
                               scan_id=scan_id,
                               scanned_at=scan_result.scanned_at,
                               developer=scan_result.user.full_name)

    return render_template('scan_result.html',
                           vulnerabilities=vulnerabilities,
                           summary=summary,
                           source=scan_result.source,
                           extracted_urls=extracted_urls,
                           testing_report=testing_report,
                           skipped_files=[],
                           scan_id=scan_id,
                           scanned_at=scan_result.scanned_at,
                           is_minified=scan_result.is_minified,
                           was_beautified=scan_result.was_beautified,
                           deobfuscation_method=scan_result.deobfuscation_method,
                           developer=scan_result.user.full_name)


@main_bp.route('/manager', methods=['GET', 'POST'])
@login_required
def manager_panel():
    if not current_user.is_manager:
        flash('Access denied. Manager role required.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Handle adding developer by invite code
    if request.method == 'POST':
        code = request.form.get('invite_code', '').strip().upper()
        if code:
            dev = User.query.filter_by(invite_code=code, role='developer').first()
            if not dev:
                flash('Invalid invite code.', 'danger')
            elif ManagerLink.query.filter_by(manager_id=current_user.id, developer_id=dev.id).first():
                flash(f'{dev.full_name} is already linked.', 'warning')
            else:
                link = ManagerLink(manager_id=current_user.id, developer_id=dev.id)
                db.session.add(link)
                db.session.commit()
                flash(f'✓ {dev.full_name} linked successfully!', 'success')

    # Get only linked developers
    links = ManagerLink.query.filter_by(manager_id=current_user.id).all()
    linked_dev_ids = [l.developer_id for l in links]
    developers = User.query.filter(User.id.in_(linked_dev_ids)).all() if linked_dev_ids else []

    # Get scans only from linked developers
    all_scans = ScanResult.query.filter(ScanResult.user_id.in_(linked_dev_ids))\
        .order_by(ScanResult.scanned_at.desc()).all() if linked_dev_ids else []

    total_scans = len(all_scans)
    total_vulns = sum(s.total_vulns for s in all_scans)
    total_critical = sum(s.critical_count for s in all_scans)

    vuln_counts = {}
    for scan in all_scans:
        for v in scan.get_vulnerabilities():
            vtype = v.get('type', 'Unknown')
            sev = v.get('severity', 'Medium')
            if vtype not in vuln_counts:
                vuln_counts[vtype] = {'count': 0, 'severity': sev}
            vuln_counts[vtype]['count'] += 1
    top_vulns = sorted([(k, v['count'], v['severity']) for k, v in vuln_counts.items()],
                       key=lambda x: x[1], reverse=True)[:10]

    dev_stats = []
    for dev in developers:
        dev_scans = [s for s in all_scans if s.user_id == dev.id]
        dev_stats.append({
            'name': dev.full_name, 'username': dev.username,
            'scan_count': len(dev_scans),
            'critical': sum(s.critical_count for s in dev_scans),
            'high': sum(s.high_count for s in dev_scans),
            'medium': sum(s.medium_count for s in dev_scans),
            'total': sum(s.total_vulns for s in dev_scans),
        })
    dev_stats.sort(key=lambda x: x['critical'], reverse=True)

    return render_template('manager_panel.html',
                           scans=all_scans, developers=developers,
                           total_scans=total_scans, total_vulns=total_vulns,
                           total_critical=total_critical,
                           top_vulns=top_vulns, dev_stats=dev_stats, links=links)


@main_bp.route('/manager/unlink/<int:dev_id>', methods=['POST'])
@login_required
def unlink_developer(dev_id):
    if not current_user.is_manager:
        return redirect(url_for('main.dashboard'))
    link = ManagerLink.query.filter_by(manager_id=current_user.id, developer_id=dev_id).first()
    if link:
        db.session.delete(link)
        db.session.commit()
        flash('Developer unlinked.', 'success')
    return redirect(url_for('main.manager_panel'))


@main_bp.route('/manager/scan/<int:scan_id>/pdf')
@login_required
def manager_scan_pdf(scan_id):
    """Download individual scan report named by domain."""
    if not current_user.is_manager:
        return redirect(url_for('main.dashboard'))
    scan = ScanResult.query.get_or_404(scan_id)
    link = ManagerLink.query.filter_by(manager_id=current_user.id, developer_id=scan.user_id).first()
    if not link:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.manager_panel'))

    vulns = scan.get_vulnerabilities()
    summary = scan.get_summary()
    # Extract domain for filename
    from urllib.parse import urlparse
    source = scan.source
    if source.startswith('http'):
        domain = urlparse(source).netloc.replace('www.', '')
    else:
        domain = source.split('/')[-1].replace('.js', '').replace('.html', '')
    filename = f"{domain}-REPORT.pdf"

    html = render_template('manager_general_report_pdf.html',
                           source=scan.source, summary=summary,
                           vulnerabilities=vulns, developer=scan.user.full_name,
                           scanned_at=scan.scanned_at, domain=domain,
                           manager_name=current_user.full_name)
    try:
        from weasyprint import HTML
        pdf = HTML(string=html).write_pdf()
        return Response(pdf, mimetype='application/pdf',
                        headers={'Content-Disposition': f'attachment;filename={filename}'})
    except Exception as e:
        flash(f'PDF failed: {e}', 'danger')
        return redirect(url_for('main.manager_panel'))


@main_bp.route('/manager/merged-report')
@login_required
def manager_merged_report():
    """Download ALL-PROJECT-MERGED-REPORT.pdf combining all linked developers' scans."""
    if not current_user.is_manager:
        return redirect(url_for('main.dashboard'))

    links = ManagerLink.query.filter_by(manager_id=current_user.id).all()
    linked_dev_ids = [l.developer_id for l in links]
    if not linked_dev_ids:
        flash('No developers linked.', 'warning')
        return redirect(url_for('main.manager_panel'))

    all_scans = ScanResult.query.filter(ScanResult.user_id.in_(linked_dev_ids))\
        .order_by(ScanResult.scanned_at.desc()).all()
    developers = User.query.filter(User.id.in_(linked_dev_ids)).all()

    html = render_template('manager_report_pdf.html',
                           total_scans=len(all_scans),
                           total_vulns=sum(s.total_vulns for s in all_scans),
                           total_critical=sum(s.critical_count for s in all_scans),
                           total_high=sum(s.high_count for s in all_scans),
                           total_medium=sum(s.medium_count for s in all_scans),
                           dev_stats=[{
                               'name': d.full_name, 'username': d.username,
                               'scan_count': len([s for s in all_scans if s.user_id == d.id]),
                               'critical': sum(s.critical_count for s in all_scans if s.user_id == d.id),
                               'high': sum(s.high_count for s in all_scans if s.user_id == d.id),
                               'medium': sum(s.medium_count for s in all_scans if s.user_id == d.id),
                               'total': sum(s.total_vulns for s in all_scans if s.user_id == d.id),
                           } for d in developers],
                           top_vulns=[], scans=all_scans,
                           generated_by=current_user.full_name)
    try:
        from weasyprint import HTML
        pdf = HTML(string=html).write_pdf()
        return Response(pdf, mimetype='application/pdf',
                        headers={'Content-Disposition': 'attachment;filename=ALL-PROJECT-MERGED-REPORT.pdf'})
    except Exception as e:
        flash(f'PDF failed: {e}', 'danger')
        return redirect(url_for('main.manager_panel'))


@main_bp.route('/manager/report')
@login_required
def manager_report_pdf():
    if not current_user.is_manager:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))

    all_scans = ScanResult.query.order_by(ScanResult.scanned_at.desc()).all()
    developers = User.query.filter_by(role='developer').all()
    total_scans = len(all_scans)
    total_vulns = sum(s.total_vulns for s in all_scans)
    total_critical = sum(s.critical_count for s in all_scans)
    total_high = sum(s.high_count for s in all_scans)
    total_medium = sum(s.medium_count for s in all_scans)

    # Per-developer stats
    dev_stats = []
    for dev in developers:
        dev_scans = [s for s in all_scans if s.user_id == dev.id]
        dev_stats.append({
            'name': dev.full_name, 'username': dev.username,
            'scan_count': len(dev_scans),
            'critical': sum(s.critical_count for s in dev_scans),
            'high': sum(s.high_count for s in dev_scans),
            'medium': sum(s.medium_count for s in dev_scans),
            'total': sum(s.total_vulns for s in dev_scans),
        })

    # Top vulns
    vuln_counts = {}
    for scan in all_scans:
        for v in scan.get_vulnerabilities():
            vtype = v.get('type', 'Unknown')
            sev = v.get('severity', 'Medium')
            if vtype not in vuln_counts:
                vuln_counts[vtype] = {'count': 0, 'severity': sev}
            vuln_counts[vtype]['count'] += 1
    top_vulns = sorted([(k, v['count'], v['severity']) for k, v in vuln_counts.items()],
                       key=lambda x: x[1], reverse=True)[:10]

    html = render_template('manager_report_pdf.html',
                           total_scans=total_scans, total_vulns=total_vulns,
                           total_critical=total_critical, total_high=total_high,
                           total_medium=total_medium, dev_stats=dev_stats,
                           top_vulns=top_vulns, scans=all_scans,
                           generated_by=current_user.full_name)
    try:
        from weasyprint import HTML
        pdf = HTML(string=html).write_pdf()
        return Response(pdf, mimetype='application/pdf',
                        headers={'Content-Disposition': 'attachment;filename=organization_security_report.pdf'})
    except Exception as e:
        flash(f'PDF generation failed: {e}', 'danger')
        return redirect(url_for('main.manager_panel'))


@main_bp.route('/download/<int:scan_id>/<format>')
@login_required
def download_report(scan_id, format):
    """Download report directly from database — no session size limit."""
    scan = ScanResult.query.get_or_404(scan_id)
    if scan.user_id != current_user.id and not current_user.is_manager:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))

    report = {
        'source': scan.source,
        'summary': scan.get_summary(),
        'vulnerabilities': scan.get_vulnerabilities(),
        'extracted_urls': scan.get_extracted_urls(),
        'testing_report': scan.get_testing_report(),
        'developer': scan.user.full_name,
        'skipped_files': [],
    }

    if format == 'json':
        return Response(json.dumps(report, indent=2), mimetype='application/json',
                        headers={'Content-Disposition': f'attachment;filename=secscan_report_{scan_id}.json'})
    elif format == 'html':
        html = render_template('download_report.html', **report)
        return Response(html, mimetype='text/html',
                        headers={'Content-Disposition': f'attachment;filename=secscan_report_{scan_id}.html'})
    elif format == 'pdf':
        try:
            from weasyprint import HTML
            html_content = render_template('download_report.html', **report)
            pdf = HTML(string=html_content).write_pdf()
            return Response(pdf, mimetype='application/pdf',
                            headers={'Content-Disposition': f'attachment;filename=secscan_report_{scan_id}.pdf'})
        except Exception as e:
            flash(f'PDF generation failed: {e}', 'danger')
            return redirect(url_for('main.dashboard'))
    flash('Invalid format.', 'danger')
    return redirect(url_for('main.dashboard'))


@main_bp.route('/history')
@login_required
def history():
    if current_user.is_manager:
        return redirect(url_for('main.manager_panel'))
    scans = ScanResult.query.filter_by(user_id=current_user.id)\
        .order_by(ScanResult.scanned_at.desc()).all()
    return render_template('history.html', scans=scans)


@main_bp.route('/scan/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)
    if scan_result.user_id != current_user.id and not current_user.is_manager:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))
    db.session.delete(scan_result)
    db.session.commit()
    flash('Scan deleted.', 'success')
    return redirect(url_for('main.history'))
