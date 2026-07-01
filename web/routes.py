import os
import json
import threading
import secrets
from flask import Blueprint, render_template, flash, redirect, url_for, session, current_app, Response, jsonify, request
from werkzeug.utils import secure_filename
from flask_login import login_required, current_user
from web.forms import ScanForm
from scanner.input_handler import InputHandler
from scanner.code_extractor import CodeExtractor
from scanner.core_engine import CoreAnalysisEngine
from scanner.report_generator import ReportGenerator
from models import db, ScanResult, User, ManagerDeveloperLink, Institution, Payment, PLANS

main_bp = Blueprint('main', __name__)

_scan_jobs = {}


# ─────────────────────────────────────────────
# Background scan helper
# ─────────────────────────────────────────────

def _run_scan_background(app, user_id, source, input_method, js_only=False):
    """Run scan in background thread. Supports single and batch (input_method='batch') modes."""
    with app.app_context():
        try:
            input_handler = InputHandler()
            extractor = CodeExtractor()
            engine = CoreAnalysisEngine()
            all_extracted_urls = []

            if input_method == 'batch':
                # source is newline-separated URLs; scan each and combine results
                urls = [u.strip() for u in source.splitlines() if u.strip()]
                all_vulnerabilities = []
                all_parts_combined = []
                for url in urls:
                    try:
                        input_data = input_handler.accept_input(url)
                        if input_data is None:
                            continue
                        parts = extractor.extract_with_origins(input_data['html'], external_js=input_data['external_js'])
                        if parts:
                            all_parts_combined.extend(parts)
                            all_extracted_urls.append(url)
                    except Exception:
                        continue
                if not all_parts_combined:
                    _scan_jobs[user_id] = {'status': 'error', 'message': 'No JavaScript found in any of the provided URLs.'}
                    return
                vulnerabilities, extracted_urls, testing_report, code_info = engine.scan(all_parts_combined, ', '.join(urls))
                all_extracted_urls.extend(extracted_urls)
                source_label = f"Batch: {len(urls)} URLs"

            elif os.path.isdir(source):
                file_paths = input_handler.get_files_from_folder(source, js_only=js_only)
                if not file_paths:
                    _scan_jobs[user_id] = {'status': 'error', 'message': 'No supported files found.'}
                    return
                all_parts = []
                scanned_files = []
                for fp in file_paths:
                    try:
                        data = input_handler.accept_input(fp)
                        if data is None:
                            continue
                        parts = extractor.extract_with_origins(data['html'], external_js=data['external_js'])
                        if parts:
                            all_parts.extend([(fp, code, off) for _, code, off in parts])
                            scanned_files.append(os.path.basename(fp))
                    except Exception:
                        continue
                if not all_parts:
                    _scan_jobs[user_id] = {'status': 'error', 'message': 'No JavaScript code found.'}
                    return
                vulnerabilities, extracted_urls, testing_report, code_info = engine.scan(all_parts, source)
                all_extracted_urls = extracted_urls + scanned_files
                source_label = source

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
                source_label = source

            summary = ReportGenerator.generate_summary(vulnerabilities)
            vuln_dicts = ReportGenerator.to_dict_list(vulnerabilities)

            scan_result = ScanResult(
                user_id=user_id,
                source=source_label,
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

            # Increment trial scan counter for free users
            user = db.session.get(User, user_id)
            if user and user.subscription_plan == 'free':
                user.trial_scans_used = (user.trial_scans_used or 0) + 1

            db.session.commit()

            _scan_jobs[user_id] = {'status': 'done', 'scan_id': scan_result.id, 'total': len(vulnerabilities)}

        except Exception as e:
            _scan_jobs[user_id] = {'status': 'error', 'message': str(e)}


# ─────────────────────────────────────────────
# Dashboard / Scanner
# ─────────────────────────────────────────────

@main_bp.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('main.admin_panel'))
    if current_user.is_manager:
        return redirect(url_for('main.manager_panel'))

    form = ScanForm()
    recent_scans = ScanResult.query.filter_by(user_id=current_user.id)\
        .order_by(ScanResult.scanned_at.desc()).limit(10).all()

    if form.validate_on_submit():
        # Check scan quota before doing anything
        if not current_user.can_scan:
            flash('Trial ended. Please subscribe to continue scanning.', 'warning')
            return redirect(url_for('main.subscription'))

        source = None
        input_method = 'file'

        # Batch URLs take priority over other inputs
        batch_raw = form.batch_urls.data.strip() if form.batch_urls.data else ''
        if batch_raw:
            source = batch_raw
            input_method = 'batch'

        elif form.file_upload.data:
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

        # Handle folder upload via browser (webkitdirectory)
        if not source:
            folder_files = request.files.getlist('folder_upload')
            if folder_files and folder_files[0].filename:
                upload_folder = current_app.config['UPLOAD_FOLDER']
                folder_dir = os.path.join(upload_folder, 'folder_scan')
                import shutil
                if os.path.exists(folder_dir):
                    shutil.rmtree(folder_dir)
                os.makedirs(folder_dir, exist_ok=True)
                js_only = request.form.get('js_only') == 'on'
                supported = ('.js',) if js_only else ('.js', '.html', '.php', '.txt')
                saved = 0
                for f in folder_files:
                    fname = f.filename or ''
                    basename = fname.rsplit('/', 1)[-1] if '/' in fname else fname
                    if basename and basename.lower().endswith(supported):
                        safe_name = secure_filename(basename)
                        if not safe_name:
                            continue
                        dest = os.path.join(folder_dir, safe_name)
                        if os.path.exists(dest):
                            name, ext = os.path.splitext(safe_name)
                            dest = os.path.join(folder_dir, f"{name}_{saved}{ext}")
                        f.save(dest)
                        saved += 1
                if saved > 0:
                    source = folder_dir
                    input_method = 'folder'
                else:
                    flash('No supported files found in the selected folder.', 'warning')
                    return render_template('index.html', form=form, recent_scans=recent_scans)

        js_only_flag = request.form.get('js_only') == 'on'

        if source:
            _scan_jobs[current_user.id] = {'status': 'running'}
            app = current_app._get_current_object()
            t = threading.Thread(
                target=_run_scan_background,
                args=(app, current_user.id, source, input_method, js_only_flag)
            )
            t.daemon = True
            t.start()
            return render_template('index.html', form=form, recent_scans=recent_scans, scan_started=True)
        else:
            flash('Please provide a file, URL, folder path, or batch URLs.', 'warning')

    return render_template('index.html', form=form, recent_scans=recent_scans)


@main_bp.route('/scan/status')
@login_required
def scan_status():
    job = _scan_jobs.get(current_user.id)
    if not job:
        return jsonify({'status': 'idle'})
    return jsonify(job)


# ─────────────────────────────────────────────
# Scan view / download / history / delete
# ─────────────────────────────────────────────

@main_bp.route('/scan/<int:scan_id>')
@login_required
def view_scan(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)

    # Access control
    if not current_user.is_admin:
        if not current_user.is_manager and scan_result.user_id != current_user.id:
            flash('Access denied.', 'danger')
            return redirect(url_for('main.dashboard'))
        if current_user.is_manager:
            link = ManagerDeveloperLink.query.filter_by(
                manager_id=current_user.id, developer_id=scan_result.user_id
            ).first()
            if not link:
                flash('Access denied. Developer not linked to you.', 'danger')
                return redirect(url_for('main.manager_panel'))

    _scan_jobs.pop(current_user.id, None)

    _sev = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
    vulnerabilities = sorted(scan_result.get_vulnerabilities(), key=lambda v: _sev.get(v.get('severity','Medium'), 2))
    summary = scan_result.get_summary()
    extracted_urls = scan_result.get_extracted_urls()
    testing_report = scan_result.get_testing_report()

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


@main_bp.route('/download/<int:scan_id>/<format>')
@login_required
def download_report(scan_id, format):
    scan = ScanResult.query.get_or_404(scan_id)
    if scan.user_id != current_user.id and not current_user.is_manager and not current_user.is_admin:
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
    if scan_result.user_id != current_user.id and not current_user.is_manager and not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))
    db.session.delete(scan_result)
    db.session.commit()
    flash('Scan deleted.', 'success')
    return redirect(url_for('main.history'))


# ─────────────────────────────────────────────
# Admin Panel
# ─────────────────────────────────────────────

@main_bp.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('Access denied. Admin role required.', 'danger')
        return redirect(url_for('main.dashboard'))

    total_users = User.query.count()
    total_scans = ScanResult.query.count()
    total_vulns = db.session.query(db.func.sum(ScanResult.total_vulns)).scalar() or 0
    revenue = db.session.query(db.func.sum(Payment.amount_tzs))\
        .filter(Payment.status == 'confirmed').scalar() or 0
    active_subs = User.query.filter(User.subscription_plan != 'free').count()

    users = User.query.order_by(User.created_at.desc()).all()
    user_stats = []
    for u in users:
        scan_count = ScanResult.query.filter_by(user_id=u.id).count()
        user_stats.append({
            'user': u,
            'scan_count': scan_count,
        })

    all_payments = Payment.query.order_by(Payment.created_at.desc()).all()

    # Count roles and plans for new template
    role_counts = {}
    plan_counts = {}
    for u in User.query.all():
        role_counts[u.role] = role_counts.get(u.role, 0) + 1
        plan_counts[u.subscription_plan] = plan_counts.get(u.subscription_plan, 0) + 1
    paid_users = sum(v for k, v in plan_counts.items() if k != 'free')
    recent_payments = Payment.query.order_by(Payment.created_at.desc()).limit(20).all()
    all_users = User.query.order_by(User.created_at.desc()).all()

    return render_template('admin_panel.html',
                           total_users=total_users,
                           total_scans=total_scans,
                           total_vulns=total_vulns,
                           paid_users=paid_users,
                           role_counts=role_counts,
                           plan_counts=plan_counts,
                           all_users=all_users,
                           recent_payments=recent_payments)


@main_bp.route('/admin/create-manager', methods=['POST'])
@login_required
def admin_create_manager():
    if not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))

    from flask_bcrypt import Bcrypt
    from auth.routes import bcrypt as auth_bcrypt

    full_name = request.form.get('full_name', '').strip()
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()

    if not all([full_name, username, email, password]):
        flash('All fields are required to create a manager.', 'danger')
        return redirect(url_for('main.admin_panel'))

    if User.query.filter_by(username=username).first():
        flash(f'Username "{username}" is already taken.', 'danger')
        return redirect(url_for('main.admin_panel'))
    if User.query.filter_by(email=email).first():
        flash(f'Email "{email}" is already registered.', 'danger')
        return redirect(url_for('main.admin_panel'))

    hashed = auth_bcrypt.generate_password_hash(password).decode('utf-8')
    manager = User(
        full_name=full_name,
        username=username,
        email=email,
        role='manager',
        password_hash=hashed,
        subscription_plan='enterprise',  # managers get full access
    )
    db.session.add(manager)
    db.session.commit()
    flash(f'✓ Manager account created for {full_name} (@{username}).', 'success')
    return redirect(url_for('main.admin_panel'))


# ─────────────────────────────────────────────
# Manager Panel
# ─────────────────────────────────────────────

@main_bp.route('/manager', methods=['GET'])
@login_required
def manager_panel():
    if not current_user.is_manager:
        flash('Access denied. Manager role required.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Get only developers created by this manager
    links = ManagerDeveloperLink.query.filter_by(manager_id=current_user.id).all()
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
            'id': dev.id,
            'name': dev.full_name,
            'username': dev.username,
            'scan_count': len(dev_scans),
            'critical': sum(s.critical_count for s in dev_scans),
            'high': sum(s.high_count for s in dev_scans),
            'medium': sum(s.medium_count for s in dev_scans),
            'total': sum(s.total_vulns for s in dev_scans),
        })
    dev_stats.sort(key=lambda x: x['critical'], reverse=True)

    total_high = sum(s.high_count for s in all_scans)
    total_medium = sum(s.medium_count for s in all_scans)
    total_low = sum(s.low_count for s in all_scans)

    return render_template('manager_panel.html',
                           scans=all_scans, developers=developers,
                           total_scans=total_scans, total_vulns=total_vulns,
                           total_critical=total_critical,
                           total_high=total_high, total_medium=total_medium,
                           total_low=total_low,
                           top_vulns=top_vulns, dev_stats=dev_stats)


@main_bp.route('/manager/create-developer', methods=['POST'])
@login_required
def manager_create_developer():
    if not current_user.is_manager:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))

    from auth.routes import bcrypt as auth_bcrypt

    full_name = request.form.get('full_name', '').strip()
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()

    if not all([full_name, username, email, password]):
        flash('All fields are required.', 'danger')
        return redirect(url_for('main.manager_panel'))

    if User.query.filter_by(username=username).first():
        flash(f'Username "{username}" is already taken.', 'danger')
        return redirect(url_for('main.manager_panel'))
    if User.query.filter_by(email=email).first():
        flash(f'Email "{email}" is already registered.', 'danger')
        return redirect(url_for('main.manager_panel'))

    hashed = auth_bcrypt.generate_password_hash(password).decode('utf-8')
    dev = User(
        full_name=full_name,
        username=username,
        email=email,
        role='developer',
        password_hash=hashed,
        subscription_plan='pro',  # manager-created devs get pro
    )
    db.session.add(dev)
    db.session.flush()
    link = ManagerDeveloperLink(manager_id=current_user.id, developer_id=dev.id)
    db.session.add(link)
    db.session.commit()
    flash(f'✓ Developer account created for {full_name} (@{username}).', 'success')
    return redirect(url_for('main.manager_panel'))


@main_bp.route('/manager/scan/<int:scan_id>/pdf')
@login_required
def manager_scan_pdf(scan_id):
    if not current_user.is_manager:
        return redirect(url_for('main.dashboard'))
    scan = ScanResult.query.get_or_404(scan_id)
    link = ManagerDeveloperLink.query.filter_by(
        manager_id=current_user.id, developer_id=scan.user_id
    ).first()
    if not link:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.manager_panel'))

    vulns = scan.get_vulnerabilities()
    summary = scan.get_summary()
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
    if not current_user.is_manager:
        return redirect(url_for('main.dashboard'))

    links = ManagerDeveloperLink.query.filter_by(manager_id=current_user.id).all()
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

    links = ManagerDeveloperLink.query.filter_by(manager_id=current_user.id).all()
    linked_dev_ids = [l.developer_id for l in links]
    all_scans = ScanResult.query.filter(ScanResult.user_id.in_(linked_dev_ids))\
        .order_by(ScanResult.scanned_at.desc()).all() if linked_dev_ids else []
    developers = User.query.filter(User.id.in_(linked_dev_ids)).all() if linked_dev_ids else []

    total_scans = len(all_scans)
    total_vulns = sum(s.total_vulns for s in all_scans)
    total_critical = sum(s.critical_count for s in all_scans)
    total_high = sum(s.high_count for s in all_scans)
    total_medium = sum(s.medium_count for s in all_scans)

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


# ─────────────────────────────────────────────
# Institution Dashboard
# ─────────────────────────────────────────────

@main_bp.route('/institution')
@login_required
def institution_dashboard():
    if not current_user.is_institution:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))

    devs = User.query.filter_by(
        institution_id=current_user.institution_id,
        role='developer'
    ).all()

    all_scans = [s for d in devs for s in d.scans]
    total_scans = len(all_scans)
    total_vulns = sum(s.total_vulns for s in all_scans)
    total_critical = sum(s.critical_count for s in all_scans)

    # Top vuln types
    vuln_counts = {}
    for scan in all_scans:
        for v in scan.get_vulnerabilities():
            vtype = v.get('type', 'Unknown')
            sev = v.get('severity', 'Medium')
            if vtype not in vuln_counts:
                vuln_counts[vtype] = {'count': 0, 'severity': sev}
            vuln_counts[vtype]['count'] += 1
    top_vulns = sorted(
        [(k, v['count'], v['severity']) for k, v in vuln_counts.items()],
        key=lambda x: x[1], reverse=True
    )[:10]

    # Institution name
    inst = current_user.institution
    institution_name = inst.name if inst else current_user.full_name

    return render_template('institution_dashboard.html',
                           devs=devs,
                           institution_name=institution_name,
                           total_developers=len(devs),
                           total_scans=total_scans,
                           total_vulns=total_vulns,
                           total_critical=total_critical,
                           top_vulns=top_vulns)


@main_bp.route('/institution/add-developer', methods=['POST'])
@login_required
def institution_add_developer():
    if not current_user.is_institution:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))

    from auth.routes import bcrypt as auth_bcrypt

    full_name = request.form.get('full_name', '').strip()
    username  = request.form.get('username', '').strip()
    email     = request.form.get('email', '').strip()
    password  = request.form.get('password', '').strip()

    if not all([full_name, username, email, password]):
        flash('All fields are required.', 'danger')
        return redirect(url_for('main.institution_dashboard'))

    if User.query.filter_by(username=username).first():
        flash(f'Username "{username}" already taken.', 'danger')
        return redirect(url_for('main.institution_dashboard'))
    if User.query.filter_by(email=email).first():
        flash(f'Email "{email}" already registered.', 'danger')
        return redirect(url_for('main.institution_dashboard'))

    hashed = auth_bcrypt.generate_password_hash(password).decode('utf-8')
    dev = User(
        full_name=full_name,
        username=username,
        email=email,
        role='developer',
        password_hash=hashed,
        institution_id=current_user.institution_id,
        subscription_plan='pro',
    )
    db.session.add(dev)
    db.session.commit()
    flash(f'✓ Developer {full_name} (@{username}) created.', 'success')
    return redirect(url_for('main.institution_dashboard'))


# ─────────────────────────────────────────────
# Subscription / Payment
# ─────────────────────────────────────────────

@main_bp.route('/subscription')
@login_required
def subscription():
    from models import TRIAL_SCANS
    payments = current_user.payments if hasattr(current_user, 'payments') else []
    return render_template('subscription.html', plans=PLANS, user=current_user,
                           payments=payments, trial_scans=TRIAL_SCANS)


@main_bp.route('/subscription/pay/<plan>', methods=['POST'])
@login_required
def pay_subscription(plan):
    if plan not in PLANS:
        flash('Invalid plan.', 'danger')
        return redirect(url_for('main.subscription'))

    if plan == 'free':
        flash('You are already on the free plan.', 'info')
        return redirect(url_for('main.subscription'))

    plan_info = PLANS[plan]
    # Accept user-supplied reference from M-Pesa modal, or generate one
    user_reference = request.form.get('reference', '').strip()
    if not user_reference:
        user_reference = secrets.token_hex(8).upper()

    payment = Payment(
        user_id=current_user.id,
        plan=plan,
        amount_tzs=plan_info['price_tzs'],
        reference=user_reference,
        status='pending',
    )
    db.session.add(payment)
    db.session.commit()

    flash(
        f'Payment request submitted (Ref: {user_reference}). '
        f'Your plan will be activated once the payment is confirmed.',
        'success'
    )
    return redirect(url_for('main.subscription'))
