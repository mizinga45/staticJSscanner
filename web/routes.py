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
from models import db, ScanResult

main_bp = Blueprint('main', __name__)

# In-memory store for background scan status per user
_scan_jobs = {}  # user_id -> {'status': 'running'|'done'|'error', 'scan_id': int, 'message': str}


def _run_scan_background(app, user_id, source, upload_folder):
    """Run scan in background thread."""
    with app.app_context():
        try:
            input_handler = InputHandler()
            extractor = CodeExtractor()
            engine = CoreAnalysisEngine()
            skipped_files = []
            all_extracted_urls = []

            if os.path.isdir(source):
                file_paths = input_handler.get_files_from_folder(source)
                if not file_paths:
                    _scan_jobs[user_id] = {'status': 'error', 'message': 'No supported files found in folder.'}
                    return

                all_parts = []
                for file_path in file_paths:
                    try:
                        file_data = input_handler.accept_input(file_path)
                        if file_data is None:
                            continue
                        parts = extractor.extract_with_origins(file_data['html'], external_js=file_data['external_js'])
                        if not parts:
                            skipped_files.append(file_path)
                            continue
                        renamed_parts = [(file_path, code, offset) for _, code, offset in parts]
                        for i, (fp, code, offset) in enumerate(renamed_parts):
                            if CodeExtractor.is_obfuscated(code):
                                renamed_parts[i] = (fp, CodeExtractor.beautify(code), offset)
                        all_parts.extend(renamed_parts)
                    except Exception:
                        continue

                if not all_parts:
                    _scan_jobs[user_id] = {'status': 'error', 'message': 'No JavaScript code found in folder.'}
                    return

                vulnerabilities, extracted_urls = engine.scan(all_parts, source)
                all_extracted_urls = extracted_urls
            else:
                input_data = input_handler.accept_input(source)
                if input_data is None:
                    _scan_jobs[user_id] = {'status': 'error', 'message': 'Invalid source or inaccessible path.'}
                    return

                parts = extractor.extract_with_origins(input_data['html'], external_js=input_data['external_js'])
                if not parts:
                    _scan_jobs[user_id] = {'status': 'error', 'message': 'No JavaScript code found.'}
                    return

                beautified_parts = []
                for src_id, code, line_offset in parts:
                    if CodeExtractor.is_obfuscated(code):
                        code = CodeExtractor.beautify(code)
                    beautified_parts.append((src_id, code, line_offset))
                parts = beautified_parts

                vulnerabilities, extracted_urls = engine.scan(parts, source)
                all_extracted_urls = extracted_urls

            summary = ReportGenerator.generate_summary(vulnerabilities)
            vuln_dicts = ReportGenerator.to_dict_list(vulnerabilities)

            scan_result = ScanResult(
                user_id=user_id,
                source=source,
                total_vulns=len(vulnerabilities),
                critical_count=summary['severity_counts']['Critical'],
                high_count=summary['severity_counts']['High'],
                medium_count=summary['severity_counts']['Medium'],
                low_count=summary['severity_counts']['Low'],
                extracted_urls=json.dumps(all_extracted_urls),
                results_json=json.dumps(vuln_dicts),
                summary_json=json.dumps(summary)
            )
            db.session.add(scan_result)
            db.session.commit()

            _scan_jobs[user_id] = {'status': 'done', 'scan_id': scan_result.id, 'total': len(vulnerabilities)}

        except Exception as e:
            _scan_jobs[user_id] = {'status': 'error', 'message': str(e)}


@main_bp.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = ScanForm()
    recent_scans = ScanResult.query.filter_by(user_id=current_user.id)\
        .order_by(ScanResult.scanned_at.desc()).limit(10).all()

    if form.validate_on_submit():
        source = None
        if form.file_upload.data:
            file = form.file_upload.data
            filename = secure_filename(file.filename)
            upload_folder = current_app.config['UPLOAD_FOLDER']
            os.makedirs(upload_folder, exist_ok=True)
            filepath = os.path.join(upload_folder, filename)
            file.save(filepath)
            source = filepath
        elif form.url_input.data:
            source = form.url_input.data.strip()
        elif form.folder_path.data:
            folder = form.folder_path.data.strip()
            if os.path.isdir(folder):
                source = folder
            else:
                flash('Invalid folder path.', 'danger')
                return render_template('index.html', form=form, recent_scans=recent_scans)

        if source:
            # Start background scan
            _scan_jobs[current_user.id] = {'status': 'running', 'message': 'Scan started...'}
            app = current_app._get_current_object()
            t = threading.Thread(target=_run_scan_background, args=(app, current_user.id, source, current_app.config['UPLOAD_FOLDER']))
            t.daemon = True
            t.start()
            return render_template('index.html', form=form, recent_scans=recent_scans, scan_started=True)
        else:
            flash('Please provide a file, URL, or folder path.', 'warning')

    return render_template('index.html', form=form, recent_scans=recent_scans)


@main_bp.route('/scan/status')
@login_required
def scan_status():
    """AJAX endpoint to check background scan status."""
    job = _scan_jobs.get(current_user.id)
    if not job:
        return jsonify({'status': 'idle'})
    return jsonify(job)


@main_bp.route('/scan/<int:scan_id>')
@login_required
def view_scan(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)
    if scan_result.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))

    vulnerabilities = scan_result.get_vulnerabilities()
    summary = scan_result.get_summary()
    extracted_urls = scan_result.get_extracted_urls()

    session['report_data'] = {
        'source': scan_result.source,
        'summary': summary,
        'vulnerabilities': vulnerabilities,
        'skipped_files': [],
        'extracted_urls': extracted_urls
    }

    return render_template('scan_result.html',
                           vulnerabilities=vulnerabilities,
                           summary=summary,
                           source=scan_result.source,
                           extracted_urls=extracted_urls,
                           skipped_files=[],
                           scan_id=scan_id,
                           scanned_at=scan_result.scanned_at)


@main_bp.route('/download/<format>')
@login_required
def download_report(format):
    report = session.get('report_data')
    if not report:
        flash('No report available. Please run a scan first.', 'warning')
        return redirect(url_for('main.dashboard'))

    if format == 'json':
        return Response(
            json.dumps(report, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment;filename=secscan_report.json'}
        )
    elif format == 'html':
        html = render_template('download_report.html', **report)
        return Response(
            html,
            mimetype='text/html',
            headers={'Content-Disposition': 'attachment;filename=secscan_report.html'}
        )
    elif format == 'pdf':
        try:
            from weasyprint import HTML
            html_content = render_template('download_report.html', **report)
            pdf = HTML(string=html_content).write_pdf()
            return Response(
                pdf,
                mimetype='application/pdf',
                headers={'Content-Disposition': 'attachment;filename=secscan_report.pdf'}
            )
        except ImportError:
            flash('PDF generation requires weasyprint.', 'danger')
            return redirect(url_for('main.dashboard'))
        except Exception as e:
            flash(f'PDF generation failed: {str(e)}', 'danger')
            return redirect(url_for('main.dashboard'))
    else:
        flash('Invalid format.', 'danger')
        return redirect(url_for('main.dashboard'))


@main_bp.route('/history')
@login_required
def history():
    scans = ScanResult.query.filter_by(user_id=current_user.id)\
        .order_by(ScanResult.scanned_at.desc()).all()
    return render_template('history.html', scans=scans)


@main_bp.route('/scan/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)
    if scan_result.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))
    db.session.delete(scan_result)
    db.session.commit()
    flash('Scan deleted.', 'success')
    return redirect(url_for('main.history'))
