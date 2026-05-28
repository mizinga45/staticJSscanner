import os
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, SubmitField, SelectField, BooleanField
from wtforms.validators import Optional, ValidationError
from urllib.parse import urlparse


def validate_url(form, field):
    if field.data:
        url = field.data.strip()
        parsed = urlparse(url)
        if not parsed.scheme:
            url = 'https://' + url
            field.data = url
            parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            raise ValidationError('Invalid URL scheme. Use http or https.')


def validate_folder_path(form, field):
    if field.data:
        path = field.data.strip()
        if not os.path.isdir(path):
            raise ValidationError('Folder not found or is not a directory.')


class ScanForm(FlaskForm):
    file_upload = FileField('Upload JavaScript/HTML/PHP File', validators=[
        Optional(),
        FileAllowed(['js', 'html', 'php', 'txt'], 'Only .js, .html, .php, .txt files allowed')
    ])
    url_input = StringField('Or Enter URL', validators=[Optional(), validate_url])
    folder_path = StringField('Or Enter Folder Path', validators=[Optional(), validate_folder_path])
    scan_depth = SelectField('Recursion Depth', choices=[
        ('0', '0 — Current folder only'),
        ('1', '1 — One level deep'),
        ('2', '2 — Two levels deep'),
        ('3', '3 — Three levels deep'),
        ('4', '4 — Four levels deep'),
        ('5', '5 — Five levels deep'),
        ('6', '6 — Six levels deep (max)'),
    ], default='6')
    js_only = BooleanField('JavaScript files only (.js)')
    submit = SubmitField('Scan Now')
