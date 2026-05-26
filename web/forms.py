import os
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, MultipleFileField
from wtforms import StringField, SubmitField
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
    submit = SubmitField('Scan Now')
