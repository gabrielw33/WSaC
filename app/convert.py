import os
from flask import Flask
from flask import send_file
from flask import render_template
from url_to_json import Url_to_json
from json_to_xml import Json_to_xml
from werkzeug.utils import secure_filename
from flask import flash, redirect, url_for, request

UPLOAD_FOLDER = 'target/'
ALLOWED_EXTENSIONS = {'json', 'xml'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() \
         in ALLOWED_EXTENSIONS


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['json_file'] = app.config['UPLOAD_FOLDER'] + 'dict.json'
app.config['xml_file'] = app.config['UPLOAD_FOLDER'] + 'config.xml'
app.secret_key = '59^6=;#&XP"2Vakfr4'


@app.route('/convert', methods=['GET', 'POST'])
def convert():
    flash('')
    return render_template('convert.html')


@app.route('/url_to_json', methods=['GET', 'POST'])
def url_to_json():
    flash('')
    if request.method == 'POST':
        if ('T_Url' not in request.form) or ('T_RegExp' not in request.form):
            return redirect(request.url)

        url = request.form['T_Url']
        regex = request.form['T_RegExp']

        if (url == '') or (regex == ''):
            flash('not given regexp or url')
            return redirect(request.url)

        path = Url_to_json(url, regex, app.config['json_file'])

        if path == "wrong url":
            flash(path)
            return redirect(request.url)

        flash('')
        return send_file(path, as_attachment=True, cache_timeout=0)

    return redirect(url_for('convert'))


@app.route('/json_to_xml', methods=['GET', 'POST'])
def json_to_xml():
    json = None
    xml = None
    uid = None
    if request.method == 'POST':
        if 'F_json' not in request.files:
            flash('No file part')
            return redirect(request.url)

        json = request.files['F_json']

        if json.filename == '':
            flash('No file selected ')
            return redirect(request.url)

        if json and not allowed_file(json.filename):
            flash('wrong file type ')
            return redirect(request.url)

        if 'F_xml' not in request.files:
            flash('No file part')
            return redirect(request.url)

        xml = request.files['F_xml']

        if xml.filename == '':
            flash('No selected file')

        if xml and not allowed_file(xml.filename):
            flash('wrong file type')
            return redirect(request.url)

        uid = request.form['T_uid']

        Json_to_xml(app.config['json_file'], app.config['xml_file'], xml, uid)

        flash('')
        return send_file(app.config['xml_file'], as_attachment=True)

    return redirect(url_for('convert'))


if __name__ == "__main__":
    app.run(host='0.0.0.0')