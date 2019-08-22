import os
from url_to_json import Url_to_json
from json_to_xml import Json_to_xml
from flask import Flask
from flask import render_template
from flask import flash, redirect, url_for, request
from flask import send_file
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'app/'
ALLOWED_EXTENSIONS = {'json', 'xml'}


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = b'_5#23s/c1D#2/3ec]/'


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')


@app.route('/url_to_json', methods=['GET', 'POST'])
def url_to_json():
    if request.method == 'POST':
        if ('T_Url' not in request.form) or ('T_RegExp' not in request.form):
            return redirect(request.url)

        url = request.form['T_Url']
        regex = request.form['T_RegExp']

        if (url == '') or (regex == ''):
            flash('No url or regexp')

            return redirect(request.url)

        path = Url_to_json(url, regex)

        return send_file(path, as_attachment=True)

    return render_template('index.html')


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

        if json and allowed_file(json.filename):
            filename = secure_filename(json.filename)
            json.save(os.path.join(app.config['UPLOAD_FOLDER'], 'dict.json'))
            # return redirect(url_for('url_to_json', filename=filename))

        if 'F_xml' not in request.files:
            flash('No file part')
            print("niema")
            return redirect(request.url)

        xml = request.files['F_xml']

        if xml.filename == '':
            flash('No selected file')
            return redirect(request.url)

        uid = request.form['T_uid']
        print("prz")
        Json_to_xml('app/dict.json', xml, uid)
        print("po")
        path = "max4.xml"
        return send_file(path, as_attachment=True)

    return render_template('index.html')


if __name__ == "__main__":
    app.run(host='0.0.0.0')
