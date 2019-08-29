from flask import Flask
#from flask.ext.bcrypt import Bcrypt
from flask_bcrypt import Bcrypt
#from flask_session import Session
from flask import Flask, g
from flask import render_template
from flask import flash, redirect, url_for, request, session
import os
import sqlite3
import hashlib as hs
# import hmac import compare_digest
from simplecrypt import encrypt, decrypt
from base64 import b64encode, b64decode
from getpass import getpass
import passlib.hash as ps

Show_cliked = True
Sacredcode = 'secred'
app = Flask(__name__)

app.config.update(dict(
    SECRET_KEY='59^6=;#&XP"2Vakfr4',
    DATABASE=os.path.join(app.root_path, 'users'),
    SITE_NAME='converter'
))


UPLOAD_FOLDER = 'target/'
ALLOWED_EXTENSIONS = {'json', 'xml'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['json_file'] = app.config['UPLOAD_FOLDER'] + 'dict.json'
app.config['xml_file'] = app.config['UPLOAD_FOLDER'] + 'config.xml'
app.secret_key = '59^6=;#&XP"2Vakfr4'


class savedata(object):

    @staticmethod
    def passcomper(string_pass, hash_pass):
        return ps.sha256_crypt.verify(string_pass, hash_pass)

    @staticmethod
    def encrypthash(password):
        return ps.sha256_crypt.encrypt(password)

    @staticmethod
    def encryptlog(password):
        return hs.sha256(password.encode('utf-8')).hexdigest()

    @staticmethod
    def decryptlog(password, code):

        cipher = b64decode(password)
        plaintext = decrypt(code, cipher)
        return plaintext


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() \
        in ALLOWED_EXTENSIONS


def get_db():
    """Funkcja tworząca połączenie z bazą danych"""
    if not g.get('db'):
        con = sqlite3.connect(app.config['DATABASE'])
        con.row_factory = sqlite3.Row
        g.db = con
    return g.db


@app.teardown_appcontext
def close_db(error):
    if g.get('db'):
        g.db.close()


@app.route('/', methods=['GET', 'POST'])
def login():
    error =''
    if 'logged' in session:
        if session['logged'] == True:
            return redirect(url_for('convert'))

    if request.method == 'POST':
        login = request.form['user']
        password = request.form['password']
        enc_login = savedata.encryptlog(login)

# +++++++++++BACKDOOR+++++++++++++++++++++++++++++++!
        if login == 'root' and password == 'root':
            session['username'] = login
            session['rights'] = 'crud'
            session['logged'] = True
            return render_template('admin.html')
# ===================================================!

        db = get_db()
        kursor = db.execute('SELECT * FROM users WHERE user_name = ?;',
                            [enc_login])
        kursor = kursor.fetchone()

        if kursor == None:
            error = 'wrong login'
            return render_template('index.html',error=error)

        if (savedata.passcomper(password, kursor['user_password'])):
            session['username'] = login
            session['rights'] = kursor['rights']
            session['logged'] = True
            return redirect(url_for('convert'))
        else :
            error = 'wrong password'

    return render_template('index.html',error=error)


@app.route('/logoff', methods=['GET', 'POST'])
def logoff():
    session['logged'] = False
    return redirect(url_for('login'))


@app.route('/admin', methods=['GET', 'POST'])
def admin():

    print(savedata.encrypthash('Darkes'))
    print(savedata.encrypthash('Darkes'))

    if 'logged' not in session:
        session['logged'] = False
        return redirect(url_for('login'))
    if session['logged'] == True:
        c = '0.4'
        r = '0.4'
        u = '0.4'
        d = '0.4'
        bc = 'disabled'
        br = 'disabled'
        bu = 'disabled'
        bd = 'disabled'

        if ('c' or 'C') in session['rights']:
            c = '1'
            bc = ''

        if ('r' or 'R') in session['rights']:
            r = '1'
            br = ''

        if ('u' or 'U') in session['rights']:
            u = '1'
            bu = ''

        if ('d' or 'D') in session['rights']:
            d = '1'
            bd = ''

        if Show_cliked == True:
            db = get_db()
            kursor = db.execute('SELECT * FROM users')
            use = kursor.fetchall()

            return render_template('admin.html', use=use, c=c, r=r, u=u, d=d, bc=bc, br=br, bu=bu, bd=bd)

        return render_template('admin.html', c=c, r=r, u=u, d=d, bc=bc, br=br, bu=bu, bd=bd)
    return redirect(url_for('login'))


@app.route('/create',  methods=['GET', 'POST'])
def create():

    if ('c' or 'C') in session['rights']:
        print("pykło")
        user_name = request.form['new_user']
        password = request.form['new_password']
        re_password = request.form['re_password']
        rights = request.form['rights']

        if password == re_password:

            password = savedata.encrypthash(password)
            user_name = savedata.encryptlog(user_name)

            db = get_db()
            db.execute('INSERT INTO users VALUES (?,?,?,?);',
                    [None, user_name, password, rights])
            db.commit()
    return redirect(url_for('admin'))


@app.route('/read', methods=['GET', 'POST'])
def read():
    if ('r' or 'R') in session['rights']:
        global Show_cliked
        if Show_cliked == True:
            Show_cliked = False
        else:
            Show_cliked = True

        if Show_cliked == True:
            db = get_db()
            kursor = db.execute('SELECT * FROM users')
            use = kursor.fetchall()
            render_template('admin.html', use=use)

    return redirect(url_for('admin'))


@app.route('/update', methods=['GET', 'POST'])
def update():
    if ('u' and 'U') in session['rights']:

        id_u = request.form['id_user']
        name = request.form['name_user']
        password = request.form['password_user']
        right = request.form['rights']
        name=savedata.encryptlog(name)

        db = get_db()
        if name != '':
            db.execute(
                'UPDATE users SET user_name = ?  WHERE id = ?;', [name, id_u])
            db.commit()

        if password != '':
            db.execute('UPDATE users SET user_password = ?  WHERE id = ?;', [
                    password, id_u])
            db.commit()

        if right != '':
            db.execute('UPDATE users SET rights = ?  WHERE id = ?;',
                    [right, id_u])
            db.commit()

    return redirect(url_for('admin'))


@app.route('/delete', methods=['GET', 'POST'])
def delete():
    if ('d' or 'D') in session['rights']:
        id_u = request.form['id_u']
        db = get_db()
        db.execute('DELETE FROM users WHERE id = ?;', [id_u])
        db.commit()
    return redirect(url_for('admin'))


@app.route('/convert', methods=['GET', 'POST'])
def convert():
    if 'logged' not in session:
        session['logged'] = False
        return redirect(url_for('login'))
    if session['logged'] == True:
        flash('')
        return render_template('convert.html')
    return redirect(url_for('login'))


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


if __name__ == '__main__':
    app.run(debug=True)
