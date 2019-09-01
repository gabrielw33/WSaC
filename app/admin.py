import base64
import hashlib as hs
import os
import sqlite3
from getpass import getpass

import passlib.hash as ps
from Crypto.Cipher import AES

from flask import (Flask, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
from json_to_xml import Json_to_xml
from url_to_json import Url_to_json

Show_cliked = False
Sacredcode = '1614567790183496'
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
    def encryptlog(password, code):

        cipher = AES.new(code, AES.MODE_ECB)
        encoded = base64.b64encode(cipher.encrypt(password.rjust(32)))
        return encoded.decode('UTF-8')

    @staticmethod
    def decryptlog(password, code):

        cipher = AES.new(code, AES.MODE_ECB)
        decoded = cipher.decrypt(base64.b64decode(password))
        return decoded.decode('UTF-8')


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

def login_test():
    if 'logged' not in session:
        session['logged'] = False

    

@app.route('/', methods=['GET', 'POST'])
def login():
    session['read'] = False
    session['db'] = None

    error = ''
    if 'logged' in session:
        if session['logged'] == True:
            return redirect(url_for('convert'))

    if request.method == 'POST':
        login = request.form['user']
        password = request.form['password']

        # ===========================================
        if login == 'root' and password == 'root':
            session['username'] = login
            session['rights'] = 'crud'
            session['logged'] = True
            return render_template('index.html', error=error)
        # ===========================================!

        enc_login = savedata.encryptlog(login, Sacredcode)
        db = get_db()
        kursor = db.execute('SELECT * FROM users WHERE user_name = ?;',
                            [enc_login])
        kursor = kursor.fetchone()

        if kursor == None:
            error = 'wrong login'
            return render_template('index.html', error=error)

        if (savedata.passcomper(password, kursor['user_password'])):
            session['username'] = login
            session['rights'] = kursor['rights']
            session['logged'] = True
            return redirect(url_for('convert'))
        else:
            error = 'wrong password'

    return render_template('index.html', error=error)


@app.route('/logoff', methods=['GET', 'POST'])
def logoff():
    session['logged'] = False
    return redirect(url_for('login'))


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    
    if 'logged' not in session:
        session['logged'] = False
    if session['logged']==False:
        return redirect(url_for('login'))

    
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
        if session['read'] == False:
            return redirect(url_for('read_db_on_begin'))
        use = session['db']

        return render_template('admin.html', c=c, r=r, u=u, d=d, bc=bc, br=br, bu=bu, bd=bd,use=use, len=len(use))
    
    return render_template('admin.html', c=c, r=r, u=u, d=d, bc=bc, br=br, bu=bu, bd=bd, len = 0)


@app.route('/create',  methods=['GET', 'POST'])
def create():
    if 'logged' not in session:
        session['logged'] = False
    if session['logged']==False:
        return redirect(url_for('login'))

    if ('c' or 'C') in session['rights']:
        user_name = request.form['new_user']
        password = request.form['new_password']
        re_password = request.form['re_password']
        rights = request.form['rights']

        if user_name == '' or password == '' or re_password == '':
            flash('complete the required forms')
            return redirect(url_for('admin'))

        if password == re_password:

            password = savedata.encrypthash(password)
            user_name = savedata.encryptlog(user_name, Sacredcode)

            db = get_db()
            db.execute('INSERT INTO users VALUES (?,?,?,?);',
                       [None, user_name, password, rights])
            db.commit()
        return redirect(url_for('read_db_on_begin'))     
    return redirect(url_for('admin'))


@app.route('/read_db_on_begin', methods=['GET', 'POST'])
def read_db_on_begin():
    if 'logged' not in session:
        session['logged'] = False
    if session['logged']==False:
        return redirect(url_for('login'))
    
    db = get_db()
    kursor = db.execute('SELECT * FROM users')
    kursor = kursor.fetchall()
    r_db = []
    lis = []
    for user in kursor:
      
        lis.append(user['id'])
        lis.append(savedata.decryptlog(user['user_name'], Sacredcode))
        lis.append(user['rights'])
        r_db.append(lis)
        lis = []
    session['db'] = r_db
    session['read'] = True
    return redirect(url_for('admin'))


@app.route('/read', methods=['GET', 'POST'])
def read():
    if 'logged' not in session:
        session['logged'] = False
    if session['logged']==False:
        return redirect(url_for('login'))

    if ('r' or 'R') in session['rights']:
        global Show_cliked
        if Show_cliked == True:
            Show_cliked = False
        else:
            Show_cliked = True

    return redirect(url_for('admin'))


@app.route('/update', methods=['GET', 'POST'])
def update():
    if 'logged' not in session:
        session['logged'] = False
    if session['logged']==False:
        return redirect(url_for('login'))

    if ('u' or 'U') in session['rights']:

        id_u = request.form['id_user']
        name = request.form['name_user']
        password = request.form['password_user']
        right = request.form['rights']
        name=savedata.encryptlog(name, Sacredcode)

        if id_u == '':
            flash('give user id')
            return redirect(url_for('admin'))

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
        return redirect(url_for('read_db_on_begin'))    
    return redirect(url_for('admin'))


@app.route('/delete', methods=['GET', 'POST'])
def delete():
    if 'logged' not in session:
        session['logged'] = False
    if session['logged']==False:
        return redirect(url_for('login'))
    
    if ('d' or 'D') in session['rights']:
        id_u = request.form['id_u']

        if id_u == '':
            flash('give user id')
            return redirect(url_for('admin'))

        db = get_db()
        db.execute('DELETE FROM users WHERE id = ?;', [id_u])
        db.commit()
        return redirect(url_for('read_db_on_begin')) 
    return redirect(url_for('admin'))


@app.route('/convert', methods=['GET', 'POST'])
def convert():
    if 'logged' not in session:
        session['logged'] = False
    
    if session['logged']==False:
        return redirect(url_for('login'))
    return render_template('convert.html')


@app.route('/url_to_json', methods=['GET', 'POST'])
def url_to_json():
    if 'logged' not in session:
        session['logged'] = False
    if session['logged']==False:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if ('T_Url' not in request.form) or ('T_RegExp' not in request.form):
            return redirect(request.url)

        url = request.form['T_Url']
        regex = request.form['T_RegExp']

        if (url == '') or (regex == ''):
            flash('Url and RegExp cannot be empty')
            return redirect(request.url)

        path = Url_to_json(url, regex, app.config['json_file'])

        if not path:
            flash('Invalid url')
            return redirect(request.url)

        flash('')
        return send_file(path, as_attachment=True, cache_timeout=0)

    return redirect(url_for('convert'))


@app.route('/json_to_xml', methods=['GET', 'POST'])
def json_to_xml():

    if 'logged' not in session:
        session['logged'] = False
    if session['logged']==False:
        return redirect(url_for('login'))

    json = None
    xml = None
    uid = None
    if request.method == 'POST':
        if 'F_json' not in request.files:
            flash('No file part')
            return redirect(request.url)

        json = request.files['F_json']
        xml = request.files['F_xml']

        if json.filename == '':
            flash('Select a json file')
            return redirect(request.url)

        if json and not allowed_file(json.filename):
            flash('wrong file type ')
            return redirect(request.url)

        if 'F_xml' not in request.files:
            flash('No file part')
            return redirect(request.url)

        if xml.filename == '':
            flash('Upload a xml file')
            return redirect(request.url)

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
