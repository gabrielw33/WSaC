from flask import Flask
from flask import Flask, g
from flask import render_template
from flask import flash, redirect, url_for, request
import os
import sqlite3

Show_cliked = True

app = Flask(__name__)

app.config.update(dict(
    SECRET_KEY='59^6=;#&XP"2Vakfr4',
    DATABASE=os.path.join(app.root_path, 'users'),
    SITE_NAME='admin'
))


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


@app.route('/admin', methods=['GET', 'POST'])
def admin():

    if Show_cliked == True:
        db = get_db()
        kursor = db.execute('SELECT * FROM users')
        use = kursor.fetchall()
        return render_template('admin.html', use=use)

    return render_template('admin.html')


@app.route('/create',  methods=['GET', 'POST'])
def create():
    user_name = request.form['new_user']
    password = request.form['new_password']
    re_password = request.form['re_password']
    Cr = request.form['Cright_user']
    Rr = request.form['Rright_user']
    Ur = request.form['Uright_user']
    Dr = request.form['Dright_user']

    if password == re_password:
        db = get_db()
        kursor = db.execute('INSERT INTO users VALUES (?,?,?,?,?,?,?);',
            [None, user_name, password ,Cr,Rr,Ur,Dr])
        db.commit()
    return redirect(url_for('admin'))


@app.route('/read', methods=['GET', 'POST'])
def read():
    global Show_cliked
    print(Show_cliked)
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
    id_u = request.form['id_user']
    name = request.form['name_user']
    password = request.form['password_user']
    Cr = request.form['Cright_user']
    Rr = request.form['Rright_user']
    Ur = request.form['Uright_user']
    Dr = request.form['Dright_user']
    
    db = get_db()
    if name != '':
        db.execute('UPDATE users SET user_name = ?  WHERE id = ?;',[ name, id_u ])
        db.commit()

    if password != '':
        db.execute('UPDATE users SET user_password = ?  WHERE id = ?;',[password, id_u ])
        db.commit()
        
    if Cr != '':
        db.execute('UPDATE users SET rights_C = ?  WHERE id = ?;',[Cr, id_u ])
        db.commit()

    if Rr != '':
        db.execute('UPDATE users SET rights_R = ?  WHERE id = ?;',[Rr, id_u ])
        db.commit()

    if Ur != '':
        db.execute('UPDATE users SET rights_U = ?  WHERE id = ?;',[ Ur, id_u ])
        db.commit()

    if Dr != '':
        db.execute('UPDATE users SET rights_D = ?  WHERE id = ?;',[ Dr, id_u ])
        db.commit()
        
    return redirect(url_for('admin'))


@app.route('/delete', methods=['GET', 'POST'])
def delete():
    id_u = request.form['id_u']
    db = get_db()
    kursor = db.execute('DELETE FROM users WHERE id = ?;',[id_u])
    db.commit()
    return redirect(url_for('admin'))    


if __name__ == '__main__':
    app.run(debug=True)
