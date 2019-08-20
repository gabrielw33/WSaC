
from flask import Flask
from flask import render_template
from flask import flash, redirect, url_for, request
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html' )   

@app.route('/url_to_json', methods=['GET', 'POST'])
def url_to_json():
    
    url=None
    regex=None
    if request.method == 'POST' :
        url = request.form['T_Url']
        regex = request.form['T_RegExp']
        print(url)
     
    return render_template('index.html',url=url,regex=regex) 

@app.route('/json_to_xml', methods=['GET', 'POST'])
def json_to_xml():
    json=None
    xml=None
    uid=None
    if request.method == 'POST':
        json = request.form['F_json']
        xml = request.form['F_xml']
        uid = request.form['T_uid']
        
    return render_template('index.html',uid=uid)       


#    if request.methods == 'POST':
#        url = request.form['T_Url'].stript()
#        regex = request.form['T_RegExp'].stript()
    


if __name__ == "__main__":
    app.run(host='0.0.0.0')
