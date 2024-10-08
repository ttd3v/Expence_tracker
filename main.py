from flask import Flask,request,jsonify
from flask_cors import CORS
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
import secrets,json
import threading
import time,datetime
from random import randint
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.secret_key = b'c\xb3G*\xa3\xf1\xf1\xf2#\x0c\x0e\xa4"d$t'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"
db = SQLAlchemy(app)
cross_origin_resource_sharing = CORS(app,origins=["http://localhost:3000"])
terminalLogs = {}
terminal_logs_saved = True

with open('./terminalLogs.json','r') as file:
    terminalLogs = json.load(file)
    file.close()

def applyTerminalLogs(message : str, weight : int):
    global terminal_logs_saved
    terminalLogs[time.time()] = str({"date":datetime.datetime.now(),"message":message,"weight":weight})
    terminal_logs_saved = False
    ## Weight: -1(error) 0(warn) 1(normal) 2(sucess)
def __terminallogthreadfun___():
    global terminal_logs_saved
    while True:   
        if not terminal_logs_saved:
            with open('./terminalLogs.json','w') as file:
                json.dump(terminalLogs,file)
                file.close()
                terminal_logs_saved = True
        time.sleep(1) 
        
        

save_terminal_logs_thread = threading.Thread(target=__terminallogthreadfun___,daemon=True)
save_terminal_logs_thread.start()
print("save_terminal_started")

with app.app_context():
    db.create_all()

migrage = Migrate(app,db)
migrage.init_app(app,db)

def create_auth_key(length=500) -> str:
        return get_random_bytes(450)
class Crypt:
    def __init__(self) -> None:
        pass
    def encrypt(self,plain_text):
        plain_text = str(plain_text).encode('utf-8')
        cipher = AES.new(app.secret_key,AES.MODE_EAX)
        text,tag =  cipher.encrypt_and_digest(plain_text)
        return text,tag,cipher.nonce
    def decrypt(self,cipher_text,tag,nonce):
        cipher_text = str(cipher_text).encode('utf-8')
        cipher = AES.new(app.secret_key,AES.MODE_EAX,nonce=nonce)
        return cipher.decrypt_and_verify(cipher_text,tag)
Crypting = Crypt()

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer,nullable=False,primary_key=True,unique=True)
    auth_key=db.Column(db.String(500),nullable=False,unique=True, default=create_auth_key)
    super_user=db.Column(db.Boolean,nullable=False,default=False)
    
    email = db.Column(db.String(320**2),nullable=False,unique=True)
    email_nonce = db.Column(db.String(32**2),nullable=False)
    email_tag = db.Column(db.String(32**2),nullable=False)
    
    password = db.Column(db.String(300**2),nullable=False)
    password_nonce = db.Column(db.String(320**2),nullable=False)
    password_tag = db.Column(db.String(320**2),nullable=False)

    expense_json = db.Column(db.Text,nullable=False)
    expense_json_nonce = db.Column(db.Text,nullable=False)
    expense_json_tag = db.Column(db.Text,nullable=False)

class data_manage:
    def __init__(self) -> None:
        pass
    def create_user(self,email,password):
        try:
            new_user = User()
            new_user.auth_key = get_random_bytes(400)
            json_data,json_tag,json_nonce = Crypting.encrypt(b'{}')
            
            new_user.expense_json = json_data
            new_user.expense_json_tag = json_tag
            new_user.expense_json_nonce = json_nonce

            email_data,email_tag,email_nonce = Crypting.encrypt(str(email).encode('utf-8'))
            new_user.email = email_data
            new_user.email_tag = email_tag
            new_user.email_nonce = email_nonce

            password_data,password_tag,password_nonce = Crypting.encrypt(str(password).encode('utf-8'))
            new_user.password = password_data
            new_user.password_tag = password_tag
            new_user.password_nonce = password_nonce
            db.session.add(new_user)
            db.session.commit()
            return new_user
        except Exception as err:
            db.session.rollback()
            print("An error have ocurred! A rollback has been made.")
            print(err)
            applyTerminalLogs('An error have ocurred while creating a new user, rollback have been made.',-1)
            applyTerminalLogs(str(err),-1)
            return None
    def check_user_exists(self,email) -> bool:
        email_cipher,email_tag,email_nonce = Crypting.encrypt(str(email).encode("utf-8"))
        return (User.query.filter_by(
            email=email_cipher,
            email_tag=email_tag,
            email_nonce=email_nonce,
        ).first() != None)
@app.route("/login_user",methods=['POST'])
def login_user_request():
    if not request.data: return
    data = json.loads(request.data)
    if request.method == "POST" and 'email' in data and 'password' in data:
        cipher_email,tag_email,nonce_email = Crypting.encrypt(data['email'])
        cipher_password,tag_password,nonce_password = Crypting.encrypt(data['password'])
        track_user = User.query.filter_by(
            email=cipher_email,
            email_tag = tag_email,
            email_nonce = nonce_email,
            password = cipher_password,
            password_tag = tag_password,
            password_nonce = nonce_password
        )
        sucess = False,
        auth_key = "",
        if track_user.first():
            applyTerminalLogs("A received request[POST] with intentions[Login] has been sucessfully made!",2)
            sucess = True
            auth_key = track_user.auth_key
        else:
            applyTerminalLogs("A received request[POST] with intentions[Login] has failed, the email or password was wrong",1)
        print(auth_key)
        return jsonify({
                'sucess' : sucess,
                'auth_key': auth_key
            })
    else:
        if not 'email' in data:
            applyTerminalLogs("A received request[POST] haven't a valid body : Missing (email) in (data)",0)
        if not 'password' in data:
            applyTerminalLogs("A received request[POST] haven't a valid body : Missing (password) in (data)",0)
data_m = data_manage()
@app.route("/register_user",methods=['POST'])
def register_user_request():
    if not request.data: return
    data = json.loads(request.data)
    if request.method == "POST" and 'email' in data and 'password' in data:
        sucess = False
        auth_key = ''
        data_return = {'sucess':False,'auth_key':""}
        if not data_m.check_user_exists(data['email']):
            new_user = data_m.create_user(data['email'],data['password'])
            if new_user:
                applyTerminalLogs("A new user has been created!",2)
                auth_key = new_user.auth_key
                sucess = True
        data_return['auth_key'] = str(auth_key)
        data_return['sucess'] = bool(sucess)
        return jsonify(data_return)
    else:
        if not 'email' in data:
            applyTerminalLogs("A received request[POST] haven't a valid body : Missing (email) in (data)",0)
        if not 'password' in data:
            applyTerminalLogs("A received request[POST] haven't a valid body : Missing (password) in (data)",0)

@app.route("/get_user_data_list",methods=['POST'])
def get_user_data_request():
    if not request.data: return
    data = json.loads(request.data)
    if 'auth_key' in data:
        try:
            user = User.query.filter_by(auth_key=data['auth_key']).first()
            if user:
                expense_json = user.expense_json
                expense_json_tag = user.expense_json_tag
                expense_json_nonce = user.expense_json_nonce
                expense_json = Crypting.decrypt(expense_json,expense_json_tag,expense_json_nonce)
                expense_json = json.loads(expense_json)
                return jsonify(str({'data':expense_json}))
            else:
                applyTerminalLogs("Failed to find user with it's (auth_key)",1)
        except Exception as err:
            applyTerminalLogs("Failed to get the user's data",0)
            applyTerminalLogs(str(err),-1)
    return jsonify({'data':'[]'})
if __name__ == "__main__":
    app.run(host='127.0.0.1',port=30)