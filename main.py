from flask import Flask,request,jsonify
from flask_cors import CORS
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
import secrets,json
import threading,math
from time import time
from datetime import datetime
from random import randint
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.secret_key = b'f99ad82706ad41b321df79ceeed22103'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"
db = SQLAlchemy(app)
cross_origin_resource_sharing = CORS(app,origins=["http://127.0.0.1:3000","http://localhost:3000"])
terminalLogs = {}
terminal_logs_saved = True

def crypt(plain_text : bytes):
    cipher = AES.new(app.secret_key,AES.MODE_EAX)
    text,tag = cipher.encrypt_and_digest(plain_text)
    return text,tag,cipher.nonce
def decrypt(text,tag,nonce):
    cipher = AES.new(app.secret_key,AES.MODE_EAX,nonce=nonce)
    return cipher.decrypt_and_verify(text,tag)
with open('./terminalLogs.json','r') as file:
    terminalLogs = json.load(file)
    file.close()

def applyTerminalLogs(message : str, weight : int):
    global terminal_logs_saved
    stamp = time()
    terminalLogs[stamp] = str({"date":datetime.now(),"message":message,"weight":weight})
    print(message)
    terminal_logs_saved = False
    with open('./terminalLogs.json','w') as file:
                json.dump(terminalLogs,file)
                file.close()
                terminal_logs_saved = True
    
    ## Weight: -1(error) 0(warn) 1(normal) 2(sucess)


with app.app_context():
    db.create_all()

migrage = Migrate(app,db)
migrage.init_app(app,db)

def create_auth_key(length=100) -> str:
    chars = str('1 2 3 4 5 6 7 8 9 0 q w e r t y u i o p a s d f g h j k l z x c v b n m Q W E R T Y U I O P Z X C V B N M').split(" ")
    result = ''
    for _ in range(length):
        result += secrets.choice(chars)
    print(result)
    return result

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer,nullable=False,primary_key=True,unique=True)
    auth_key=db.Column(db.String(50),nullable=False,unique=True)
    super_user=db.Column(db.Boolean,nullable=False,default=False)
    
    email = db.Column(db.LargeBinary,nullable=False,unique=True)
    email_nonce = db.Column(db.LargeBinary,nullable=False,unique=True)
    email_tag = db.Column(db.LargeBinary,nullable=False,unique=True)
    
    password = db.Column(db.LargeBinary,nullable=False,unique=True)
    password_nonce = db.Column(db.LargeBinary,nullable=False,unique=True)
    password_tag = db.Column(db.LargeBinary,nullable=False,unique=True)

    expense_json = db.Column(db.LargeBinary,nullable=False)
    expense_json_nonce = db.Column(db.LargeBinary,nullable=False)
    expense_json_tag = db.Column(db.LargeBinary,nullable=False)
    def __repr__(self) -> str:
        return f"User<{self.auth_key}>"

class data_manage:
    def __init__(self) -> None:
        pass
    def create_user(self,email,password):
        try:
            new_user = User()
            new_user.auth_key = create_auth_key(500)
            json_data,json_tag,json_nonce = crypt(b'{}')
            
            new_user.expense_json = json_data
            new_user.expense_json_tag = json_tag
            new_user.expense_json_nonce = json_nonce

            email_data,email_tag,email_nonce = crypt(str(email).encode('utf-8'))
            new_user.email = email_data
            new_user.email_tag = email_tag
            new_user.email_nonce = email_nonce

            password_data,password_tag,password_nonce = crypt(str(password).encode('utf-8'))
            new_user.password = password_data
            new_user.password_tag = password_tag
            new_user.password_nonce = password_nonce
            print(decrypt(json_data,json_tag,json_nonce))
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
        email_cipher,email_tag,email_nonce = crypt(str(email).encode("utf-8"))
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
        cipher_email,tag_email,nonce_email = crypt(data['email'])
        cipher_password,tag_password,nonce_password = crypt(data['password'])
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
    print(data)
    if 'auth_key' in data and len(data['auth_key']) > 10:
        try:
            print(data['auth_key'])
            user = User.query.filter_by(auth_key=data['auth_key']).first()
            print(user)
            if user:
                expense_json = user.expense_json
                expense_json_tag = user.expense_json_tag
                expense_json_nonce = user.expense_json_nonce
                expense_json = decrypt(expense_json,expense_json_tag,expense_json_nonce)
                expense_json = expense_json.decode('utf-8')
                expense_json = expense_json.replace("'",'"')
                print(expense_json)
                expense_json = json.loads(expense_json)
                print(expense_json)
                return json.loads(json.dumps(expense_json))
            else:
                applyTerminalLogs("Failed to find user with it's (auth_key)",1)
                return jsonify(str({'error':'null_user'}))
        except Exception as err:
            applyTerminalLogs("Failed to get the user's data",0)
            applyTerminalLogs(str(err),-1)
            return jsonify(str({'error':'null_user'}))
    return jsonify(str({}))

@app.route("/create_user_history",methods=["POST"])
def create_user_history_request():
    if not request.data: return
    data = json.loads(request.data)
    if not 'auth_key' in data:
        applyTerminalLogs("A received request[POST] haven't a valid body : Missing (auth_key)",0)
    else:
        user = User.query.filter_by(auth_key=data['auth_key']).first()
        if user:
            if not 'new_history' in data:
                applyTerminalLogs("Failed to create (new_history) : Missing (new_history) in (data)",-1)
                return None
            if 'new_history' in data:
                try:
                    expense_json = user.expense_json
                    expense_json_tag = user.expense_json_tag
                    expense_json_nonce = user.expense_json_nonce
                    print("step 1")
                    expense_json = decrypt(expense_json,expense_json_tag,expense_json_nonce)
                    print(expense_json.decode('utf-8'))
                    expense_json = json.loads((expense_json.decode('utf-8')).replace("'",'"'))
                    print('step 2')
                    print(expense_json,expense_json_tag,expense_json_nonce)
                    new_history = data['new_history']
                    stamp = math.floor(time())
                    expense_json[str(stamp)] = {
                        'Cash' : new_history['Cash'],
                        'Name' : new_history['Name'],
                        'Category' : new_history['Category'],
                        'Date' : str(datetime.fromtimestamp(stamp))
                    }
                    
                    encrypted_json,encrypted_json_tag, encrypted_json_nonce = crypt(str(expense_json).encode('utf-8'))
                    user.expense_json = encrypted_json
                    user.expense_json_tag = encrypted_json_tag
                    user.expense_json_nonce = encrypted_json_nonce 
                    db.session.commit()
                    return jsonify(str(expense_json[str(stamp)]))
                except Exception as err:
                    db.session.rollback()
                    applyTerminalLogs("Error while saving user expense_json, a rollback has been made",-1)
                    applyTerminalLogs(str(err),-1)
                    return None
        else:
            print(data['auth_key'])
            applyTerminalLogs("Failed to find user, no auth_key match",-1)
            return jsonify(str({'error':'null_user'}))
if __name__ == "__main__":
    app.run(host='127.0.0.1',port=30)