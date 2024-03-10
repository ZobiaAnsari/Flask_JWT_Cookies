from flask import Flask,request,jsonify,make_response
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import jwt
from werkzeug.security import generate_password_hash,check_password_hash
import datetime


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///jwt.db'
app.config['SECRET_KEY'] = 'SECRET_KEY'
db=SQLAlchemy(app)


class User(db.Model):
    id= db.Column(db.Integer,primary_key=True) 
    email_id= db.Column(db.String(50),unique=True)
    user_name= db.Column(db.String(200),nullable=False)
    password= db.Column(db.String(50),nullable=False)

    def __init__(self,email_id,user_name,password):
        self.email_id = email_id 
        self.user_name = user_name
        self.password = password

blacklisted_tokens= set()

def token_required(f):
    @wraps(f)
    def decor(*args,**kwargs):
        token = request.cookies.get('access_token_cookie')
        if not token:
            return jsonify ({"message":"token not found"}),401
        
        if is_token_blacklisted(token):
            return jsonify({"message":"token  has expire"}),401
        
        try:
            user_data = jwt.decode(token,app.config['SECRET_KEY'],algorithms=['HS256'])
            user = User.query.get(user_data['user_id'])
        except jwt.ExpiredsignatureEror:
            return jsonify({'mesaage':'token is expired'}),401
        except jwt.invalidtokenEror:
            return jsonify({"mesg":'invalid token'}),401
        except Exception as e:
            return jsonify({"mesg":'error decoding token','eror':str(e)}),401
        
        return f(user, *args, **kwargs)
    
    return decor
@app.route('/register',methods=['POST'])
def signup():
    data = request.json
    email_id=data.get('email_id')
    user_name=data.get('user_name')
    password=data.get('password')

    if not email_id or not  user_name or not password: 
        return jsonify ({'message':"missing fields"}),400
    
    hashed_password=generate_password_hash(password)
    new_user=User(email_id=email_id,user_name=user_name,password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message":"user created succesfully"})


@app.route('/login',methods=['POST'])
def login():
    data = request.json
    email_id=data.get('email_id')
    password=data.get('password')
    print(email_id,password)

    if not email_id or not password:
        return jsonify({"message":"misisng_credentials"}),400

    user=User.query.filter_by(email_id=email_id).first()
    if not user or not check_password_hash(user.password,password):
        return jsonify({"message":'invalid credential'}),401
    access_token=jwt.encode(
          
        {'user_id':user.id,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=120)}
        ,app.config['SECRET_KEY'],algorithm='HS256')
    response=make_response(jsonify({'message':"loginsucessfully"}))
    response.set_cookie('access_token_cookie',access_token,httponly=True)
    return response

@app.route('/logout',methods=['GET'])
def logout():
    response=make_response(jsonify({"message":"successfully logout"}))
    response.set_cookie('access_token_cookie','',expires=0)
    return response

@app.route('/greeet')
@token_required
def hello(user):
    return jsonify(f'hello aslam{user.user_name}')



def is_token_blacklisted(token):
    return token in blacklisted_tokens
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=8000, use_reloader=False)