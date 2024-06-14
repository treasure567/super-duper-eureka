#setting up the connection to the MongoDB Atlas cluster
from pymongo.mongo_client import MongoClient
#dotenv
from dotenv import load_dotenv
import os

# Load the dotenv file
load_dotenv()
uri = os.environ.get('MONGO_URL')
# Create a new client and connect to the server
client = MongoClient(uri)

#setting up flask
from flask import Flask, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_restful import Api, Resource
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity


from roles import roles 



#setting up app instance 
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})
app.config['JWT_SECRET_KEY']=os.environ.get('JWT_SECRET')
app.config['JWT_ACCESS_TOKEN_EXPIRES']=int(os.environ.get('jwt_expiry_time'))
jwt=JWTManager(app)
api = Api(app)


#setin up API

class Register(Resource):
    def post(self):
        data = request.get_json()
        email=data.get("email")
        password=data.get("password")
        role=data.get("role","member")
        if(email and password):
            users = client.pipeops.users
            if users.find_one({'email':email}):
                return {"message":"User already exists"}, 400
            uuid=""
            users.insert_one({'email':email, 'password':generate_password_hash(password),"role":roles.get("member"),"uuid":uuid})
            return {"message":"User created successfully"}, 201
        return {"message":"Invalid data"}, 400

class Login(Resource):
    def post(self):
        data = request.get_json()
        email=data.get("email")
        password=data.get("password")
        if(email and password):
            users = client.pipeops.users
            user_data = users.find_one({'email':email})
            if user_data and check_password_hash(user_data['password'],password):
                access_token = create_access_token(identity=user_data.get('uuid'))
                return {"access_token":access_token}, 200
            return {"message":"Invalid credentials"}, 400
        return {"message":"Invalid data"}, 400


### Register routes
Api.add_resource(Register,"/api/auth/register")
Api.add_resource(Login,"/api/auth/login")

### Run app
if __name__=="__main__":
    app.run(debug=True)