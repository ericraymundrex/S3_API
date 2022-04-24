UPLOAD_FOLDER = './static'

ENDPOINT = "database-1.covw3qyzqrxg.ap-south-1.rds.amazonaws.com"
USER = "postgres"
PASSWORD = "milZXI8ozwq8cHIz45K7"
DATABASE_NAME = "users"

import os
from functools import wraps
import jwt
import datetime
import glob
from flask import Flask, jsonify, request, send_from_directory
from flask_restful import Api, Resource, reqparse
from flask_cors import CORS, cross_origin
from werkzeug.utils import secure_filename
import psycopg2
import boto3 as aws
import bcrypt

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['CORS_HEADERS'] = 'multipart/form-data'
app.config['SECRET_KEY'] = "Thisisasecertkey"
api = Api(app)
cors = CORS(app)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


credentials = reqparse.RequestParser()
credentials.add_argument("username", type=str, help="username: is required", required=True)
credentials.add_argument("password", type=str, help="password: is required", required=True)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # args=token.parse_args()
        token = request.args.get("token")
        # print(token)
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({"message": "Token is invalid or missing"}), 403
        return f(*args, **kwargs)

    return decorated


class S3_upload_and_show_all(Resource):

    @cross_origin()
    @token_required
    def post(self):
        token = request.args.get("token")
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = data["user"].lower()
        bucket_name = f"{user}-bucket-s3"

        if 'files[]' not in request.files:
            # response = jsonify({"messgae": "No file in the request"})
            # response.status_code = 400
            return jsonify({"messgae": "No file in the request"}),400

        files = request.files.getlist('files[]')
        errors = {}
        success = False

        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                success = True
            else:
                errors[file.filename] = 'File type is not allowed'

        statics_folder = glob.glob('static/*')
        print(statics_folder)
        for file_in_static in statics_folder:
            client = aws.client('s3');
            client.upload_file(file_in_static, bucket_name, file_in_static.split("/")[1])
        for file in statics_folder:
            os.remove(file)

        if success and errors:
            errors['message'] = 'File(s) successfully uploaded'
            resp = jsonify(errors)
            resp.status_code = 500

            return resp
        if success:
            resp = jsonify({'message': 'Files successfully uploaded'})
            resp.status_code = 201

            return resp
        else:
            resp = jsonify(errors)
            resp.status_code = 500
            return resp

    @cross_origin()
    @token_required
    def get(self):
        token = request.args.get("token")
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = data["user"].lower()
        bucket_name = f"{user}-bucket-s3"

        s3 = aws.resource('s3')
        bucket = s3.Bucket(bucket_name)
        files_in_s3 = list(bucket.objects.all())
        files = {}
        files["data"] = []
        for file in files_in_s3:
            files["data"].append(file.key)
        print(files)
        return jsonify(files)


class S3_show_one_data(Resource):

    @cross_origin()
    @token_required
    def get(self, filename):
        token = request.args.get("token")
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = data["user"].lower()
        bucket_name = f"{user}-bucket-s3"
        if not filename:
            return {}
        try:
            client = aws.client('s3');
            client.download_file(bucket_name, filename, "./download/" + filename)
            return send_from_directory('download', filename), 200
        except:
            return {"message": "error"}


class Signup(Resource):
    @cross_origin()
    def post(self):
        args = credentials.parse_args()
        conn = psycopg2.connect(dbname=DATABASE_NAME, user=USER, password=PASSWORD, host=ENDPOINT)
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM users WHERE username='{args.username}'")
        exist = cur.fetchall()
        print(exist)
        if len(exist) != 0:
            return {"message": "There is a user in this name"}
        else:
            password = args.password
            salt = bcrypt.gensalt()
            hash = bcrypt.hashpw(password.encode('utf-8'), salt)
            hash = str(hash).split("'")[1]
            salt = str(salt).split("'")[1]
            try:
                cur.execute(f"INSERT INTO users(username, hash, salt) VALUES('{args.username}','{hash}','{salt}')")
                conn.commit()
                cur.close()
                conn.close()
            except:
                return {"message":"Problem in DB(AWS RDS connection)"}

            try:
                client = aws.client('s3');
                client.create_bucket(Bucket=f"{args.username.lower()}-bucket-s3")
            except:
                return {"message":"Problem in S3 Connection"}
            return {"message": "Account sucessfully created"}


class Login(Resource):
    @cross_origin()
    def post(self):
        args = credentials.parse_args()
        conn = psycopg2.connect(dbname=DATABASE_NAME, user=USER, password=PASSWORD, host=ENDPOINT)
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM users WHERE username='{args.username}'")
        exist = cur.fetchall()
        hashed = bcrypt.hashpw(args.password.encode('utf-8'), exist[0][3].encode('utf-8'))
        hashed = str(hashed).split("'")[1]
        if (hashed.encode('utf-8') == exist[0][2].encode('utf-8')):
            token = jwt.encode(
                {"user": args.username, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])
            conn.commit()
            cur.close()
            conn.close()
            return jsonify({"token": token})
        else:
            return jsonify({"message": "not sucess"})


api.add_resource(S3_upload_and_show_all, "/file")
api.add_resource(S3_show_one_data, "/file/<string:filename>")
api.add_resource(Signup, "/signup")
api.add_resource(Login, "/login")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
