import os
from flask import Flask, abort, request, jsonify, g, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from flask import make_response
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from flask_bcrypt import Bcrypt
from datetime import datetime
import uuid
import re
from flask_marshmallow import Marshmallow
import config
from flask_migrate import Migrate
import sys
from werkzeug.utils import secure_filename
import boto3

# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = config.SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = config.SQLALCHEMY_COMMIT_ON_TEARDOWN
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = config.SQLALCHEMY_TRACK_MODIFICATIONS

UPLOAD_FOLDER = '/home/ubuntu'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
bucket = config.s3_bucketname

# print(os.path.dirname(os.path.realpath(__file__)))
# print(os.getcwd())

# extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
ma = Marshmallow(app)
auth = HTTPBasicAuth()

# SQLite Database
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column('id', db.String(length=36), default=lambda: str(
        uuid.uuid4()), primary_key=True)
    username = db.Column(db.String(256), index=True,
                         nullable=False, unique=True)
    password_hash = db.Column(db.String(64), nullable=False)
    first_name = db.Column(db.String(64), nullable=False)
    last_name = db.Column(db.String(64), nullable=False)
    account_created = db.Column(db.String, index=True, default=datetime.now)
    account_updated = db.Column(db.String, default=datetime.now)

    def hash_password(self, password):
        self.password_hash = Bcrypt().generate_password_hash(password).decode()

    def verify_password(self, password):
        return Bcrypt().check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {}>'.format(self.username)

    @staticmethod
    def verify_auth_token(token):
        serial = Serializer(app.config['SECRET_KEY'])
        try:
            data = serial.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['username'])
        return user

class Book(db.Model):
    __tablename__ = 'books'

    id = db.Column('id', db.String(length=36), default=lambda: str(
        uuid.uuid4()), primary_key=True)
    title = db.Column(db.String(256), nullable=False)
    author = db.Column(db.String(256), nullable=False)
    isbn = db.Column(db.String(64), nullable=False)
    published_date = db.Column(db.String(256), nullable=False)
    book_created = db.Column(db.String, default=datetime.now)
    user_id = db.Column(db.String(64))

    def __repr__(self):
        return '<Book {}>'.format(self.title)


class BookSchema(ma.Schema):
    class Meta:
        fields = ("id", "title", "author", "isbn",
                  "published_date", "book_created", "user_id")
        model = Book


book_schema = BookSchema()
books_schema = BookSchema(many=True)

class Image(db.Model):
    __tablename__ = 'images'

    file_id = db.Column('file_id', db.String(length=36), primary_key=True)
    file_name = db.Column(db.String(256), nullable=False)
    created_date = db.Column(db.String, default=datetime.now)
    s3_object_name = db.Column(db.String, default='some_id')
    user_id = db.Column(db.String(64), nullable=False)
    book_id = db.Column(db.String(64), nullable=False)

    def __repr__(self):
        return '<Image {}>'.format(self.file_name)


class ImageSchema(ma.Schema):
    class Meta:
        fields = ("file_id", "file_name", "created_date", "s3_object_name",
                  "user_id", "book_id")
        model = Image


image_schema = ImageSchema()
images_schema = ImageSchema(many=True)


@auth.verify_password
def verify_password(username, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


def validate_password(password):
    reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,25}$"
    pattern = re.compile(reg)
    match = re.search(pattern, password)

    if match:
        return True
    else:
        return False


@app.route('/v1/user', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    first_name = request.json.get('first_name')
    last_name = request.json.get('last_name')

    if username is None or password is None or first_name is None or last_name is None:
        return "Please enter username, password, first_name and last_name", 400     # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        return "Username exists. Please use a different username", 400       # existing user
    if not validate_password(password):
        return "Please enter a strong password. Follow NIST guidelines", 400

    user = User(username=username, first_name=first_name,
                last_name=last_name)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    response = jsonify({
        'id': user.id,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'username': user.username,
        'account_created': user.account_created,
        'account_updated': user.account_updated
    })
    response.status_code = 201
    return response


@app.route('/v1/user/self', methods=['GET', 'PUT'])
@auth.login_required
def auth_api():
    if request.method == "GET":
        response = jsonify({
            'id': g.user.id,
            'first_name': g.user.first_name,
            'last_name': g.user.last_name,
            'username': g.user.username,
            'account_created': g.user.account_created,
            'account_updated': g.user.account_updated,
        })
        response.status_code = 200
        return response
    
    if request.method == "PUT":
        if request.json.get('username') is not None:
            return "Cannot modify username. Please supply first_name, last_name or password", 400
        if request.json.get('first_name') is not None:
            g.user.first_name = request.json.get('first_name')
        if request.json.get('last_name') is not None:
            g.user.last_name = request.json.get('last_name')
        if request.json.get('password') is not None:
            if not validate_password(request.json.get('password')):
                return "Please enter a strong password. Follow NIST guidelines", 400
            password = request.json.get('password')
            g.user.hash_password(password)
        g.user.account_updated = str(datetime.now())
        print(request.json)
        print(request.json.get('username'))
        print(request.json.get('username') is not None)
        db.session.add(g.user)
        db.session.commit()
        
        response = jsonify({
            'id': g.user.id,
            'first_name': g.user.first_name,
            'last_name': g.user.last_name,
            'account_created': g.user.account_created,
            'account_updated': g.user.account_updated,
        })
        response.status_code = 204
        return response


@app.route('/books', methods=['GET'])
def get_books():
    all_books = Book.query.all()
    result = books_schema.dump(all_books)

    # print(result)
    # for r in result:
    #     print(r['id'])
    #     book_id = print(r['id'])
    #     image_all = Image.query.filter_by(book_id=id).all()
    #     result = images_schema.dump(image_all)

    #     if image is None:
    #         return book_schema.jsonify(book)

    return jsonify(result)


@app.route("/books/<id>", methods=["GET"])
def book_detail(id):
    book = Book.query.get(id)
    if book is None:
        return 'Not found', 404
    
    else:
        image = Image.query.filter_by(book_id=id).first()
        
        image_all = Image.query.filter_by(book_id=id).all()
        result = images_schema.dump(image_all)
    
        if image is None:
            return book_schema.jsonify(book)

        else:
            response = jsonify({
                'id': book.id,
                'title': book.title,
                'author': book.author,
                'isbn': book.isbn,
                'published_date': book.published_date,
                'book_created': book.book_created,
                'user_id': book.user_id,
                'book_images': result
            })
            response.status_code = 200
            return response


@app.route("/books/<id>", methods=["DELETE"])
@auth.login_required
def book_delete(id):
    book = Book.query.get(id)
    if book is None:
        return 'Not found', 404
    if g.user.id == book.user_id:
        db.session.delete(book)
        db.session.commit()
        return book_schema.jsonify(book)
    else:
        return 'Unauthorized Access', 401


@app.route('/books', methods=['POST'])
@auth.login_required
def new_book():
    title = request.json.get('title')
    author = request.json.get('author')
    isbn = request.json.get('isbn')
    published_date = request.json.get('published_date')
    user_id = g.user.id

    if title is None or author is None or isbn is None or published_date is None:
        return "Please enter title, author, isbn and published_date", 400

    book = Book(title=title, author=author, isbn=isbn,
                published_date=published_date, user_id=user_id)

    db.session.add(book)
    db.session.commit()

    response = jsonify({
        'id': book.id,
        'title': book.title,
        'author': book.author,
        'isbn': book.isbn,
        'published_date': book.published_date,
        'book_created': book.book_created,
        'user_id': book.user_id
    })
    response.status_code = 201
    return response


ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/books/<id>/image', methods=['POST'])
@auth.login_required
def upload_image(id):
	
    book_id = id
    if 'file' not in request.files:
        response = jsonify({'message': 'No file part in the request'})
        response.status_code = 400
        return response

    file = request.files['file']

    if file.filename == '':
        response = jsonify({'message': 'No file selected for uploading'})
        response.status_code = 400
        return response

    if file and allowed_file(file.filename):
    
        file_name = secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, file_name))
        file_id = str(uuid.uuid4())
        s3_object_name = book_id + '/' + file_id + '/' + file_name
        s3 = boto3.client('s3')
        s3.upload_file(f"/home/ubuntu/{file_name}", bucket, s3_object_name)
        
        image = Image(file_name=file_name, file_id=file_id, book_id=book_id,
                      s3_object_name=s3_object_name, user_id=g.user.id)
        db.session.add(image)
        db.session.commit()

        response = jsonify({
            'file_name': image.file_name,
            's3_object_name': s3_object_name,
            'file_id': image.file_id,
            'created_date': image.created_date,
            'user_id': image.user_id
        })
        response.status_code = 201
        return response
    else:
        response = jsonify({'message': 'Allowed file types are png, jpg, jpeg, gif'})
        response.status_code = 400
        return response


@app.route('/books/<book_id>/image/<file_id>', methods=['DELETE'])
@auth.login_required
def delete_image(book_id, file_id):

    image = Image.query.get(file_id)
    if image is None:
        return 'Not found', 404
    if g.user.id == image.user_id:
        db.session.delete(image)
        db.session.commit()

        s3 = boto3.resource('s3')
        prefix = book_id + '/' + file_id + '/'
        bucket_id = s3.Bucket(bucket)
        bucket_id.objects.filter(Prefix=prefix).delete()

        return image_schema.jsonify(image), 204
    
    else:
        return 'Unauthorized Access', 401


if __name__ == '__main__':
    if not os.path.exists('webapp.sqlite'):
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)
