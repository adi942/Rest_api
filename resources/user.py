from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask_jwt_extended import create_access_token,create_refresh_token, get_jwt_identity, jwt_required, get_jwt
from blocklist import BLOCKLIST
from passlib.hash import pbkdf2_sha256
from db import db
from models1 import UserModel
from schemas import UserSchema

blp = Blueprint("Users", "users", description="Users actions")

@blp.route("/register")
class UserRegister(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        if UserModel.query.filter(UserModel.username == user_data["username"]).first():
            abort(409, message="User already exists")
        user = UserModel(username=user_data["username"], password = pbkdf2_sha256.hash(user_data["password"]))

        db.session.add(user)
        db.session.commit()

        return {"message": "User registered succesfully"}, 201


@blp.route("/user/<int:user_id>")
class User(MethodView):
    @blp.response(200, UserSchema)
    def get(self, user_id):
        user = UserModel.query.get_or_404(user_id)
        return user


    def delete(self, user_id):
        user = UserModel.query.get_or_404(user_id)

        db.session.delete(user)
        db.session.commit()

        return {"message": "User deleted"}, 200


@blp.route("/login")
class UserLogin(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        user = UserModel.query.filter(UserModel.username == user_data["username"]).first()
        if user and pbkdf2_sha256.verify(user_data["password"], user.password):
            acess_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(identity=user.id)

            return {"access_token": acess_token, "refresh_token": refresh_token}, 200
        abort(401, message="Invalid credentials")



@blp.route("/userinfo")
class UserInfo(MethodView):
    @jwt_required()
    @blp.response(200, UserSchema(many=True))
    def get(self):
        users = UserModel.query.all()
        return users

@blp.route("/logout")
class UserLogout(MethodView):
    @jwt_required()
    def post(self):
        jti = get_jwt()["jti"]
        BLOCKLIST.add(jti)

        return {"message": "succesfully logged out"}, 200


@blp.route("/refresh")
class RefreshToken(MethodView):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)

        # Make it clear that when to add the refresh token to the blocklist will depend on the app design
        jti = get_jwt()["jti"]
        BLOCKLIST.add(jti)

        return {"access_token": new_token}, 200



