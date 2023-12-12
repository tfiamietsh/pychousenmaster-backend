from typing import Tuple
from passlib.hash import pbkdf2_sha256 as sha256
from sqlalchemy.exc import SQLAlchemyError
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt, get_jwt_identity
from flask_jwt_extended.exceptions import RevokedTokenError
from flask_restful import reqparse, Resource
from api.models import UserModel, RevokedTokenModel

login_parser = reqparse.RequestParser()
login_parser.add_argument('username', required=True)
login_parser.add_argument('password', required=True)


class UserRegister(Resource):
    @staticmethod
    def post() -> dict:
        data = login_parser.parse_args()
        user = UserModel.find_by_username(data['username'])

        if user:
            return {'message': 'User \'{}\' already exists'}
        try:
            UserModel(username=data['username'], password_hash=sha256.hash(data['password'])).add()
        except SQLAlchemyError:
            return {'message': 'Something gone wrong'}
        return {}


class UserLogin(Resource):
    @staticmethod
    def post() -> dict or Tuple[dict, int]:
        data = login_parser.parse_args()
        user = UserModel.find_by_username(data['username'])

        if not user:
            return {'message': 'User \'{}\' does not exist'}
        if sha256.verify(data['password'], user.password_hash):
            return {'id': user.user_id,
                    'username': user.username,
                    'access_token': create_access_token(identity=data['username']),
                    'refresh_token': create_refresh_token(identity=data['username'])
                    }
        else:
            return {'message': 'Wrong password'}


class UserLogoutToken(Resource):
    @staticmethod
    def _post() -> dict or Tuple[dict, int]:
        jti = get_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {'message': 'Token has been revoked'}
        except RevokedTokenError:
            return {'message': 'Something gone wrong...'}, 500


class UserLogoutAccessToken(UserLogoutToken):
    @staticmethod
    @jwt_required()
    def post() -> dict or Tuple[dict, int]:
        return super()._post()


class UserLogoutRefreshToken(UserLogoutToken):
    @staticmethod
    @jwt_required(refresh=True)
    def post() -> dict or Tuple[dict, int]:
        return super()._post()


class TokenRefresh(Resource):
    @staticmethod
    @jwt_required(refresh=True)
    def post():
        return {'access_token': create_access_token(identity=get_jwt_identity())}


class Dummy(Resource):
    @staticmethod
    def get():
        return {'message': 'backend works!'}
