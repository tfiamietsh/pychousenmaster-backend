from datetime import timedelta
from flask import Flask, Response
from flask_jwt_extended import JWTManager
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from utils.json_config_loader import JSONConfigLoader

config = JSONConfigLoader.load('config.json')
app = Flask(config['name'])
app.config.update({
    'CORS_HEADERS': 'Content-Type',
    'SQLALCHEMY_DATABASE_URI': 'postgresql://{pg_user}:{pg_pass}@localhost:{pg_port}/{pg_db}'.format(**config),
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SECRET_KEY': config['secret_key'],
    'JWT_SECRET_KEY': 'jwt-' + config['secret_key'],
    'JWT_ACCESS_TOKEN_EXPIRES': timedelta(minutes=10),
    'JWT_BLACKLIST_ENABLED': True,
    'JWT_BLACKLIST_TOKEN_CHECKS': ['access', 'refresh']
})
cors = CORS(app)
api = Api(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)


@app.after_request
def add_headers(response: Response) -> Response:
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:' + config['cli_port'])
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response


@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(_, decrypted_token: dict):
    jti = decrypted_token['jti']
    return RevokedTokenModel.is_jti_in_blocklist(jti)


from api.resources import *

api.add_resource(UserLogin, '/login')
api.add_resource(UserRegister, '/register')
api.add_resource(UserLogoutAccessToken, '/logout/access')
api.add_resource(UserLogoutRefreshToken, '/logout/refresh')
api.add_resource(TokenRefresh, '/token/refresh')
api.add_resource(Problem, '/problem/<string:title>')
api.add_resource(LeaveFeedback, '/feedback')
api.add_resource(GetFeedback, '/feedback/<string:title>+<string:user_id>')
api.add_resource(SandboxRun, '/run')
api.add_resource(SandboxSubmit, '/submit')
api.add_resource(Submissions, '/submissions/<string:title>+<string:user_id>')
api.add_resource(NewChallenge, '/new-challenge')
api.add_resource(ToggleChallenge, '/toggle-challenge')
api.add_resource(Challenges, '/challenges')
api.add_resource(UserChallenges, '/user-challenges/<string:username>+<string:authorized>')
api.add_resource(DeleteChallenge, '/delete-challenge')
api.add_resource(AddChallengeProblem, '/add-challenge-problem')
api.add_resource(DeleteChallengeProblem, '/delete-challenge-problem')
api.add_resource(ProblemChallenges, '/problem-challenges/<string:username>+<string:title>')
api.add_resource(Tags, '/tags')
api.add_resource(Problems, '/problems/<string:pattern>+<int:mask>+<string:user_id>')

with app.app_context():
    db.create_all()
