from typing import Tuple
from itertools import groupby
from passlib.hash import pbkdf2_sha256 as sha256
from sqlalchemy.exc import SQLAlchemyError
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt, get_jwt_identity
from flask_jwt_extended.exceptions import RevokedTokenError
from flask_restful import reqparse, Resource
from api.models import *
from app import db

login_parser = reqparse.RequestParser()
login_parser.add_argument('username', required=True)
login_parser.add_argument('password', required=True)


class UserRegister(Resource):
    @staticmethod
    def post() -> dict:
        data = login_parser.parse_args()
        user = UserModel.find_by_username(data['username'])

        if user:
            return {'error': 'Username \'{}\' is invalid'.format(data['username'])}
        try:
            UserModel(username=data['username'], password_hash=sha256.hash(data['password'])).add()
        except SQLAlchemyError:
            return {'error': 'Something gone wrong'}
        return {}


class UserLogin(Resource):
    @staticmethod
    def post() -> dict or Tuple[dict, int]:
        data = login_parser.parse_args()
        user = UserModel.find_by_username(data['username'])

        if user and sha256.verify(data['password'], user.password_hash):
            return {'id': user.user_id,
                    'username': user.username,
                    'access_token': create_access_token(identity=data['username']),
                    'refresh_token': create_refresh_token(identity=data['username'])
                    }
        else:
            return {'message': 'Incorrect username or password'}


class UserLogoutAccessToken(Resource):
    @staticmethod
    @jwt_required()
    def post() -> dict or Tuple[dict, int]:
        jti = get_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {'message': 'Token has been revoked'}
        except RevokedTokenError:
            return {'message': 'Something gone wrong...'}, 500


class UserLogoutRefreshToken(Resource):
    @staticmethod
    @jwt_required(refresh=True)
    def post() -> dict or Tuple[dict, int]:
        jti = get_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {'message': 'Token has been revoked'}
        except RevokedTokenError:
            return {'message': 'Something gone wrong...'}, 500


class TokenRefresh(Resource):
    @staticmethod
    @jwt_required(refresh=True)
    def post():
        return {'access_token': create_access_token(identity=get_jwt_identity())}


class Problem(Resource):
    @staticmethod
    def get(title: str, user_id: str):
        problem = db.session.query(ProblemModel).filter(ProblemModel.check_title(title)).first()
        if not problem:
            return {'message': 'Page not found'}, 404
        feedback_positive = db.session.query(func.sum(FeedbackModel.feedback)) \
            .where(FeedbackModel.problem_id == problem.id) \
            .where(FeedbackModel.feedback > 0).scalar()
        feedback_negative = db.session.query(func.abs(func.sum(FeedbackModel.feedback))) \
            .where(FeedbackModel.problem_id == problem.id) \
            .where(FeedbackModel.feedback < 0).scalar()
        testcases = db.session.query(TestcaseModel, TestcaseInputModel, TestcaseOutputModel) \
            .where(TestcaseModel.problem_id == problem.id) \
            .where(TestcaseModel.id == TestcaseInputModel.testcase_id) \
            .where(TestcaseModel.id == TestcaseOutputModel.testcase_id) \
            .all()
        submissions = db.session.query(SubmissionModel) \
            .where(SubmissionModel.problem_id == problem.id)
        submissions_all = submissions.all()
        submissions_accepted = submissions.where(SubmissionModel.status == 'Accepted')
        user_id = int(user_id)
        state = 2
        if submissions_accepted.where(SubmissionModel.user_id == user_id).all():
            state = 0
        elif submissions.where(SubmissionModel.user_id == user_id).all():
            state = 1
        tags = db.session.query(ProblemTagModel, TagModel) \
            .where(ProblemTagModel.problem_id == problem.id) \
            .where(ProblemTagModel.tag_id == TagModel.id) \
            .all()

        return {
            'title': problem.title,
            'difficulty': problem.difficulty,
            'state': state,
            'likes': feedback_positive,
            'dislikes': feedback_negative,
            'description': problem.description,
            'code': problem.code,
            'totalAccepted': len(submissions_accepted.all()),
            'totalSubmissions': len(submissions_all),
            'tags': sorted([tag.TagModel.name for tag in tags]),
            'testcases': [{
                'input': {
                    t.TestcaseInputModel.name: t.TestcaseInputModel.value for t in list(ts)
                },
                'output': output
            } for output, ts in groupby(testcases, lambda t: t.TestcaseOutputModel.value)],
            'submissions': [{
                'status': submission.SubmissionModel.status,
                'runtime': submission.SubmissionModel.runtime,
                'memory': submission.SubmissionModel.memory,
                'code': submission.SubmissionModel.code
            } for submission in submissions_all]
        }
