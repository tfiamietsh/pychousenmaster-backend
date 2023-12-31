import json
from typing import Tuple
from itertools import groupby
from functools import reduce
from datetime import datetime
from calendar import monthrange
from passlib.hash import pbkdf2_sha256 as sha256
from sqlalchemy.exc import SQLAlchemyError
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt, get_jwt_identity
from flask_jwt_extended.exceptions import RevokedTokenError
from flask_restful import reqparse, Resource
from api.models import *
from app import db
from utils.sandbox import Sandbox

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
                    'refresh_token': create_refresh_token(identity=data['username']),
                    'role': user.role}
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


class Users(Resource):
    @staticmethod
    def get(pattern: str):
        usernames = db.session.query(UserModel).filter(UserModel.username.ilike(pattern)).all()
        return {'users': [{'username': t.username} for t in usernames]}


class TokenRefresh(Resource):
    @staticmethod
    @jwt_required(refresh=True)
    def post():
        return {'access_token': create_access_token(identity=get_jwt_identity())}


class NewProblem(Resource):
    @staticmethod
    def post():
        new_problem_data_parser = reqparse.RequestParser()
        new_problem_data_parser.add_argument('problem', required=True)

        data = new_problem_data_parser.parse_args()
        problem_raw = json.loads(data['problem'])
        problem = ProblemModel(title=problem_raw['title'], difficulty=int(problem_raw['difficulty']),
                               description=problem_raw['description'], solution=problem_raw['solution'])
        problem.add()
        for tc in problem_raw['testcases']:
            testcase = TestcaseModel(problem_id=problem.id)
            testcase.add()
            for name in tc['input']:
                TestcaseInputModel(testcase_id=testcase.id, name=name, value=tc['input'][name]).add()
            TestcaseOutputModel(testcase_id=testcase.id, value=tc['output']).add()
        i, n = 0, problem_raw['tagsMask']
        while n > 0:
            if n & 1:
                ProblemTagModel(problem_id=problem.id, tag_id=i + 1).add()
            n, i = n >> 1, i + 1


class Problem(Resource):
    @staticmethod
    def get(title: str):
        problem = db.session.query(ProblemModel).filter(ProblemModel.check_title(title)).first()
        if not problem:
            return {'message': 'Page not found'}, 404
        testcases = db.session.query(TestcaseModel, TestcaseInputModel, TestcaseOutputModel) \
            .where(TestcaseModel.problem_id == problem.id) \
            .where(TestcaseModel.id == TestcaseInputModel.testcase_id) \
            .where(TestcaseModel.id == TestcaseOutputModel.testcase_id) \
            .all()
        tags = db.session.query(ProblemTagModel, TagModel) \
            .where(ProblemTagModel.problem_id == problem.id) \
            .where(ProblemTagModel.tag_id == TagModel.id) \
            .all()

        return {
            'title': problem.title,
            'difficulty': problem.difficulty,
            'description': problem.description,
            'code': problem.solution[:problem.solution.index('\n')],
            'tags': sorted([tag.TagModel.name for tag in tags]),
            'testcases': [{
                'input': {
                    t.TestcaseInputModel.name: t.TestcaseInputModel.value for t in list(ts)
                },
                'output': output
            } for output, ts in groupby(testcases, lambda t: t.TestcaseOutputModel.value)][:3]
        }


class LeaveFeedback(Resource):
    @staticmethod
    def post():
        feedback_parser = reqparse.RequestParser()
        feedback_parser.add_argument('title', required=True)
        feedback_parser.add_argument('user_id', required=True)
        feedback_parser.add_argument('feedback', required=True)

        data = feedback_parser.parse_args()
        user_id, feedback = int(data['user_id']), int(data['feedback'])
        if user_id > 0:
            problem = db.session.query(ProblemModel).filter(ProblemModel.title == data['title']).first()
            feedback_query = db.session.query(FeedbackModel) \
                .filter(FeedbackModel.problem_id == problem.id) \
                .filter(FeedbackModel.user_id == user_id)

            if feedback_query.all():
                feedback_query.update({'feedback': feedback})
                db.session.commit()
            else:
                FeedbackModel(user_id=user_id, problem_id=problem.id, feedback=feedback).add()
        return {}, 200


class GetFeedback(Resource):
    @staticmethod
    def get(title: str, user_id: str):
        problem = db.session.query(ProblemModel).filter(ProblemModel.title == title).first()
        feedbacks_positive = db.session.query(func.sum(FeedbackModel.feedback)) \
            .where(FeedbackModel.problem_id == problem.id) \
            .where(FeedbackModel.feedback > 0).scalar()
        feedbacks_negative = db.session.query(func.abs(func.sum(FeedbackModel.feedback))) \
            .where(FeedbackModel.problem_id == problem.id) \
            .where(FeedbackModel.feedback < 0).scalar()
        user_feedback = db.session.query(FeedbackModel) \
            .where(FeedbackModel.problem_id == problem.id) \
            .where(FeedbackModel.user_id == int(user_id)).all()
        feedback = 0
        if user_feedback:
            feedback = user_feedback[0].feedback
        return {
            'positive': feedbacks_positive,
            'negative': feedbacks_negative,
            'user': feedback
        }


class SandboxRun(Resource):
    @staticmethod
    def post():
        sandbox_data_parser = reqparse.RequestParser()
        sandbox_data_parser.add_argument('title', required=True)
        sandbox_data_parser.add_argument('code', required=True)
        sandbox_data_parser.add_argument('testcases', required=True)

        data = sandbox_data_parser.parse_args()
        problem = db.session.query(ProblemModel).filter(ProblemModel.title == data['title']).first()
        method_name = problem.solution[4:problem.solution.find('(')]
        response = Sandbox.test(data['code'], method_name, data['testcases'], problem.solution)
        return {
            key: response[key] for key in ['outputs', 'expected', 'status']
        }


class SandboxSubmit(Resource):
    @staticmethod
    def post():
        sandbox_data_parser = reqparse.RequestParser()
        sandbox_data_parser.add_argument('title', required=True)
        sandbox_data_parser.add_argument('user_id', required=True)
        sandbox_data_parser.add_argument('code', required=True)

        data = sandbox_data_parser.parse_args()
        user_id = int(data['user_id'])
        if user_id > 0:
            dt = datetime.now()
            problem = db.session.query(ProblemModel).filter(ProblemModel.title == data['title']).first()
            method_name = problem.solution[4:problem.solution.find('(')]
            testcases_raw = db.session.query(TestcaseModel, TestcaseInputModel, TestcaseOutputModel) \
                .where(TestcaseModel.problem_id == problem.id) \
                .where(TestcaseModel.id == TestcaseInputModel.testcase_id) \
                .where(TestcaseModel.id == TestcaseOutputModel.testcase_id) \
                .all()
            testcases = str([{
                'input': {
                    t.TestcaseInputModel.name: t.TestcaseInputModel.value for t in list(ts)
                },
                'output': output
            } for output, ts in groupby(testcases_raw, lambda t: t.TestcaseOutputModel.value)])
            response = Sandbox.test(data['code'], method_name, testcases, problem.solution)
            SubmissionModel(problem_id=problem.id, user_id=user_id, runtime=response['runtime'],
                            memory=response['memory'], status=response['status'], datetime=dt, code=data['code']).add()
        return {}, 200


class Submissions(Resource):
    @staticmethod
    def get(title: str, user_id: str):
        user_id = int(user_id)
        problem = db.session.query(ProblemModel).filter(ProblemModel.title == title).first()
        submissions = db.session.query(SubmissionModel) \
            .where(SubmissionModel.problem_id == problem.id)
        submissions_all = submissions.all()
        submissions_accepted = submissions.where(SubmissionModel.status == 'Accepted')
        user_submissions = submissions.where(SubmissionModel.user_id == user_id).all()
        state = 2

        if submissions_accepted.where(SubmissionModel.user_id == user_id).all():
            state = 0
        elif user_submissions:
            state = 1
        return {
            'problemState': state,
            'totalAccepted': len(submissions_accepted.all()),
            'totalSubmissions': len(submissions_all),
            'submissions': [{
                'status': submission.status,
                'runtime': submission.runtime,
                'memory': submission.memory,
                'date': submission.datetime.strftime('%b %d, %Y'),
                'code': submission.code
            } for submission in sorted(user_submissions, key=lambda submission: submission.datetime, reverse=True)]
        }


class NewChallenge(Resource):
    @staticmethod
    def post():
        new_challenge_data_parser = reqparse.RequestParser()
        new_challenge_data_parser.add_argument('username', required=True)
        new_challenge_data_parser.add_argument('name', required=True)

        data = new_challenge_data_parser.parse_args()
        user = UserModel.find_by_username(data['username'])
        if user:
            ChallengeModel(user_id=user.user_id, name=data['name'], is_public=False).add()
        return {}


class ToggleChallenge(Resource):
    @staticmethod
    def post():
        toggle_challenge_data_parser = reqparse.RequestParser()
        toggle_challenge_data_parser.add_argument('username', required=True)
        toggle_challenge_data_parser.add_argument('name', required=True)

        data = toggle_challenge_data_parser.parse_args()
        user = UserModel.find_by_username(data['username'])
        query = db.session.query(ChallengeModel) \
            .filter(ChallengeModel.user_id == user.user_id) \
            .filter(ChallengeModel.name == data['name'])
        if query.all():
            query.update({'is_public': not query.first().is_public})
            db.session.commit()
        return {}


class Challenges(Resource):
    @staticmethod
    def get(pattern: str):
        return {'challenges': [{
            'name': t.ChallengeModel.name,
            'username': t.UserModel.username
        } for t in db.session.query(ChallengeModel, UserModel).filter(ChallengeModel.name.ilike(pattern))
            .filter(ChallengeModel.is_public).filter(ChallengeModel.user_id == UserModel.user_id).all()]}


class UserChallenges(Resource):
    @staticmethod
    def get(username: str, authorized: str):
        user = UserModel.find_by_username(username)
        if not user:
            return {}, 404
        query = db.session.query(ChallengeModel).filter(ChallengeModel.user_id == user.user_id)
        if authorized == 'false':
            query = query.filter(ChallengeModel.is_public)
        return {'challenges': [{
            'name': challenge.name,
            'isPublic': challenge.is_public,
            'problems': list(sorted(map(lambda t: t.ProblemModel.title,
                                        db.session.query(ChallengeProblemModel, ProblemModel)
                                        .filter(ChallengeProblemModel.challenge_id == challenge.id)
                                        .filter(ChallengeProblemModel.problem_id == ProblemModel.id).all())))
        } for challenge in list(sorted(query.all(), key=lambda challenge: challenge.id))]}


class DeleteChallenge(Resource):
    @staticmethod
    def post():
        delete_challenge_data_parser = reqparse.RequestParser()
        delete_challenge_data_parser.add_argument('username', required=True)
        delete_challenge_data_parser.add_argument('name', required=True)

        data = delete_challenge_data_parser.parse_args()
        db.session.query(ChallengeModel) \
            .filter(ChallengeModel.user_id == UserModel.find_by_username(data['username']).user_id) \
            .filter(ChallengeModel.name == data['name']).delete()
        db.session.commit()
        return {}


class AddChallengeProblem(Resource):
    @staticmethod
    def post():
        add_challenge_problem_data_parser = reqparse.RequestParser()
        add_challenge_problem_data_parser.add_argument('username', required=True)
        add_challenge_problem_data_parser.add_argument('challenge_name', required=True)
        add_challenge_problem_data_parser.add_argument('problem_title', required=True)

        data = add_challenge_problem_data_parser.parse_args()
        challenge = db.session.query(ChallengeModel) \
            .filter(ChallengeModel.user_id == UserModel.find_by_username(data['username']).user_id) \
            .filter(ChallengeModel.name == data['challenge_name']).first()
        problem = db.session.query(ProblemModel) \
            .filter(ProblemModel.title == data['problem_title']).first()
        ChallengeProblemModel(challenge_id=challenge.id, problem_id=problem.id).add()
        return {}


class DeleteChallengeProblem(Resource):
    @staticmethod
    def post():
        delete_challenge_problem_data_parser = reqparse.RequestParser()
        delete_challenge_problem_data_parser.add_argument('username', required=True)
        delete_challenge_problem_data_parser.add_argument('challenge_name', required=True)
        delete_challenge_problem_data_parser.add_argument('problem_title', required=True)

        data = delete_challenge_problem_data_parser.parse_args()
        challenge = db.session.query(ChallengeModel) \
            .filter(ChallengeModel.user_id == UserModel.find_by_username(data['username']).user_id) \
            .filter(ChallengeModel.name == data['challenge_name']).first()
        problem = db.session.query(ProblemModel) \
            .filter(ProblemModel.title == data['problem_title']).first()
        db.session.query(ChallengeProblemModel) \
            .filter(ChallengeProblemModel.problem_id == problem.id) \
            .filter(ChallengeProblemModel.challenge_id == challenge.id).delete()
        db.session.commit()
        return {}


class ProblemChallenges(Resource):
    @staticmethod
    def get(username: str, title: str):
        user = UserModel.find_by_username(username)
        problem = db.session.query(ProblemModel).filter(ProblemModel.title == title).first()
        challenges = db.session.query(ChallengeModel) \
            .filter(ChallengeModel.user_id == user.user_id).all()
        return {'challenges': [{
            'name': challenge.name,
            'isIn': db.session.query(db.exists()
                                     .where(ChallengeProblemModel.challenge_id == challenge.id)
                                     .where(ChallengeProblemModel.problem_id == problem.id)).scalar()
        } for challenge in challenges]}


class Tags(Resource):
    @staticmethod
    def get():
        return {'tagIdxMap': {tag.name: 1 << i for i, tag in enumerate(db.session.query(TagModel).all())}}


class Problems(Resource):
    @staticmethod
    def get(mask: int, user_id: str, pattern: str):
        def get_mask(problem_id: int):
            return reduce(lambda a, b: a | b, [tag_idx_map[t.TagModel.name]
                                               for t in db.session.query(ProblemTagModel, TagModel)
                          .filter(ProblemTagModel.problem_id == problem_id)
                          .filter(ProblemTagModel.tag_id == TagModel.id).all()])

        result, tag_idx_map = [], {tag.name: 1 << i for i, tag in enumerate(db.session.query(TagModel).all())}
        problems = db.session.query(ProblemModel).filter(ProblemModel.title.ilike(pattern)).all()
        user_id = int(user_id)

        for problem in problems:
            temp_mask = get_mask(problem.id)
            submissions = db.session.query(SubmissionModel).filter(SubmissionModel.problem_id == problem.id)
            accepted = submissions.filter(SubmissionModel.status == 'Accepted')
            status = ''
            if accepted.filter(SubmissionModel.user_id == user_id).first():
                status = 'Solved'
            elif submissions.filter(SubmissionModel.user_id == user_id).first():
                status = 'Attempted'
            submissions_num = len(submissions.all())

            if (temp_mask | mask) == temp_mask:
                result.append({
                    'status': status,
                    'title': problem.title,
                    'acceptance': 100 * len(accepted.all()) / submissions_num if submissions_num else 0,
                    'difficulty': {0: 'Easy', 1: 'Medium', 2: 'Hard'}[problem.difficulty]
                })
        return {'problems': result}


class Profile(Resource):
    @staticmethod
    def get(username: str):
        def elapsed(dt: datetime):
            ans, now = '', datetime.now()
            td = now - dt
            if td.days > 0:
                if td.days > 730:
                    ans = 'years'
                elif td.days > 365:
                    ans = 'a year'
                elif td.days > 180:
                    ans = 'many months'
                elif td.days > 61:
                    ans = 'a few months'
                elif td.days > monthrange(now.year, now.month)[1]:
                    ans = 'a month'
                elif td.days > 1:
                    ans = '{} days'.format(td.days)
                else:
                    ans = 'a day'
            else:
                if td.seconds > 7200:
                    ans = '{} hours'.format(td.seconds // 3600)
                elif td.seconds > 3600:
                    ans = 'an hour'
                elif td.seconds > 120:
                    ans = '{} minutes'.format(td.seconds // 60)
                elif td.seconds > 60:
                    ans = 'a minute'
                elif td.seconds > 2:
                    ans = '{} seconds'.format(td.seconds)
                else:
                    ans = 'a moment'
            return '{} ago'.format(ans)

        user = UserModel.find_by_username(username)
        total_easy = len(db.session.query(ProblemModel).filter(ProblemModel.difficulty == 0).all())
        total_medium = len(db.session.query(ProblemModel).filter(ProblemModel.difficulty == 1).all())
        total_hard = len(db.session.query(ProblemModel).filter(ProblemModel.difficulty == 2).all())
        subquery = db.session.query(SubmissionModel.problem_id, func.max(SubmissionModel.datetime).label('dt')) \
            .group_by(SubmissionModel.problem_id).subquery()
        recent = db.session.query(SubmissionModel, ProblemModel, subquery) \
            .filter(SubmissionModel.user_id == user.user_id) \
            .filter(SubmissionModel.problem_id == subquery.c.problem_id) \
            .filter(SubmissionModel.datetime == subquery.c.dt) \
            .filter(SubmissionModel.problem_id == ProblemModel.id)
        solved = db.session.query(SubmissionModel, ProblemModel) \
            .filter(SubmissionModel.user_id == user.user_id) \
            .filter(SubmissionModel.problem_id == ProblemModel.id) \
            .filter(SubmissionModel.status == 'Accepted')
        solved_easy = len(solved.filter(ProblemModel.difficulty == 0).all())
        solved_medium = len(solved.filter(ProblemModel.difficulty == 1).all())
        solved_hard = len(solved.filter(ProblemModel.difficulty == 2).all())

        return {'profile': {
            'username': user.username,
            'solved': {'easy': solved_easy, 'medium': solved_medium, 'hard': solved_hard},
            'total': {'easy': total_easy, 'medium': total_medium, 'hard': total_hard},
            'recentAC': [{
                'title': t.ProblemModel.title,
                'elapsedTime': elapsed(t.SubmissionModel.datetime)} for t in recent.limit(10).all()]
        }}
