from sqlalchemy import func
from app import db


class _HasAddMethod:
    def add(self):
        db.session.add(self)
        db.session.commit()


class UserModel(db.Model, _HasAddMethod):
    __tablename__ = 'users'
    user_id = db.Column(db.SmallInteger, primary_key=True, nullable=False)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.SmallInteger, nullable=False)

    @classmethod
    def find_by_username(cls, username: str) -> 'UserModel':
        return cls.query.filter_by(username=username).first()


class RevokedTokenModel(db.Model, _HasAddMethod):
    __tablename__ = 'revoked_tokens'
    token_id = db.Column(db.SmallInteger, primary_key=True, nullable=False)
    jti = db.Column(db.String(120), nullable=False)

    @classmethod
    def is_jti_in_blocklist(cls, jti: str) -> bool:
        return bool(cls.query.filter_by(jti=jti).first())


class TagModel(db.Model):
    __tablename__ = 'tags'
    id = db.Column(db.SmallInteger, primary_key=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)


class ProblemModel(db.Model, _HasAddMethod):
    __tablename__ = 'problems'
    id = db.Column(db.SmallInteger, primary_key=True, nullable=False)
    title = db.Column(db.String(120), nullable=False)
    difficulty = db.Column(db.SmallInteger, nullable=False)
    description = db.Column(db.String(2000), nullable=False)
    code = db.Column(db.String(1000), nullable=False)
    solution = db.Column(db.String(1000), nullable=False)

    @classmethod
    def check_title(cls, title: str) -> str:
        return func.replace(cls.title, ' ', '-').ilike(title)


class ProblemTagModel(db.Model, _HasAddMethod):
    __tablename__ = 'problem_tags'
    id = db.Column(db.SmallInteger, primary_key=True, nullable=False)
    problem_id = db.Column(db.SmallInteger, nullable=False)
    tag_id = db.Column(db.SmallInteger, nullable=False)


class FeedbackModel(db.Model, _HasAddMethod):
    __tablename__ = 'feedbacks'
    id = db.Column(db.SmallInteger, primary_key=True, nullable=False)
    user_id = db.Column(db.SmallInteger, nullable=False)
    problem_id = db.Column(db.SmallInteger, nullable=False)
    feedback = db.Column(db.SmallInteger, nullable=False)


class SubmissionModel(db.Model, _HasAddMethod):
    __tablename__ = 'submissions'
    id = db.Column(db.SmallInteger, primary_key=True, nullable=False)
    user_id = db.Column(db.SmallInteger, nullable=False)
    problem_id = db.Column(db.SmallInteger, nullable=False)
    status = db.Column(db.String(120), nullable=False)
    runtime = db.Column(db.SmallInteger, nullable=False)
    memory = db.Column(db.Float, nullable=False)
    datetime = db.Column(db.DateTime, nullable=False)
    code = db.Column(db.String(5000), nullable=False)


class TestcaseModel(db.Model, _HasAddMethod):
    __tablename__ = 'testcases'
    id = db.Column(db.SmallInteger, primary_key=True, nullable=False)
    problem_id = db.Column(db.SmallInteger, nullable=False)


class TestcaseInputModel(db.Model, _HasAddMethod):
    __tablename__ = 'testcase_inputs'
    id = db.Column(db.SmallInteger, primary_key=True, nullable=False)
    testcase_id = db.Column(db.SmallInteger, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    value = db.Column(db.String(5000), nullable=False)


class TestcaseOutputModel(db.Model, _HasAddMethod):
    __tablename__ = 'testcase_outputs'
    id = db.Column(db.SmallInteger, primary_key=True, nullable=False)
    testcase_id = db.Column(db.SmallInteger, nullable=False)
    value = db.Column(db.String(5000), nullable=False)


class ChallengeModel(db.Model, _HasAddMethod):
    __tablename__ = 'challenges'
    id = db.Column(db.SmallInteger, primary_key=True, nullable=False)
    user_id = db.Column(db.SmallInteger, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    is_public = db.Column(db.Boolean, nullable=False)


class ChallengeProblemModel(db.Model, _HasAddMethod):
    __tablename__ = 'challenge_problems'
    id = db.Column(db.SmallInteger, primary_key=True, nullable=False)
    challenge_id = db.Column(db.SmallInteger, nullable=False)
    problem_id = db.Column(db.SmallInteger, nullable=False)
