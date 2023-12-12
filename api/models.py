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
