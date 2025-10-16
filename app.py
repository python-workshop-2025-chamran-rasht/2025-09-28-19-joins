from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from typing import Optional
from flask import Flask, render_template, redirect, flash, request
from forms import LoginForm, SignupForm
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import sqlalchemy as sa
import sqlalchemy.orm as so
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    current_user,
    login_required,
    logout_user,
)
from urllib.parse import urlsplit
from logging.handlers import SMTPHandler
import logging

app = Flask(__name__)

app.config.from_object("default_config")
app.config.from_prefixed_env()

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_mgr = LoginManager(app)
login_mgr.login_view = "login_ep"

if not app.debug and app.config.get("MAIL_SERVER"):
    auth = None
    if app.config.get("MAIL_USERNAME") and app.config.get("MAIL_PASSWORD"):
        auth = (app.config["MAIL_USERNAME"], app.config["MAIL_PASSWORD"])

    secure = None
    if app.config.get("MAIL_USE_TLS"):
        secure = ()

    handler = SMTPHandler(
        mailhost=(app.config["MAIL_SERVER"], app.config["MAIL_PORT"]),
        fromaddr="no-reply@" + app.config["MAIL_SERVER"],
        toaddrs=[app.config["ADMIN"]],
        subject="Error in Microblogging App",
        credentials=auth,
        secure=secure,
    )

    handler.setLevel(logging.ERROR)
    app.logger.addHandler(handler)

followers_table = sa.Table(
    "followers",
    db.metadata,
    sa.Column("follower_id", sa.Integer, sa.ForeignKey("user.id"), primary_key=True),
    sa.Column("following_id", sa.Integer, sa.ForeignKey("user.id"), primary_key=True),
)


class User(UserMixin, db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    username: so.Mapped[str] = so.mapped_column(sa.String(64), index=True, unique=True)
    email: so.Mapped[str] = so.mapped_column(sa.String(128), index=True, unique=True)
    password_hash: so.Mapped[str] = so.mapped_column(sa.String(256))
    about_me: so.Mapped[Optional[str]] = so.mapped_column(sa.String(140))
    last_seen: so.Mapped[Optional[datetime]] = so.mapped_column(
        default=lambda: datetime.now(timezone.utc)
    )

    followers: so.WriteOnlyMapped["User"] = so.relationship(
        back_populates="followings",
        secondary=followers_table,
        primaryjoin=followers_table.c.following_id == id,
        secondaryjoin=followers_table.c.follower_id == id,
    )

    followings: so.WriteOnlyMapped["User"] = so.relationship(
        back_populates="followers",
        secondary=followers_table,
        primaryjoin=followers_table.c.follower_id == id,
        secondaryjoin=followers_table.c.following_id == id,
    )

    posts: so.WriteOnlyMapped["Post"] = so.relationship(back_populates="author")

    def __repr__(self) -> str:
        return f"<User {self.username}>"

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str):
        return check_password_hash(self.password_hash, password)

    def follow(self, user: 'User'):
        if not self.is_following(user):
            self.followings.add(user)

    def unfollow(self, user: 'User'):
        if self.is_following(user):
            self.followings.remove(user)

    def is_following(self, user: 'User'):
        query = self.followings.select().where(User.id == user.id)
        return db.session.scalar(query) is not None

    def followers_count(self):
        query = sa.select(sa.func.count()).select_from(
            self.followers.select().subquery()
        )
        return db.session.scalar(query)

    def followings_count(self):
        query = sa.select(sa.func.count()).select_from(
            self.followings.select().subquery()
        )
        return db.session.scalar(query)

    def following_posts(self):
        Author = so.aliased(User)
        Follower = so.aliased(User)

        return (
            sa.select(Post)
                .join(Post.author.of_type(Author))
                .join(Author.followers.of_type(Follower))
                .where(Follower.id == self.id)
                .order_by(Post.timestamp.desc())
        )


@login_mgr.user_loader
def load_user(id):
    return db.session.get(User, int(id))


class Post(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    content: so.Mapped[str] = so.mapped_column(sa.String(512))
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey(User.id), index=True)

    timestamp: so.Mapped[Optional[datetime]] = so.mapped_column(
        default=lambda: datetime.now(timezone.utc)
    )

    author: so.Mapped[User] = so.relationship(back_populates="posts")

    def __repr__(self) -> str:
        return f"<post {self.content}>"


@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.now(timezone.utc)
        db.session.commit()


@app.errorhandler(404)
def not_found_handler():
    return render_template("404.html"), 404


@app.errorhandler(500)
def error_handler():
    db.session.rollback()
    return render_template("500.html"), 500


@app.route("/")
@login_required
def index_ep():
    raise Exception("No. testing.")
    return render_template("index.html")


@app.route("/user/<username>")
@login_required
def user_ep(username: str):
    user = db.first_or_404(sa.select(User).where(User.username == username))

    posts = [
        {"author": user, "content": "Test post 1"},
        {"author": user, "content": "Test post 2"},
    ]

    return render_template("profile.html", user=user, posts=posts)


@app.route("/logout")
def logout_ep():
    logout_user()
    return redirect("/")


@app.route("/login", methods=["GET", "POST"])
def login_ep():
    if current_user.is_authenticated:
        return redirect("/")

    form = LoginForm()

    if form.validate_on_submit():
        user = db.session.scalar(
            sa.Select(User).where(User.username == form.username.data)
        )

        if user is None or not user.check_password(form.password.data):
            flash("Invalid username or password")
            return redirect("/login")

        login_user(user)

        next_page = request.args.get("next")

        if not next_page or urlsplit(next_page).netloc != "":
            next_page = "/"

        return redirect(next_page)

    return render_template("login.html", form=form)


@app.route("/signup", methods=["GET", "POST"])
def signup_ep():
    form = SignupForm()

    if form.validate_on_submit():
        flash("You are now signed up.")
        return redirect("/")

    return render_template("signup.html", form=form)
