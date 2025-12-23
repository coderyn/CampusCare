from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError

# Import from your app (single-file structure)
from website.app import db, User

auth_bp = Blueprint("auth", __name__)

# ---------- Forms ----------
class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Create Student Account")

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError("Username already taken.")

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError("Email already registered.")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class ProfileForm(FlaskForm):
    # NOTE: your User model currently has no bio field.
    # If you want bio, add it to User model first.
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=80)])
    submit = SubmitField("Update Profile")

class AdminLoginForm(FlaskForm):
    email = StringField("Admin Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Admin Login")


# ---------- Routes ----------
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            role="student",
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        flash("Student account created! Please login.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Logged in successfully.", "success")

            # same behavior as your old code:
            next_page = request.args.get("next") or url_for("dashboard")
            return redirect(next_page)

        flash("Invalid credentials.", "error")

    return render_template("login.html", form=form)


@auth_bp.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if current_user.is_authenticated and current_user.role == "admin":
        return redirect(url_for("admin_issues"))

    form = AdminLoginForm()
    if form.validate_on_submit():
        admin = User.query.filter_by(email=form.email.data, role="admin").first()
        if admin and admin.check_password(form.password.data):
            login_user(admin)
            flash("Admin logged in.", "success")
            return redirect(url_for("admin_issues"))

        flash("Invalid admin credentials.", "error")

    return render_template("admin_login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("home"))


@auth_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    # student profile
    if current_user.role != "student":
        flash("Only students can access profile.", "error")
        return redirect(url_for("home"))

    form = ProfileForm()
    if request.method == "GET":
        form.username.data = current_user.username

    if form.validate_on_submit():
        existing = User.query.filter_by(username=form.username.data).first()
        if existing and existing.id != current_user.id:
            flash("Username already taken.", "error")
            return redirect(url_for("auth.profile"))

        current_user.username = form.username.data
        db.session.commit()
        flash("Profile updated.", "success")
        return redirect(url_for("auth.profile"))

    return render_template("profile.html", form=form)

