from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash

auth_bp = Blueprint(
    "auth",
    __name__,
    template_folder="templates"

@auth_bp.route("/login")
def login():
    return "Login page placeholder"

@auth_bp.route("/register")
def register():
    return "Register page placeholder"

@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))
