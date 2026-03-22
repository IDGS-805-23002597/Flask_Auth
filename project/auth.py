from flask import Blueprint, render_template, redirect, url_for, request,flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_security import login_required
from flask_security.utils import login_user, logout_user
from .models import User
from . import db, user_datastore
import logging
from flask_security import current_user
import uuid

auth= Blueprint('auth', __name__, url_prefix='/security')

@auth.route('/login')
def login():
    return render_template('/security/login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email=request.form.get('email')
    password=request.form.get('password')
    remember=True if request.form.get('remember')else False
    

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        logging.warning(f"Intento fallido de login: {email}")
        flash("El usuario y/o la contraseña son incorrectos")
        return redirect(url_for('auth.login'))

    login_user(user, remember=remember)

    logging.info(f"Login exitoso: {user.email}")

    return redirect(url_for("main.profile"))

@auth.route("/register")
def register():
    return render_template('/security/register.html')

@auth.route('/register', methods=['POST'])
def register_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()

    if user:
        logging.warning(f"Intento de registro con correo existente: {email}")
        flash("El correo electrónico ya existe")
        return redirect(url_for('auth.register'))

    # Crear nuevo usuario
    # Crear nuevo usuario
    password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    user = user_datastore.create_user(
        name=name,
        email=email,
        password=password_hash,
        fs_uniquifier=str(uuid.uuid4())
    )

    user_datastore.add_role_to_user(user, 'end-user')
    db.session.commit()

    # LOG de registro exitoso
    logging.info(f"Nuevo usuario registrado: {email}")

    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    # Guardar email antes de cerrar sesión
    email = current_user.email

    logout_user()

    # LOG de logout
    logging.info(f"Logout usuario: {email}")

    return redirect(url_for('main.index'))
        