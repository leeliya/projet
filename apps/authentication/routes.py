# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import json
from datetime import datetime

import flask
from flask import render_template, redirect, request, url_for, flash, session
from flask_login import current_user, login_user, logout_user, login_required

from apps import db, login_manager
from apps.authentication import blueprint
from apps.authentication.forms import LoginForm, CreateAccountForm, UpdateProfileForm, ChangePasswordForm
from apps.authentication.models import Users
from apps.authentication.util import verify_pass, hash_pass
from apps.home.cleanup import clear_analysis_state


@blueprint.route('/')
def route_default():
    from flask_login import current_user
    if current_user.is_authenticated:
        # ✅ Redirige maintenant vers le dashboard
        return redirect(url_for('home_blueprint.dashboard'))
    else:
        return redirect(url_for('authentication_blueprint.login'))


# GitHub OAuth login has been removed. Only username/password login is supported now.


@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)

    if flask.request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = Users.query.filter_by(username=username).first()
        print(f"Recherche utilisateur: {username}")
        print(f"Utilisateur trouvé: {user is not None}")

        if user and verify_pass(password, user.password):
            login_user(user)
            print(f"Utilisateur {username} connecté avec succès, redirection vers /dashboard")
            # ✅ Redirection corrigée ici
            return redirect(url_for('home_blueprint.dashboard'))
        else:
            print(f"Échec de connexion pour {username}")
            return render_template('accounts/login.html',
                                   msg='Wrong user or password',
                                   form=login_form)

    if current_user.is_authenticated:
        # ✅ Correction ici aussi
        return redirect(url_for('home_blueprint.dashboard'))
    else:
        return render_template('accounts/login.html', form=login_form)


@blueprint.route('/register', methods=['GET', 'POST'])
def register():
    create_account_form = CreateAccountForm(request.form)
    if 'register' in request.form:
        username = request.form['username']
        email = request.form['email']

        user = Users.query.filter_by(username=username).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Username already registered',
                                   success=False,
                                   form=create_account_form)

        user = Users.query.filter_by(email=email).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Email already registered',
                                   success=False,
                                   form=create_account_form)

        user = Users(**request.form)
        db.session.add(user)
        db.session.commit()
        logout_user()

        return render_template('accounts/register.html',
                               msg='User created successfully.',
                               success=True,
                               form=create_account_form)
    else:
        return render_template('accounts/register.html', form=create_account_form)


"""JWT login endpoint removed; simple form-based login only."""


@blueprint.route('/logout')
def logout():
    # Nettoyer l'état d'analyse temporaire à la déconnexion
    try:
        clear_analysis_state(session)
    except Exception:
        pass

    logout_user()
    return redirect(url_for('authentication_blueprint.login'))


@blueprint.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    update_profile_form = UpdateProfileForm()
    change_password_form = ChangePasswordForm()
    password_message = None

    if request.method == 'POST':
        if 'update_profile' in request.form:
            if update_profile_form.validate_on_submit():
                current_user.full_name = update_profile_form.full_name.data
                current_user.email = update_profile_form.email.data
                current_user.mobile = update_profile_form.mobile.data
                current_user.location = update_profile_form.location.data
                db.session.commit()
                flash('Profil mis à jour avec succès!', 'success')
                return redirect(url_for('authentication_blueprint.profile'))

        elif 'change_password' in request.form:
            if change_password_form.validate_on_submit():
                old_password = change_password_form.old_password.data
                new_password = change_password_form.new_password.data
                if verify_pass(old_password, current_user.password):
                    current_user.password = hash_pass(new_password)
                    db.session.commit()
                    password_message = "Mot de passe changé avec succès!"
                else:
                    password_message = "Ancien mot de passe incorrect!"

    return render_template('home/profile.html',
                           update_profile_form=update_profile_form,
                           change_password_form=change_password_form,
                           password_message=password_message,
                           page_title='Profil',
                           segment='profile')


@blueprint.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    update_profile_form = UpdateProfileForm(request.form)

    if update_profile_form.validate_on_submit():
        current_user.full_name = update_profile_form.full_name.data
        current_user.email = update_profile_form.email.data
        current_user.mobile = update_profile_form.mobile.data
        current_user.location = update_profile_form.location.data
        db.session.commit()
        flash('Profil mis à jour avec succès!', 'success')
    else:
        flash('Erreur lors de la mise à jour du profil', 'error')

    return redirect(url_for('authentication_blueprint.profile'))


@blueprint.route('/change-password', methods=['POST'])
@login_required
def change_password():
    change_password_form = ChangePasswordForm(request.form)
    password_message = None

    if change_password_form.validate_on_submit():
        old_password = change_password_form.old_password.data
        new_password = change_password_form.new_password.data

        if verify_pass(old_password, current_user.password):
            current_user.password = hash_pass(new_password)
            db.session.commit()
            password_message = "Mot de passe changé avec succès!"
        else:
            password_message = "Ancien mot de passe incorrect!"
    else:
        password_message = "Erreur de validation du formulaire"

    return redirect(url_for('authentication_blueprint.profile', password_message=password_message))


@login_manager.unauthorized_handler
def unauthorized_handler():
    # Redirect to login with next parameter when user is not authenticated
    flash('Veuillez vous connecter pour accéder à cette page.', 'warning')
    next_url = request.url
    return redirect(url_for('authentication_blueprint.login', next=next_url))


@blueprint.errorhandler(403)
def access_forbidden(error):
    return render_template('home/page-403.html'), 403


@blueprint.errorhandler(404)
def not_found_error(error):
    return render_template('home/page-404.html'), 404


@blueprint.errorhandler(500)
def internal_error(error):
    return render_template('home/page-500.html'), 500
