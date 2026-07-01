#!/usr/bin/env python3
"""
Create or reset an admin user for the SecScan JS application.

Usage:
  python scripts/create_admin.py

This script prompts for username, email and password interactively.
Run it inside your project's virtualenv (recommended):
  ./venv/bin/python scripts/create_admin.py

NOTE: This file is created locally and will not be pushed.
"""
import sys
import getpass
from pathlib import Path

# Ensure script is run from project root
ROOT = Path(__file__).resolve().parents[1]
if str(Path.cwd().resolve()) != str(ROOT):
    print(f"Warning: it's recommended to run this script from project root: {ROOT}")


def prompt(prompt_text, default=None):
    if default:
        rv = input(f"{prompt_text} [{default}]: ")
        return rv.strip() or default
    return input(f"{prompt_text}: ").strip()


def main():
    try:
        # Import app and models while inside project
        sys.path.insert(0, str(ROOT))
        from app import app
        from models import db, User
        from auth.routes import bcrypt as auth_bcrypt
    except Exception as e:
        print("Failed to import application. Run this from the project root and ensure dependencies are installed.")
        print("Error:", e)
        sys.exit(1)

    username = prompt('Admin username (login)')
    email = prompt('Admin email')
    if not username or not email:
        print('username and email are required')
        sys.exit(1)

    # Prompt for password twice
    while True:
        password = getpass.getpass('Password: ')
        password2 = getpass.getpass('Confirm password: ')
        if password != password2:
            print('Passwords do not match — try again.')
            continue
        if len(password) < 8:
            print('Use a stronger password (min 8 chars).')
            if input('Proceed anyway? (y/N): ').lower() != 'y':
                continue
        break

    confirm = input(f"Create/overwrite admin '{username}' with email '{email}'? (y/N): ").lower()
    if confirm != 'y':
        print('Aborted by user.')
        sys.exit(0)

    with app.app_context():
        existing = User.query.filter((User.username == username) | (User.email == email)).all()
        target = None
        for u in existing:
            if u.username == username or u.email == email:
                target = u
                break

        hashed = auth_bcrypt.generate_password_hash(password).decode('utf-8')

        if target:
            print(f"Found existing user (id={target.id}, role={target.role}). Updating to admin and resetting password.")
            target.username = username
            target.email = email
            target.password_hash = hashed
            target.role = 'admin'
            target.subscription_plan = 'enterprise'
            target.trial_scans_used = 0
            target.is_active = True
            db.session.commit()
            print(f"Updated user id={target.id} -> now admin.")
        else:
            new = User(
                full_name='Administrator',
                username=username,
                email=email,
                role='admin',
                password_hash=hashed,
                subscription_plan='enterprise',
                trial_scans_used=0,
                is_active=True
            )
            db.session.add(new)
            db.session.commit()
            print(f"Created new admin user id={new.id}.")

    print('Done. You can now login as the admin user.')


if __name__ == '__main__':
    main()
