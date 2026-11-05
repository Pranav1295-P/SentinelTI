"""Admin commands. Usage: python -m app.cli create-user analyst@company.com"""

import argparse
import getpass
import os
import sys

from sqlalchemy import select

from app.core.db import SyncSessionLocal
from app.core.security import hash_password
from app.models import User


def create_user(email: str) -> int:
    # Environment variable for non-interactive setup, such as a first deploy script.
    password = os.environ.get("SENTINELTI_USER_PASSWORD") or getpass.getpass("Password (12+ characters): ")
    if len(password) < 12:
        print("Password must be at least 12 characters.", file=sys.stderr)
        return 1
    with SyncSessionLocal() as session:
        email = email.lower()
        if session.scalar(select(User).where(User.email == email)):
            print(f"{email} already exists.", file=sys.stderr)
            return 1
        session.add(User(email=email, password_hash=hash_password(password)))
        session.commit()
    print(f"Created {email}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("create-user").add_argument("email")
    args = parser.parse_args()
    return create_user(args.email)


if __name__ == "__main__":
    raise SystemExit(main())
