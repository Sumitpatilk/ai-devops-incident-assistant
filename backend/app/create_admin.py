import getpass
import sys

from app.services.auth_store import create_user


def main():
    username = input("Choose a username: ").strip()
    password = getpass.getpass("Choose a password (minimum 12 characters): ")
    confirmation = getpass.getpass("Confirm password: ")

    if password != confirmation:
        print("Passwords do not match.", file=sys.stderr)
        raise SystemExit(1)

    try:
        create_user(username, password)
    except ValueError as exc:
        print(f"Account was not created: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    print(f"Local account '{username}' created successfully.")


if __name__ == "__main__":
    main()
