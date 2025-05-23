#!/opt/data-gather/venv/bin/python
import argparse
from utils import email_lookup, name_lookup

def main():
    parser = argparse.ArgumentParser(description="Simple OSINT Tool")
    parser.add_argument("--email", help="Target email address")
    parser.add_argument("--name", help="Target full name")
    args = parser.parse_args()

    if args.email:
        print(f"[*] Looking up email: {args.email}")
        email_lookup.search_by_email(args.email)
    if args.name:
        print(f"[*] Looking up name: {args.name}")
        name_lookup.search_by_name(args.name)

if __name__ == "__main__":
    main()

