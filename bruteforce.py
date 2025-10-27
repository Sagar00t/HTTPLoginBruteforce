import requests
import argparse
from pathlib import Path
from urllib.parse import urlparse, parse_qsl, urlencode
import sys

####################
# global variables #
####################
found = False
mode_list = ["http-post"]

#get bad login response to make the filtering a good response
def httppost_bad_request(url,data):

    filled = data.replace("^USER^", "input1").replace("^PASS^", "input2")
    data = dict(parse_qsl(filled))

    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(url, json=data, headers=headers)
    bad_request = {}
    bad_request["status"] = response.status_code
    bad_request["text"] = response.text
    print("Failed HTTP status : "+str(response.status_code))
    print("Failed HTTP body : "+response.text)
    print("Failed HTTP request : ")
    print("---")
    req = response.request
    print(f"{req.method} {req.url}")
    for i in dict(req.headers):
        print(i+"="+req.headers[i])
    print(urlencode(data))
    print("---")
    return bad_request

def httppost(url,username,password,bad_request_data,data):
    global found 

    filled = data.replace("^USER^", username).replace("^PASS^", password)
    data = dict(parse_qsl(filled))
    
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
    global found 
    global mode_list

    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Example script that accepts host, username file and password file.",
        add_help=False,  # we'll provide a custom --help so we can use -h for host
    )

    parser.add_argument("-h", "--host", dest="host", required=True,
                        help="Target host URL (e.g. http://example.com)")
    parser.add_argument("-m", "--mode", dest="mode", required=True,
                        help="This is the authentification mode")
    parser.add_argument("-d", "--data", dest="data", required=True,
                        help="This shows how the data is set")
    parser.add_argument("-u", "--user-file", dest="user_file", required=True,
                        help="Path to username file (one username per line)")
    parser.add_argument("-p", "--pass-file", dest="pass_file", required=True,
                        help="Path to password file (one password per line)")
    args = parser.parse_args(argv)

    host = args.host
    mode = args.mode
    data = args.data

    funcs = [httppost]
    funcs_bad_request = [httppost_bad_request]

    # Validate URL
    if not is_valid_url(args.host):
        parser.error(f"Invalid host URL: {args.host}")
    if mode not in mode_list:
        parser.error(f"The mode must be in the following list : "+str(mode))
    
    mode_index = mode_list.index("http-post")

    print("------------")
    print("URL : "+host)
    bad_request_data = funcs_bad_request[mode_index](host,data)
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
            funcs[mode_index](host,user,password,bad_request_data,data)
    print()
    global found 
    if not found:
        print(f"\rFAILED")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())

