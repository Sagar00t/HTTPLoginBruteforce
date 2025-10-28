# Minotaur

An HTTP Login Bruteforcer written in Python

## ⚙️ Requirements

- Python 3.x

## 📂 Files

- `minotaur.py`: The main script file.
- `username.txt`: A text file containing a list of usernames.
- `password.txt`: A text file containing a list of passwords.
- `req.txt`: A text file containing the request in Curl format.

## 🚀 Usage

Bruteforce via HTTP GET method:

```bash
python3 minotaur.py -h http://api.example.org/v1/login -u username.txt -p password.txt -m http-get -d "username=^USER^&password=^PASS^"
```

Bruteforce via HTTP POST method:

```bash
python3 minotaur.py -h http://api.example.org/v1/login -u username.txt -p password.txt -m http-post -d "{\"email\":\"^USER^\",\"password\":\"^PASS^\"}"
```

Bruteforce via Authorization Basic method:

```bash
python3 minotaur.py -h http://api.example.org/v1/login -u username.txt -p password.txt -m basic -d "anypayload"
```

Bruteforce via a request template:
<small><em>The format must be like the req.txt file inside this repository (Curl format).
It can be taken inside Browser Dev tools by copying into curl format.</em></small>

```bash
python3 minotaur.py -m requestfile -d req.txt -u username.txt -p password.txt
```