# Minotaur

An HTTP Login Bruteforcer written in Python

## ⚙️ Requirements

- Python 3.x

## 📂 Files

- `minotaur.py`: The main script file.
- `username.txt`: A text file containing a list of usernames.
- `password.txt`: A text file containing a list of passwords.

## 🚀 Usage

Bruteforce via HTTP POST method:

```bash
python3 minotaur.py -h http://api.example.org/v1/login -u username.txt -p password.txt -m http-post -d "username=^USER^&password=^PASS^"
```

Bruteforce via Authorization Basic method:

```bash
python3 minotaur.py -h http://api.example.org/v1/login -u username.txt -p password.txt -m basic -d "anypayload"
```
