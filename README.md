# Minotaur

An HTTP Login Bruteforcer written in Python

## ⚙️ Requirements

- Python 3.x

## 📂 Files

- `bruteforce.py`: The main script file.
- `username.txt`: A text file containing a list of usernames.
- `password.txt`: A text file containing a list of passwords.

## 🚀 Usage

To run the script, use the following command:

```bash
python3 minotaur.py -h http://api.example.org/v1/login -u username.txt -p password.txt -m http-post -d "username=^USER^&password=^PASS^"
```

## 🔐 Authentication Format

mode: http-post
data: username=^USER^&password=^PASS^

```bash
username=input1&password=input2
```