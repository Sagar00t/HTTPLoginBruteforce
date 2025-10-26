# HTTPLoginBruteforce

HTTP Login Bruteforce written in Python

## ⚙️ Requirements

- Python 3.x
- Internet connection
- A valid target API endpoint

## 📂 Files

- `bruteforce.py`: The main script file.
- `username.txt`: A text file containing a list of usernames.
- `password.txt`: A text file containing a list of passwords.

## 🚀 Usage

To run the script, use the following command:

```bash
python3 bruteforce.py -h http://api.example.org/v1/login -u username.txt -p password.txt
```

## 🔐 Authentication Format

Currently, the script sends credentials as a JSON payload with the following structure:

```json
{
  "email": "USERNAME",
  "password": "PASSWORD"
}
