import json
import time
import requests

data = {'username': 'jack', 'password': 'password'}
r = requests.post("http://0.0.0.0:9000/login", data=json.dumps(data))
access_token = r.headers["Authorization"]
refresh_token = r.headers["Refresh"]
print("POST http://0.0.0.0:9000/login")
print(r)
print(f"access token: {access_token}")
print(f"refresh token: {refresh_token}", "\n")


headers = {"Authorization": access_token}
r = requests.get("http://0.0.0.0:9000/protected", headers=headers)
print("GET http://0.0.0.0:9000/protected with access token")
print(r, r.text, "\n")


r = requests.get("http://0.0.0.0:9000/protected")
print("GET http://0.0.0.0:9000/protected without access token")
print(r, r.text, "\n")

time.sleep(1)
headers = {"Authorization": access_token, "Refresh": refresh_token}
r = requests.get("http://0.0.0.0:9000/refresh", headers=headers)
access_token = r.headers["Authorization"]
refresh_token = r.headers["Refresh"]
print("GET http://0.0.0.0:9000/refresh")
print(r)
print(f"access token: {access_token}")
print(f"refresh token: {refresh_token}", "\n")


headers = {"Authorization": access_token, "Refresh": refresh_token}
r = requests.get("http://0.0.0.0:9000/protected", headers=headers)
print("GET http://0.0.0.0:9000/protected with access token")
print(r, r.text, "\n")
