---
title: XSS Filtering Bypass Reborn
date: 2025-10-13 11:00:00 +0800
categories: [Cybersecurity]
tags: [dreamhack, web]
description: Level 5 web exploitation challenge on Dreamhack.io
---

### The Challenge
[https://dreamhack.io/wargame/challenges/2291](https://dreamhack.io/wargame/challenges/2291)

![](/assets/img/posts/xss-filtering-bypass-reborn/img1.png)
*XSS filter bypass challenges are quite boring*

In `app.py` a really strict filter is implemented:

```py
def xss_filter(text):
    banned_chars = '!&<>?@#$xusriptjavelnhtwdkm012456789`%'
    for i in range(0,len(banned_chars),1):
        x=banned_chars[i]
        if x in text.lower():
            return "No Hack~ ^_^"
    return text
```

We're able to execute any Javascript we want (if it passes the filters), as seen in `vuln.html`:

```html
<style type="text/css">
  .important {
    color: #336699;
  }
</style>
<img src="null" onerror="{{param}}" />
```

I was thinking of using HTML entity encoding, but that wouldn't work because of `&` being filtered, as well as most of the digits from `0-9`.

I spent some time looking into homoglyphs and trying to get them to normalize into actual ASCII characters after passing the filters, but this did not work either.

Using JSF\*ck would have worked if `!` wasn't filtered. However this gave me an idea to find other Javascript obfuscators like JSF\*ck.

After some searching, I found this tool which could obfuscate my Javascript payload, bypassing the filters: [https://jamtg.github.io/aaencode-and-aadecode/](https://jamtg.github.io/aaencode-and-aadecode/)


![](/assets/img/posts/xss-filtering-bypass-reborn/img2.png)
*Generating the obfuscated payload*

![](/assets/img/posts/xss-filtering-bypass-reborn/img3.png)
*It works!*

Now that we can run arbitrary Javascript, solving the rest of the challenge is trivial and left as an exercise for the reader.