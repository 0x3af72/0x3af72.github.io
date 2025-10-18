---
title: Yapper catcher
date: 2025-10-19 08:00:00 +0800
categories: [Cybersecurity]
tags: [linectf, web]
description: The easiest web exploitation challenge on LINECTF 2025
---

### The Challenge

![](/assets/img/posts/Yapper%20catcher/img1.png)
*Is this a LLM challenge?*

There was a lot of code to analyze in this challenge. Although there was an admin bot, this wasn't an XSS challenge. Instead, the admin bot creates a post that contains the flag in it.

`username` is an value which we control.

```js
await page.goto(process.env.SERVER_URL + '/?user=' + username)
await page.type('input#username', username);
await page.type('textarea#quote', quote);
await page.click('button#post-status');
await page.waitForNavigation();
```

I originally thought we had to use NoSQL injection to find the post created by the admin bot, and then somehow find the key to decrypt the post.

Looking at the `/` route, it actually goes through `status.getStatus` first.

```js
router.get('/', status.getStatus, status.newStatus);
```

As `req.param` also checks the query string, it's possible to submit something like `/?id[$ne]=awd` to do some sort of NoSQL injection, but this is useless. We also can't query other fields in the database.

```js
exports.getStatus = async (req, res, next) => {
  const statusId = req.param('id');
  if (!statusId) {
    return next()
  }
  const status = await Status.getStatus(statusId);
  if (!status) {
    return next(new Error(`Can't find status with id ${statusId}`));
  }

  status.content = status.content.map(content => {
    content.userSize = parseInt(content.user.split(':')[2].length / 2);
    content.quoteSize = parseInt(content.quote.split(':')[2].length / 2);
    return content;
  });

  res.render('status', { status });
}
```

However, notice that there's a seemingly unused post updating functionality:

```js
exports.updateStatus = async (req, res, next) => {
  const id = req.param('id');
  if (!id) {
    return next();
  }

  const { user, quote } = req.body;
  try {
    await Status.updateStatus(id, user, quote);
  }
  catch (e) {
    console.error(e);
    return next(`Cannot update status with id ${id}`)
  }

  return res.redirect(`/${id}?random=${Math.random()}`);
}
```

Looking back at the admin bot code, it's also possible to add our own argument to the query string. We can make the admin bot visit `/?user=awd&id=(our id)` from this line:

```js
await page.goto(process.env.SERVER_URL + '/?user=' + username)
```

Hence, we can simply redirect the admin bot using a post ID that we've created beforehand.

Since the selectors on the page are the same, the admin bot just adds to our post, and we can easily decrypt the contents using the password we used to create the post.

![](/assets/img/posts/Yapper%20catcher/img2.png)
*This challenge was confusing...*