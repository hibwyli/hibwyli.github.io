---
title: "Some notes on DomPurify"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2025-07-10
draft: false
authors:
  - Hibwyli
---


# DEEP DOWN TO DOMPURIFY 
Some note when learning mxss.
Source : https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes
## DOWPURFIY WORKFLOWS : 
![image](https://hackmd.io/_uploads/BkojtKgDgl.png)
1. _initDocument_ : Dùng  API [DOMParser](https://developer.mozilla.org/en-US/docs/Web/API/DOMParser) để parse dữ liệu đúng như Browser parse
2. _createNodeIterator_ : Dùng API [NodeIterator](https://developer.mozilla.org/en-US/docs/Web/API/NodeIterator) để iterate qua tất cả các node 
3. _sanitizeElement_ :  Kiểm tra tag allowed or not 
4. _sanitizeShadowDOM  : The NodeIterator API doesn't iterate over the template tag by default. Recursively sanitizes when it reaches a DocumentFragment.
5. _sanitizeAttributes : dùng dom apis để sanitize  HTML attributes .
6. Output 
   
## How MXSS happens :  
- Vậy thì DOMPurify sử dụng cùng một hệ thống dom parser với browser vậy thì làm thế nào mà MXSS xảy ra . Có một vấn đề khá lớn đã được đề cập trong w3c : 
    ![image](https://hackmd.io/_uploads/HyNGjYevex.png)
Parse một html string  **2 lần** có thể dẫn đến những kết quả khác nhau .
Ví dụ  :
Dựa vào tính chất không chứa tag form trong form ta có thể khiến mutation xảy ra : 
![image](https://hackmd.io/_uploads/B1Vw2Kgvle.png)
![image](https://hackmd.io/_uploads/rJlX2KlDgg.png)
Note : 
**Kết quả domparser đầu tiên là thứ mà DOM purify thấy và đã check xong return về. Kết quả thứ 2 là những gì browser cho ra cuối cùng**
Đọc thêm ở : https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/?utm_source=chatgpt.com 

![image](https://hackmd.io/_uploads/rJH1JqxPxx.png)


## Foreign Content 
Hầu hết các element sẽ thuộc HTML namespace nhưng cũng có một vài element như svg và math thì svg và math sẽ thuộc cái namespace khác nhau gọi chung là Foreign Content . 
    
Cụ thể có sự khác biệt giữa tag style trong HTML namespace vs SVG namespace .
    ![image](https://hackmd.io/_uploads/SJotZ5eDel.png)
Trong html namespace thì trong style chỉ chứa text nhưng trong svg thì chứa cả element .Nhưng không hẳn là lúc nào trong foreign content thì cũng không chứa HTML namespace , ta sẽ có một vài điểm để bật html gọi là **intergration point**. 
     ![image](https://hackmd.io/_uploads/rkmSGqgwgg.png)
![image](https://hackmd.io/_uploads/SkqzQcxwel.png)
Chỉ khi token đầu tiên trong mtext là mglyph hoặc malign mark 
    ![image](https://hackmd.io/_uploads/SJAVmqewee.png)

# Rules to decide the namespace : 
![image](https://hackmd.io/_uploads/B1EhSqxvgl.png)


## Node Flattening 
Một câu hỏi khá hay là DOM có thể sâu tới bao nhiêu layers ? 
Không có một giới hạn cụ thể nào nên phụ thuộc vào thư viện  
![image](https://hackmd.io/_uploads/ry2eI5xPgx.png)
![image](https://hackmd.io/_uploads/SyTbLcgPxe.png)
Ồ  vậy là chính DOM parser đã có limit là 512 nested Node và sẽ **Flattening** ? 
    ![image](https://hackmd.io/_uploads/SkJU8cxPxg.png)
Ta có thể thấy khi vượt ngưỡng nó sẽ flat tag nested cuối cùng . Và kết quả sau khi reparse là : 
![image](https://hackmd.io/_uploads/r1E389gPle.png)

## HTML Parsing State : 
Ta sẽ cần hiểu 2 concepts sau  : 
1. Insertion modes
2. Stack of open elements 
    
Ta sẽ tập trung vào insert modes của captions in table tag : 
    ![image](https://hackmd.io/_uploads/rkMS2qxDgx.png)
Ta sẽ thấy nếu như đang trong mode in caption mà gặp thêm một tag caption nữa thì sẽ pop stack cho tới khi caption được pop out ra sau đó chuyển về in tables mode . Stack đơn giản là đọc từ trên xuống và đưa vào stack khi là start tag và pop khi là close tag . Vậy what could go wrong. Ta nhìn vào snippet sau  :  
    
```html 
<table>
  <caption>
    <div>before</div>
    <caption></caption>
    <div>after</div>
  </caption>
</table>
```
Khi parser đọc đến caption tag đầu tiên nó sẽ được vào stack và khi chạm phải open tag caption tiếp theo nó sẽ bắt đầu close tag cho đến khi caption đã được pop out khỏi tag và switch sang intable mode dẫn đến việc trên stack không tồn tại caption nữa và tag <\/caption> cũng vô nghĩa =>  div after sẽ bị chuyển về intable modes nhưng vì divs cũng không hợp lệ trong tables dẫn đến bị pop out ra và cho kết quả như sau : 
    ![image](https://hackmd.io/_uploads/ry51Tcgwgg.png)
Nhưng có  một vấn đề cuối cùng là caption không thể được nest như trong snippet thế nên để bypass cái này thì ta sẽ lợi dụng Node Flattening và kết quả là : 
    ![image](https://hackmd.io/_uploads/SJMpC5xwll.png)
Ta đã có caption nested in caption và mxss go here
    
    Final payload : https://yeswehack.github.io/Dom-Explorer/frame?input=editable&titleBar=readonly&readonly=true&pipe[titleBar]=true&pipe[settings]=true&pipe[render]=true&pipe[skip]=true/#eyJpbnB1dCI6IjxkaXYqNTA2PlxuPHRhYmxlPlxuICA8Y2FwdGlvbj5cbiAgICA8c3ZnPlxuICAgICAgPHRpdGxlPlxuICAgICAgICA8dGFibGU+PGNhcHRpb24+PC9jYXB0aW9uPjwvdGFibGU+XG4gICAgICA8L3RpdGxlPlxuICAgICAgPHN0eWxlPjxhIGlkPVwiPC9zdHlsZT48aW1nIHNyYz14IG9uZXJyb3I9YWxlcnQoKT5cIj48L2E+PC9zdHlsZT5cbiAgICA8L3N2Zz5cbiAgPC9jYXB0aW9uPlxuPC90YWJsZT4iLCJwaXBlbGluZXMiOlt7ImlkIjoiMGFkcXN1YWoiLCJuYW1lIjoiRG9tIFRyZWUiLCJwaXBlcyI6W3sibmFtZSI6IkRvbVB1cmlmeSIsImlkIjoiZXJsNXR6ZXMiLCJoaWRlIjp0cnVlLCJza2lwIjpmYWxzZSwib3B0cyI6eyJ2ZXJzaW9uIjoiMy4xLjAiLCJvcHRpb25zIjoie30ifX0seyJuYW1lIjoiRG9tUGFyc2VyIiwiaWQiOiJiNTRyd2RiNSIsImhpZGUiOmZhbHNlLCJza2lwIjpmYWxzZSwib3B0cyI6eyJ0eXBlIjoidGV4dC9odG1sIiwic2VsZWN0b3IiOiJib2R5Iiwib3V0cHV0IjoiaW5uZXJIVE1MIiwiYWRkRG9jdHlwZSI6dHJ1ZX19XX1dfQ== 
    
    
## BUMP ELEMENT 
![image](https://hackmd.io/_uploads/rkbOTjxveg.png)
CÁI  GÌ ĐANG XẢY RA Ở ĐÂY V  ? : 
    Cùng đọc docs nhé https://html.spec.whatwg.org/multipage/parsing.html#parsing-main-intable

Có vẻ là do<\/form> nên mới bug ở đây 
![image](https://hackmd.io/_uploads/rJurEhePxe.png)
Xóa start form thì vẫn ăn =)) vậy tức là do thằng cu <\/form> mẹ ròi 

Vi <\/form> la invalid tag sẽ fallback về foster parenting 
![image](https://hackmd.io/_uploads/HyETt6evxe.png)

## Cơ chế foster parenting 
Trong HTML parsing, foster parenting là một cơ chế đặc biệt được quy định trong HTML parsing algorithm để xử lý một số trường hợp không hợp lệ (misnested), cụ thể là khi bạn chèn các thẻ không hợp lệ vào giữa các thẻ như ```<table>, <tbody>, <tr>, v.v.```


Ví dụ trường hợp là tag h1 
![image](https://hackmd.io/_uploads/rJzOnplPle.png)
Thì sẽ được đẩy vào form , vì form không thể chứa **```<form>```** như ta đã biết nhưng còn ```**</form>**``` thì sao ? 
Khi nhảy ra ngoài form nó cũng không valid nên nó nhảy ra tới tag body và vì thế ôm luôn thằng div ?? 
![image](https://hackmd.io/_uploads/ByGP66eDlx.png)

Sau một hồi test thì có vẻ không phải như vậy.
Vậy nguyên nhân là do đâu mà BUMP hoạt động ? 

## Final : 
- Sau một hồi đọc docx thì mình cũng nhận ra điều sau : 
Ta thấy khi gặp <\/form> sẽ có những action sau, đặc biệt là 2. và 3. khi kết hợp lại có thể xóa đi một **form element pointer nhưng vẫn không xóa node đó khỏi stack**
![image](https://hackmd.io/_uploads/SkYD_kZwxl.png)
- Điều kiện số 3 sẽ kiểm tra có node trong scope hay không ? Thế nghĩa là sao ? Ta nhìn vào đoạn sau :
![image](https://hackmd.io/_uploads/Sy-PKJZDgl.png)
Hiểu đơn giản là : 
**Một phần tử được coi là "in scope" nếu nó nằm trên stack, và không bị "che mất" bởi các phần tử đặc biệt khác như table, select, template, etc.**


- Khi được foster parenting stack hiện là : 
[body , form , table ] với **table** là blocking tag nên khi trigger <\/form> sẽ trigger trường hợp thứ ba nhưng đồng thời set **form element về null** dẫn đến <\/form> cuối cùng không đóng form này lại được . và form vẫn nằm trên stack và nhận children  =))))
=> <\/form> đã bị chặn bởi tag table 

Tổng kết flow như sau : 
![image](https://hackmd.io/_uploads/HyY6jkZDlg.png)


Dựa trên điều đó ta có thể thay thế blocking scope tag và có cùng effect : 
![image](https://hackmd.io/_uploads/Hk43JgbDxe.png)
