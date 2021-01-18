# BambooFox CTF 2021 - The Vault

Given a webpage displaying a keypad `index.html`, javascript driver file `main.js` and webassembly compiled binary `wasm`, you are supposed to find the pin that unlocks the vault.

## Blackbox approach

Without dealing with the wasm binary at first, reading through `main.js` specifically between lines 18 and 25 there seems to be some environment validations and checks.
```javascript
var ENVIRONMENT_IS_WEB = false;
var ENVIRONMENT_IS_WORKER = false;
var ENVIRONMENT_IS_NODE = false;
var ENVIRONMENT_IS_SHELL = false;
ENVIRONMENT_IS_WEB = typeof window === 'object';
ENVIRONMENT_IS_WORKER = typeof importScripts === 'function';
ENVIRONMENT_IS_NODE = typeof process === 'object' && typeof process.versions === 'object' && typeof process.versions.node === 'string';
ENVIRONMENT_IS_SHELL = !ENVIRONMENT_IS_WEB && !ENVIRONMENT_IS_NODE && !ENVIRONMENT_IS_WORKER;
```

Which lead me to think, possibly the driver code `main.js` supports multiple environments, indeed running the code with `nodejs` yields the banner.

```
kaftejiman:~/rev/vault/upload
▶ node main.js
 WASM VAULT v0.1
```
which comes from:

```javascript
function banner() {
    console.log("%c WASM VAULT v0.1", "font-weight: bold; font-size: 50px;color: red; text-shadow: 3px 3px 0 rgb(217,31,38) , 6px 6px 0 rgb(226,91,14) , 9px 9px 0 rgb(245,221,8) , 12px 12px 0 rgb(5,148,68) , 15px 15px 0 rgb(2,135,206) , 18px 18px 0 rgb(4,77,145) , 21px 21px 0 rgb(42,21,113)")
}
```

knowing `_validate` is the bridge function to the checking routine in the wasm binary:
```javascript
var _validate = Module["_validate"] = function () {
    return (_validate = Module["_validate"] = Module["asm"]["n"]).apply(null, arguments)
};
```
for the sake of carrying purely a black box approach, we can simply try to bruteforce all possible combinations (supposed 4 characters long) by slightly modifying the `main.js` code, specifically:

* modifying banner function to make it call the checking routine
* modifying fail function to make it less verbose (simply null it)
* modifying get_password function to make it read pin from argv

```javascript
function banner() {
    console.log('trying: '+process.argv[2]);
    _validate();
}

function fail() {
}

function get_password() {
    const val = process.argv[2];
    const len = lengthBytesUTF8(val) + 1;
    const str = _malloc(len);
    stringToUTF8(val, str, len);
    return str
}

function win(flag) {
    console.log('found');
    console.log(`${UTF8ToString(flag)}`);
}
```

with some bash wrapper (albeit naive algorithm):
```bash
for i in `seq 040 177`
do
    for j in `seq 040 177`
    do
        for k in `seq 040 177`
        do
            for l in `seq 040 177`
            do
                    c1=$(printf "\\$(printf %o $i)\n")
                    c2=$(printf "\\$(printf %o $j)\n")
                    c3=$(printf "\\$(printf %o $k)\n")
                    c4=$(printf "\\$(printf %o $l)\n")
                    node main.js "${c1}${c2}${c3}${c4}"
            done
                
        done
            
    done
        
done
```

let it spin, after a while you get:
```
▶ ./xx.sh
.
.
.
.
trying: p/k0
trying: p0k0
trying: p1k0
trying: p2k0
trying: p3k0
found
flag{w45m_w4sm_wa5m_wasm}
```

## White box approach

From the `main.js` specifically `_evaluate()` calling `Module["asm"]["n"]` we can deduce `n()` is probably the checking routine in the wasm binary.

Using wasm-decompile from [wabt](https://github.com/WebAssembly/wabt)

```c++
▶ wasm-decompile main.wasm | grep -A28 'function n'
export function n() {
  var c:int;
  var a:{ a:long, b:long, c:long, d:short } = g_a - 32;
  g_a = a;
  var b:{ a:ubyte, b:ubyte, c:ubyte, d:ubyte } = a_d();
  a.d = d__WD_l4GoR[12]:ushort;
  a.c = d__WD_l4GoR[2]:long;
  a.b = d__WD_l4GoR[1]:long;
  a.a = d__WD_l4GoR[0]:long;
  if (f_h(b) != 4) goto B_b;
  if (b.a != 112) goto B_b;
  if (b.b != 51) goto B_b;
  if (b.c != 107) goto B_b;
  if (b.d != 48) goto B_b;
  var d:int = 22;
  var e:int = a;
  loop L_c {
    e[0]:byte = (b + (c & 3))[0]:ubyte ^ d;
    e = a + (c = c + 1);
    d = e[0]:ubyte;
    if (d) continue L_c;
  }
  a_c(a);
  goto B_a;
  label B_b:
  a_b();
  label B_a:
  g_a = a + 32;
}
```

with: 
* a_d() reads pin
* a_c() spits flag
* a_b() fail
* f_h() sort of checksum maybe?

deduced from:
```javascript
var asmLibraryArg = {
    'e': banner,
    'a': _emscripten_resize_heap,
    'b': fail,
    'd': get_password,
    'c': win
};
```

`var b:{ a:ubyte, b:ubyte, c:ubyte, d:ubyte } = a_d();`

b populated with pin: {a: 1st char, b:2nd char, c:3rd char, d:4th char}

actual pin check is carried here:
```
  if (b.a != 112) goto B_b;
  if (b.b != 51) goto B_b;
  if (b.c != 107) goto B_b;
  if (b.d != 48) goto B_b;
```
evaluate:
```
kaftejiman:RE/rev  master ✔                                                                              4d
▶ pypy3
Python 3.6.9 (2ad108f17bdb, Apr 07 2020, 02:59:05)
[PyPy 7.3.1 with GCC 7.3.1 20180303 (Red Hat 7.3.1-5)] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>>> chr(112)+chr(51)+chr(107)+chr(48)
'p3k0'
```
try it:

```
▶ node main.js p3k0
trying: p3k0
found
flag{w45m_w4sm_wa5m_wasm}
```

done.




