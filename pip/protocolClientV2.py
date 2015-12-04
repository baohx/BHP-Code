#!/usr/bin/python
# -*- coding: utf-8 -*-
import socket

class TCPFactory(object):
    def __init__(self, target_host, target_port, message):
        self.target_host = target_host
        self.target_port = target_port
        self.message = message
    def create_socket(self, para1 = socket.AF_INET, para2 = socket.SOCK_STREAM):
        client = socket.socket(para1, para2)
        return client
    def connect_send(self, client):
        client.connect((self.target_host, self.target_port))
        client.send(self.message)
        return client
    def receive(self, client):
        data = ""
        client.settimeout(2)
        try:
            data = client.recv(4096)
            return data
        except socket.timeout:
            return data

class UDPFactory(TCPFactory):
    def __init__(self, target_host, target_port, message):
        super(TCPFactory, self).__init__(target_host, target_port, message)
    def connect_send(self, client):
        client = self.create_socket(para2 = socket.SOCK_DGRAM)
        client.sendto(self.message, (self.target_host, self.target_port))
        return client
    def receive(self, client):
        client.settimeout(2)
        try:
            date, addr = client.recvfrom(4096)
            return data
        except socket.timeout:
            return "Time out. 2s"

def get_response(factory):
    client = factory.create_socket()
    client = factory.connect_send(client)
    return factory.receive(client)

def main():
    print("[+] TCP RESPONSE MESSAGE!")
    print(get_response(TCPFactory("yw.spdbfl.com.cn", 80, "GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")))
    print("[+] UDP RESPONSE MESSAGE!")
    print(get_response(UDPFactory("10.116.2.20", 80, "AAABBBCCC")))

if __name__ == "__main__":
    main()
