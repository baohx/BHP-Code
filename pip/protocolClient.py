#!/usr/bin/python
# -*- coding: utf-8 -*-
import socket

class TCPFactory:
    #def __init__(target_host, target_port, message):
    #    self.target_host = target_host
    #    self.target_port = target_port
    #    self.message = message
    @classmethod
    def create_socket(Class, para1 = socket.AF_INET, para2 = socket.SOCK_STREAM):
        client = socket.socket(para1, para2)
        return client
    @classmethod
    def connect_send(Class, client, target_host, target_port, message):
        client.connect((target_host, target_port))
        client.send(message)
        return client
    @classmethod
    def receive(Class, client):
        data = ""
        client.settimeout(2)
        try:
            data = client.recv(4096)
            return data
        except socket.timeout:
            return data

class UDPFactory(TCPFactory):
    #def __init__(target_host, target_port, message):
    #    self.target_host = target_host
    #    self.target_port = target_port
    #    self.message = message
    #@classmethod
    #def create_socket(Class):
    #    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #    return client
    @classmethod
    def connect_send(Class, client, target_host, target_port, message):
        client = TCPFactory.create_socket(para2 = socket.SOCK_DGRAM)
        client.sendto(message, (target_host, target_port))
        return client
    @classmethod
    def receive(Class, client):
        client.settimeout(2)
        try:
            date, addr = client.recvfrom(4096)
            return data
        except socket.timeout:
            return "Time out. 2s"

def get_response(factory, target_host, target_port, message):
    client = factory.create_socket()
    client = factory.connect_send(client, target_host, target_port, message)
    return factory.receive(client)

def main():
    print("[+] TCP RESPONSE MESSAGE!")
    print(get_response(TCPFactory, "yw.spdbfl.com.cn", 80, "GET / HTTP/1.1\r\nHost: google.com\r\n\r\n"))
    print("[+] UDP RESPONSE MESSAGE!")
    print(get_response(UDPFactory, "10.116.2.20", 80, "AAABBBCCC"))

if __name__ == "__main__":
    main()
