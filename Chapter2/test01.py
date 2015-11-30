import socket
import sys

target_host = "yw.spdbfl.com.cn"
target_port = 80

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((target_host, target_port))
client.send("GET / HTTP/1.1\r\nHost: "+ sys.argv[1] +"\r\n\r\n")

response = client.recv(int(sys.argv[2]))
response += client.recv(int(sys.argv[2]))
response += client.recv(int(sys.argv[2]))
response += client.recv(int(sys.argv[2]))
response += client.recv(int(sys.argv[2]))
response += client.recv(int(sys.argv[2]))
response += client.recv(int(sys.argv[2]))
response += client.recv(int(sys.argv[2]))


print response
