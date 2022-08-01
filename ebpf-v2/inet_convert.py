import socket
import struct

print(0x100007f)
print(socket.inet_ntoa(struct.pack('i', 0x100007f)))
print(socket.ntohs(16777343))