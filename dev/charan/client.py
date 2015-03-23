'''
Created on Mar 3, 2015

@author: gcharan09
'''

import pickle
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode 
import time

host = 'localhost'
port = 12345

class client:
    
    def __init__(self):
        
        self.host="localhost"
        self.port=12345
        
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            print "Socket Created Successfully"
        except socket.error:
            print "unable to create socket"
    
    def __genKey(self):
        self.RSAKey=RSA.generate(2048,e=65537)
        print "Key generation successful"
        return self.RSAKey
    
    def exchangeKeys(self):
        
        clientKey=self.__genKey()
        self.sock.connect((self.host,self.port))
        print "connected to server\n"
        serverReply=self.sock.recv(2048)
        print "received server Key\n"
        serverKey = pickle.loads(serverReply)
        with open("serverKey",'wb') as f:
            f.write(serverKey.exportKey())
        self.sock.sendall(pickle.dumps(self.RSAKey.publickey(), None))
        print "Key Exchange Successful\n"
    
    def sendData(self):
        
        self.exchangeKeys()
        key = open("serverKey", "r").read() 
        serverKey= RSA.importKey(key)
        serverKey = PKCS1_OAEP.new(serverKey) 
        while True:
            reply=raw_input("Enter the Data to be send to server \n Enter q to quit\n")
            if reply!='q':
                if(len(reply)>100):
                    for i in range(100,len(reply),100):
                        secretText = serverKey.encrypt(reply[i-100:i])
                        time.sleep(0.5)
                        self.sock.sendall(pickle.dumps(secretText.encode('base64')))
                    secretText=serverKey.encrypt(reply[(i):len(reply)])
                    time.sleep(0.5)
                    self.sock.sendall(pickle.dumps(secretText.encode('base64')))
                else:
                    secretText=serverKey.encrypt(reply)
                    self.sock.sendall(pickle.dumps(secretText.encode('base64')))
            else:
                print "closing the socket\n"
                self.sock.shutdown(1)
                self.sock.close()
                break


if __name__ == '__main__':
    clientObj=client()
    clientObj.sendData()