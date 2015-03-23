'''
Created on Mar 2, 2015

@author: gcharan09
'''
import socket
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
            self.sock.listen(5)
        except KeyboardInterrupt:
            raise
        except socket.gaierror:
            print "Unable to bind to host:port kindly check"
        print "Socket created and server listening on :"+str(self.host)+":"+str(self.port)
    
    def __genKey(self):
        self.RSAKey=RSA.generate(2048,e=65537)
        return self.RSAKey
    
    def __exchangeKeys(self,clientsock):
        self.__genKey()
        self.clientsock=clientsock
        print "Connected to the client"+str(clientsock.getpeername())+"exchanging the public keys\n"
        self.clientsock.sendall(pickle.dumps(self.RSAKey.publickey(),None))
        print "sent the pubKey\n"
        buf = self.clientsock.recv(2048)
        print "received ClientKey\n"
        clientKey=pickle.loads(buf)
        with open("clientKey",'wb') as f:
            f.write(clientKey.exportKey())
        print "loaded key successfully\n"
        return clientKey
        
    def receiveData(self):
            while 1:
                try:
                    clientsock, clientaddr = self.sock.accept()
                    self.__exchangeKeys(clientsock)
                    key=open("clientKey",'r').read()
                    clientKey=RSA.importKey(key)
                    clientKey=PKCS1_OAEP.new(clientKey) 
#                     clientKey=self.__exchangeKeys(clientsock)
                    print "the Client Key is"
                    print "got connection from ", clientsock.getpeername()
                    while 1:
                        buf = clientsock.recv(4096)
                        if buf:
                            encmessage = b64decode(pickle.loads(buf))
                            print PKCS1_OAEP.new(self.RSAKey).decrypt(encmessage)
                        else:
                            print "client closed connection"
                            break
                    clientsock.close()
                except KeyboardInterrupt:
                    raise
                except:
                    continue
        
                finally:
                    clientsock.close()
                

if __name__ == '__main__':
    try:
        sockObj=pyserver()
        sockObj.receiveData()
    except KeyboardInterrupt:
            raise
    except Exception as e:
        print e
    
    