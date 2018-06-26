#!/usr/bin/env python
#based on: https://github.com/stylesuxx/udp-hole-punching
#great info here: http://www.brynosaurus.com/pub/net/p2pnat/

from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from twisted.internet import task
from hashlib import sha256
import json
import sys

SERVER_PORT = 5160

class ServerProtocol(DatagramProtocol):
    def __init__(self):
        """Initialize with empy server list."""
        self.serverHosts = {}
        print("Handshake server started.\nListening on port " + str(SERVER_PORT))

    def datagramReceived(self, datagram, address):
        """
        Handles incoming packets.
        """
        original_data = json.loads(datagram.decode('utf-8'))
        jData = self.validateData(original_data, address)
        if jData == None:
            return
        
        #send back a list of servers if that's what we're doing
        if jData['__type'] == 'requesting-server-list':
            reply = {
                'server-list' : list(self.serverHosts.keys()),
            }
            self.send('providing-server-list', jData['__sender-name'], jData['global-address'], reply, jData['password'])
            print("sent server list to: " + str(jData['global-address']))

        #register server if that's what we're doing
        if jData['__type'] == 'registering-server':
            if jData['__sender-name'] in self.serverHosts:
                existingAddress = self.serverHosts[jData['__sender-name']]['global-address']
                if jData['global-address'] != existingAddress:
                    self.sendError(jData, "server already exists")
                    return
            #store the server by its sender
            self.serverHosts[jData['__sender-name']] = {
                'seconds-before-expiry': jData['seconds-before-expiry'],
                'global-address': jData['global-address'],
                'local-address': jData['local-address'],
                'password': jData['password'],
                '__sender-name': jData['__sender-name']
            }
            print(jData['__sender-name'] + " added to server list")
            print("global adress: " + str(jData['global-address']))
            #send back confirmation
            self.send('confirming-registration', jData['__sender-name'], jData['global-address'], {}, jData['password'])

        #link a server and a nonserver peer
        elif jData['__type'] == 'requesting-to-join-server':
            #check server exists
            if not jData['server-name'] in self.serverHosts.keys():
                self.sendError(jData, jData['server-name'] + " not found")
                return
            #make handshake messages
            serverJData = self.serverHosts[jData['server-name']]
            sendToClient = self.makeHandshakeJson(serverJData)
            sendToServer = self.makeHandshakeJson(jData)
            self.send('providing-peer-handshake-info', serverJData['__sender-name'], serverJData['global-address'], 
                      sendToServer, serverJData['password'])
            self.send('providing-peer-handshake-info', jData['__sender-name'], jData['global-address'],
                      sendToClient, jData['password'])
            print("sent linking info to " + jData['server-name'] + " and " + jData['__sender-name'])
        
        #refrresh a server registration
        elif jData['__type'] == 'refreshing-server-registration':
            sender = jData['__sender-name']
            if sender in self.serverHosts:
                self.serverHosts[sender]['seconds-before-expiry'] = jData['seconds-before-expiry']
                self.send('confirming-registration-refresh', sender, jData['global-address'], {}, self.serverHosts[sender]['password'])
                print("registration refreshed for " + jData['__sender-name'])
            else:
                self.sendError(jData, "registration refresh failed: " + sender + " not found")


    def validateData(self, data, senderAddress):
        """
        Checks whether all required keys are present.
        Returns json if good, None otherwise
        """
        #mandatory keys for all types
        validData = {}
        validData['global-address'] = (senderAddress[0], senderAddress[1])
        requiredKeys = ['__sender-name', '__type', '__hash-string']
        for requiredKey in requiredKeys:
            if not requiredKey in data:
                self.sendError(data, "missing field: " + requiredKey)
                print(data)
                return None
            else:
                validData[requiredKey] = data[requiredKey]
        
        #check hash for authentication
        myHashResult = self.getHashOfDictionary(data['__sender-name'], data)
        senderHashResult = data['__hash-string']
        if myHashResult != senderHashResult:
            self.sendError(data, "authentication failure")
            return None

        #mandatory keys for specific type        
        requiredKeys = []
        if validData['__type'] == 'requesting-to-join-server':
            requiredKeys.extend(['server-name', 'local-address', 'password'])
        elif validData['__type'] == 'registering-server':
            requiredKeys.extend(['seconds-before-expiry', 'local-address', 'password'])
        elif validData['__type'] == 'requesting-server-list':
            requiredKeys.extend(['password'])
        elif validData['__type'] == 'refreshing-server-registration':
            requiredKeys.extend(['seconds-before-expiry'])
        for requiredKey in requiredKeys:
            if requiredKey in data:
                validData[requiredKey] = data[requiredKey]
            else:
                message = "missing info from packet data: " + requiredKey
                self.sendError(data, message)
                return
        return validData    


    def makeHandshakeJson(self, data):
        """returns a package for clients that want to join another client"""
        package = {}
        package['peer-name'] = data['__sender-name']
        package['global-address'] = data['global-address']
        package['local-address'] = data['local-address']
        return package

    def sendError(self, data, message):
        """sends a packet of type server-error"""
        if '__sender-name' in data and 'global-address' in data:
            hostName = data['__sender-name']
            errorPackage = {
                    'message': message
            }
            if 'password' in data:
                errorPackage['password'] = data['password']
            self.send('server-error', hostName, data['global-address'], errorPackage)
            print("sent error: " + message)



    def send(self, packetType, destName, destAddress, data, password=None):
        data['__type'] = packetType 
        data['__destination-name'] = destName 
        data['__destination-address'] = destAddress 
        if password:
            data['password'] = password
        elif not 'password' in data:
            if destName in self.serverHosts:
                data['password'] = self.serverHosts[destName]['password'] 
            else:
                print("unable to send message: no password")
                return
        data['__hash-string'] = self.getHashOfDictionary(destName, data)
        data.pop('password')
        self.transport.write(json.dumps(data).encode(), destAddress)


    def getHashOfDictionary(self, hostName, data):
        """
        data must have a password field, or hostName must be a registred server
        * Gets string keys, string values and sorts them independently,
        * Concatenates those arrays into strings
        * concatenates the values string to the end of the keys string
        * returns sha-256 hash of that string, in hex string format
        """
        copyForHashing = data.copy()
        if '__hash-string' in copyForHashing:
            copyForHashing.pop('__hash-string')
        if not 'password' in copyForHashing and hostName in self.serverHosts:
            copyForHashing['password'] = self.serverHosts[hostName]['password']
        keys = [key for key in copyForHashing.keys() if isinstance(key, str)]
        keys.sort()
        jstring = ''.join(keys)
        values = [value for value in copyForHashing.values() if isinstance(value, str)]
        values.sort()
        jstring += ''.join(values)
        return sha256(jstring.encode('utf-8')).hexdigest()

    def serverHostRefresh(self):
        serversToRemove = []
        for serverName, serverInfo in self.serverHosts.items():
            serverInfo['seconds-before-expiry'] -= 1
            if serverInfo['seconds-before-expiry'] <= 0:
                serversToRemove.append(serverName)
        for serverToRemove in serversToRemove:
            self.serverHosts.pop(serverToRemove)

if __name__ == '__main__':
    listener = ServerProtocol()
    reactor.listenUDP(SERVER_PORT, listener)
    task.LoopingCall(listener.serverHostRefresh).start(1.0)
    reactor.run()