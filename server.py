#!/usr/bin/env python
#based on https://github.com/stylesuxx/udp-hole-punching
"""
UNTESTED because I can't figure out how to get this script server hosted anywhere

1) user A finds out his private ip and port, then sends a json (string) as a udp data packet:
    {
      'registering-server': True,
      'user-name': <string>,
      'private-ip': <string>,  
      'private-port': <int>,
    }

2) User B finds out her provate IP and port,then sends a json (string) as a udp packet:



"""

from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
import json
import sys

PORT = 5160

class ServerProtocol(DatagramProtocol):
    def __init__(self):
        """Initialize with empy address list."""
        self.server_hosts = {}


    def validateData(self, dataString):
        """
        Take a datagram string.
        Checks whether all required keys are present.
        Returns json if good, None otherwise
        """
        jData = json.loads(dataString)
        ret = {}
        #required for all users
        requiredKeys = ['registering-server', 'user-name', 'private-ip', 'private-port']
        for key in requiredKeys:
            if key in jData:
                ret[key] = jData[key]
            else:
                return
        #required for users seeking to join a server
        if not jData['registering-server']:
            requiredKeys = ['server-name', 'server-password']
            for key in requiredKeys:
                if key in jData:
                    ret[key] = jData[key]
                else:
                    return
        return ret    


    def makeHandshakeJsonString(self, jData):
        ret = {}
        ret['public-address'] = jData['public-ip'] + ':' + str(jData['public-port'])
        ret['private-address'] = jData['private-ip'] + ':' + str(jData['private-port'])
        if 'server-password' in jData.keys():
            ret['server-password'] = jData['server-password']
        return json.dumps(ret)

    def datagramReceived(self, datagram, address):
        datagram = datagram.decode("utf-8")
        print("received " + datagram + " from " + address[0])

        #gather the user info
        jData = self.validateData(datagram)
        if jData == None:
            return
        jData['public-ip'] = address[0]
        jData['public-port'] = address[1]
        
        #register server if need be
        if jData['registering-server'] == True:
            #store the server by its user-name
            self.server_hosts[jData['user-name']] = jData
            print("servers updated: ")
            print(self.server_hosts)

        #otherwise, we're joining a server and a client- HOLE PUNCH!
        elif jData['registering-server'] == False:
            print("joining: " + jData['server-name'])
            if not jData['server-name'] in self.server_hosts.keys():
                print(jData['server-name'] + " not found")
                return
            serverJData = self.server_hosts[jData['server-name']]
            serverInfo = self.makeHandshakeJsonString(serverJData)
            clientInfo = self.makeHandshakeJsonString(jData)
            self.transport.write(serverInfo, jData['public-address'])
            self.transport.write(clientInfo, serverJData['public-address'])
            print("sent info to " + jData['server-name'] + " and " + jData['user-name'])
        

if __name__ == '__main__':
    reactor.listenUDP(PORT, ServerProtocol())
    reactor.run()




#listen on a port

#receive udp with user A data with registering-server==True
#store data indexed by user-name

#receive udp with user B data with registering-server==False
#send A and B packets containing each other's info






'''
For now, for redshift, just focus on:
    1) user A sends message to server registering itself, with requires-key as true
    2) user B sends message to server requesting user A
    3) server sends public and privates to A and B
    4) user A and user B send udp packages until a udp pack is received on both - user B sends key as data
    5) continue only if user A sees correct key
    5) user A and B store the address of the packets they received- these are the server/client addresses
    6) send heartbeats out every 15 seconds- just to keep NAT hole open




'''


'''
#users send the following data to server to register/join
datagram:
    {
      'registering-server': <bool>, #false if joining a server
      'host-name': <string> #only if joining a server
      'password': <string> #only if joining a server
      'user-name': <string>,
      'private-ip': <string>,  
      'private-port': <int>,
    }

'''