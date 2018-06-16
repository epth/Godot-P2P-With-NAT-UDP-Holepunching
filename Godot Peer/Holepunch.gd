extends Node

"""
todo: add X-scene support (eg a function that takes a bool (am i server) and confirmed peers
		and continues heartbeating and signallin etc.)
	: check whether addres smatches peer - if not, discard the received packet
	: add get list of servers from handshake
	: make local ip automatically retreived (with override)
	: at the moment, bcause yourself isnt in the peer list, packets sent to self are dismissed. do we want that?
"""

signal peer_dropped
signal connection_terminated 
signal packet_received
signal peer_confirmed
signal received_unreliable_message_from_peer
signal received_reliable_message_from_peer 
signal peer_confirmed_reliable_message_received
signal reliable_message_timeout
signal peer_check_timeout
signal peer_handshake_timeout
signal server_error


#keep "" to differentiate between it and other peers
const _SERVER_NAME = ""
var _user_name = null
var _i_am_server = null
var _peers = null
var _heartbeat_packets = null
var _socket = null
var _seconds_ticker = 0
#set false when we don't care what the server is sending us
var _listening_to_handshake = true 
var _local_address = null
var _handshake_address = null


func _process(delta):
	_seconds_ticker += delta
	if _seconds_ticker > 1:
		_seconds_ticker = 0
		#heartbeat packets
		if _heartbeat_packets:
			for packet in _heartbeat_packets.get_packets_array_copy():
				var packet_expired = packet.seconds_tick()
				if packet_expired:
					_heartbeat_packets.remove(packet.peer_name, packet.type)
					if packet.type == 'registering-server':
						quit_connection()
						return
					if packet.type == 'requesting-to-join-server':
						quit_connection()
						return
					if packet.type == 'local-global-inqury':
						_peers.remove(packet.peer_name)
						emit_signal('peer_handshake_timeout', packet.peer_name)
						return
					if packet.type == 'peer-check':
						_peers.remove(packet.peer_name)
						emit_signal('peer_check_timeout', packet.peer_name)
						return
					if packet.type == 'reliable-peer-message':
						emit_signal('reliable_message_timeout', packet.get_copy_of_json_data())
						return
					#default to quitting
					else:
						quit_connection()
					return
	
	#process messages
	if _socket:
		while _socket.get_available_packet_count() > 0:
			#extract and validate
			var packet = _socket.get_packet()
			var sender_address = [_socket.get_packet_ip(), _socket.get_packet_port()]
			var jData = _validate_incoming(packet, sender_address)
			if jData == null:
				return
			emit_signal('packet_received', jData.duplicate())
			
			#server errors should terminate the connection
			if jData['type'] == 'server-error':
				emit_signal('server_error', jData['message'])
				quit_connection()
				break
			
			#registration confirmation - only for server hosts
			elif jData['type'] == 'confirming-registration':
				_heartbeat_packets.reset_expiry(_SERVER_NAME, 'registering-server')
			
			#from server - peer info we can use to join P2P
			elif jData['type'] == 'providing-peer-handshake-info':
				#only matters if we asked to join - remove is forgiving
				_heartbeat_packets.remove(_SERVER_NAME, 'requesting-to-join-server')
				#send out test packets to local and global addresses if we haven't already
				var peer_name = jData['peer-name']
				if _peers.get_peer(peer_name) == null:
					var peer = Peer.new(self._user_name, peer_name, jData['global-address'],
									jData['local-address'], self._socket, self._heartbeat_packets)
					_peers.add(peer)
					peer.send_address_inquiry()
			
			#inquiry from peer - we want to mirror back the successful packet
			elif jData['type'] == 'local-global-inqury':
				#note we don't add this into heartbeat- we just bounce back whatever the
				#peer sends us. If it fails, they'll send again because it's in their heartbeat
				var address = [_socket.get_packet_ip(), _socket.get_packet_port()]
				#jData will get overwritten with the correct sender info
				var mirrored = Packet.new(self._user_name, jData['sender'], _socket, address,
										  'local-global-inquiry-response', jData)
				mirrored.send()
			
			#from peer - we have received the reflecion of the succesful inquiry
			elif jData['type'] == 'local-global-inquiry-response':
				var peer_name = jData['sender']
				_heartbeat_packets.remove(peer_name, 'local-global-inqury')
				#check we know who this is but that a pervious inquiry response 
				#hasn't already come through (we want the fastest one)
				var peer = _peers.get_peer(peer_name)
				if peer and not peer.is_confirmed():
					peer.confirm(jData['used-global'])
					emit_signal('peer_confirmed', peer.info())
					_heartbeat_packets.add(peer.make_heartbeat_packet('peer-check', {}, false, 15))
			
			#sent from peer to keep connection open and check if we're still here
			elif jData['type'] == 'peer-check':
				#send back a response
				var peer = _peers.get_peer(jData['sender'])
				if peer and peer.is_confirmed():
					peer.make_packet('peer-check-response', jData).send()
			
			#sent by peer in response to peer check
			elif jData['type'] == 'peer-check-response':
				_heartbeat_packets.reset_expiry(jData['sender'], 'peer-check')
			
			#unreliable message sent by peer
			elif jData['type'] == 'unreliable-peer-message':
				emit_signal('received_unreliable_message_from_peer', jData)
				
			#reliable message sent by peer
			elif jData['type'] == 'reliable-peer-message':
				var peer = _peers.get_peer(jData['sender'])
				if peer and peer.is_confirmed():
					if not peer.msg_history_contains(jData['message-id']):
						peer.add_id_to_msg_history(jData['message-id'])
						emit_signal('received_reliable-message_from_peer', jData)
					peer.make_packet('reliable-peer-message-response', jData).send()
			
			#sent by peer confirming they have received our reliable message
			elif jData['type'] == 'reliable-peer-message-response':
				var peer_name = jData['sender']
				var type = jData['type']
				var key = 'message-id'
				var value = jData['message-id']
				_heartbeat_packets.remove_contains_key_value(peer_name, type, key, value)
				emit_signal('peer_confirmed_reliable_message_received', jData)


func quit_connection():
	"""reset to an initial state with no peers and a null socket"""
	_user_name = null
	_peers = null
	_i_am_server = null
	_heartbeat_packets = null
	_socket = null
	_local_address = null
	_handshake_address = null
	emit_signal('connection_terminated')


func drop_connection_with_handshake_server():
	_listening_to_handshake = false


func drop_peer(peer_name):
	_heartbeat_packets.remove_peer(peer_name)
	var peer = _peers.get_peer(peer_name)
	_peers.remove(peer_name)
	if peer:
		emit_signal('peer_dropped', peer_name)


func _common_init(user_name, handshake_ip, handshake_port, local_ip, local_port):
	self._local_address = [local_ip, int(local_port)]
	self._handshake_address = [handshake_ip, int(handshake_port)]
	self._socket = PacketPeerUDP.new()
	self._heartbeat_packets = _HeartBeatPacketContainer.new()
	self._listening_to_handshake = true
	self._user_name = user_name
	self._peers = PeerContainer.new()
	if _socket.listen(local_port) != OK:
		quit_connection()
		emit_signal('server_error', 'invalid listener port')
		return false
	return true
	
func init_server(handshake_ip, handshake_port, local_ip, local_port, 
				 server_name, seconds_registration_valid=60, 
				 registration_refresh_rate=15):
	if not _common_init(server_name, handshake_ip, handshake_port, local_ip, local_port):
		return 
	self._i_am_server = true
	var data = {
		'type': 'registering-server',
		'local-address': self._local_address,
		'seconds-before-expiry': seconds_registration_valid
	}
	#packet will be sent immediately, and every 15 seconds
	var packet = HeartbeatPacket.new(self._user_name, _SERVER_NAME, _socket, self._handshake_address,
									 'registering-server', data, true, registration_refresh_rate)
	_heartbeat_packets.add(packet)
	
func init_client(handshake_ip, handshake_port, local_ip, local_port, user_name, server_name):
	if not _common_init(user_name, handshake_ip, handshake_port, local_ip, local_port):
		return
	self._i_am_server = false
	var data = {
		'type': 'requesting-to-join-server',
		'local-address': self._local_address,
		'server-name': server_name
	}
	#packet will be sent immediately
	var packet = HeartbeatPacket.new(self._user_name, _SERVER_NAME, _socket, self._handshake_address,
									 'requesting-to-join-server', data, true)
	_heartbeat_packets.add(packet)



func send_unreliable_message_to_peer(peer_name, message):
	var peer = _peers.get_peer(peer_name)
	if peer:
		peer.send_unreliable_message(message)

		
func send_reliable_message_to_peer(peer_name, message):
	var peer = _peers.get_peer(peer_name)
	if peer:
		peer.send_reliable_message(message)



func get_peers():
	if _peers:
		return _peers.get_confirmed()

func get_user_name():
	return _user_name

func i_am_server():
	return _i_am_server



func _validate_incoming(packet, sender_address):
	#fail if we haven't initialised
	if not _socket or not _peers:
		return null
	#extract json - fail on error
	var json_string = packet.get_string_from_utf8()
	var result = JSON.parse(json_string)
	if result.error != OK:
		return null
	var jData = result.result
	#okay if it was the handshake server and we care what it says
	if _listening_to_handshake and sender_address == _handshake_address:
		return jData
	var peer = _peers.get_peer(jData['sender'])
	#peer exists
	if peer:
		#address matches peer records
		if peer.local_address() == sender_address or peer.global_address() == sender_address:
			#we are the intended recipient
			if jData.has('intended-recipient') and jData['intended-recipient'] == _user_name:
				return jData
	return null


#############################################################
#############################################################
#                        HELPER CLASSES                     #
#############################################################


class Packet:
	"""
	Stores enough information about a packet to provide a simple send() function
	"""
	var peer_name #destination peer
	var _socket
	var address #[ip, port] as [<string>, <int>]
	var _data_as_json
	var type #e.g. 'registering-server'

	func _init(user_name, peer_name, _socket, address, type, data_as_json):
		"""adds the type to the data to be sent"""
		self.peer_name = peer_name
		self._socket = _socket
		self.address = address
		self._data_as_json = data_as_json
		self._data_as_json['type'] = type
		self._data_as_json['sender'] = user_name
		self._data_as_json['intended-recipient'] = peer_name
		self.type = type
	func get_copy_of_json_data():
		return _data_as_json.duplicate()
	func send():
		var bin_data = JSON.print(self._data_as_json).to_utf8()
		self._socket.set_dest_address(address[0], address[1])
		self._socket.put_packet(bin_data)

class HeartbeatPacket extends Packet:
	"""
	Call self.seconds_tick() every second, and call self.reset_expiry() when 
	a reply comes in. self.seconds_tick() returns true if the packet has expired.
	Stores a packet to be sent every self.seconds_between_resends seconds. 
	Every time it's sent, it will wait self.seconds_to_await_reply before
	giving up on receiving a reply. After self.attempts_before_expiration failures,
	the packet will expire. 
	"""
	var _resend_countdown
	var _await_reply_countdown
	var _attempts_countdown
	var _attempts_before_expiration
	var _seconds_to_await_reply
	var _seconds_between_resends #set -1 to never resend 
	var _awaiting_reply = false
	func _init(user_name, peer_name, _socket, address, type, data_as_json, 
				send_immediately=true, seconds_between_resends=-1,
				seconds_to_await_reply=1,
				attempts_before_expiration=3).(user_name, peer_name, 
												_socket, address, type, 
												data_as_json):
		self._seconds_between_resends = seconds_between_resends
		self._resend_countdown = seconds_between_resends
		self._seconds_to_await_reply = seconds_to_await_reply
		self._await_reply_countdown = seconds_to_await_reply
		self._attempts_before_expiration = attempts_before_expiration
		self._attempts_countdown = attempts_before_expiration
		if send_immediately:
			send()
			self._awaiting_reply = true
			
	func seconds_tick():
		"""
		Returns true if the packet has expired
		"""
		if _awaiting_reply:
			_await_reply_countdown -= 1
			if _await_reply_countdown <= 0:
				print("attempt failed")
				_attempts_countdown -= 1
				#if we're run out of attempts, we expire
				if _attempts_countdown <= 0:
					print("packet expired")
					return true
				#otherwise we retry sending the packet and waiting
				else:
					_await_reply_countdown = _seconds_to_await_reply
					send()
		#set _seconds_between_resends to -1 to avoid resends
		elif _seconds_between_resends > 0:
			_resend_countdown -= 1
			if _resend_countdown <= 0:
				#reset the expiration counters and send the packet
				print("sent")
				send()
				reset_expiry()
				_awaiting_reply = true
		#the packet hasn't expired
		return false

	func reset_expiry():
		"""called when a reply has come io this packet"""
		_awaiting_reply = false
		_attempts_countdown = _attempts_before_expiration
		_await_reply_countdown = _seconds_to_await_reply
		_resend_countdown = _seconds_between_resends

class _HeartBeatPacketContainer:
	"""
	Used to store and manage heartbeat packets.
	"""
	var _packets = []
	
	func add(packet, replace_same_peer_and_type = true):
		"""add a heartbeat packet - replaces existing with same peer_name and type."""
		if replace_same_peer_and_type:
			remove(packet.peer_name, packet.type)
		_packets.push_back(packet)
	
	func remove_peer(peer_name):
		"""removes all packets directed to a given peer"""
		for packet in _packets.duplicate():
			if packet.peer_name == peer_name:
				_packets.erase(packet)
	func remove(peer_name, type):
		"""remove all packets for a given peer and type"""
		for packet in _packets.duplicate():
			if packet.peer_name == peer_name and packet.type == type:
				_packets.erase(packet)
	func remove_contains_key_value(peer_name, type, key, value):
		"""remove all packets for a given peer and type that have a key with value"""
		for packet in _packets.duplicate():
			if packet.peer_name == peer_name and packet.type == type:
				var data = packet.get_copy_of_json_data()
				if data.has(key) and data[key] == value:
						_packets.erase(packet)
		
	func reset_expiry_for_peer(peer_name):
		"""reset all packets for a given peer"""
		for packet in _packets:
			if packet.peer_name == peer_name:
				packet.reset_expiry()
				
	func reset_expiry(peer_name, type):
		"""reset all packets for a given peer and type"""
		for packet in _packets:
			if packet.peer_name == peer_name and packet.type == type:
				packet.reset_expiry()
				
	func get_packets_array_copy():
		"""returns a copy of the underlying array"""
		return _packets.duplicate()
		
	func clear():
		_packets = []


class Peer:
	var _peer_name
	var _your_name
	var _local_address
	var _global_address
	var _ids_of_received_messaged = []
	var _use_global = null
	var _sent_message_id_counter = 0
	var _socket
	var _heartbeat_container
	func _init(your_name, peer_name, global_address, local_address, socket, heartbeat_container):
		self._your_name = your_name
		self._peer_name = peer_name
		self._global_address = [global_address[0], int(global_address[1])]
		self._local_address = [local_address[0], int(local_address[1])]
		self._socket = socket
		self._heartbeat_container = heartbeat_container
	func confirm(use_global):
		self._use_global = use_global
	func is_confirmed():
		return _use_global != null
	func global_address():
		return _global_address
	func local_address():
		return _local_address
	func address():
		if not is_confirmed():
			return null
		if _use_global:
			return global_address()
		else:
			return local_address()
	func name():
		return _peer_name
	func your_name():
		return _your_name
	func socket():
		return _socket
	func info():
		if is_confirmed():
			return {'name': name(), 'address': address()}
		else:
			return {'name': name(), 'local-address': local_address(), 
									'global-address': global_address()}
									
	func send_address_inquiry():
		#send global-address query
		self._use_global = true
		var g_data = {'used-global': true}
		_heartbeat_container.add(make_heartbeat_packet('local-global-inqury', g_data))
		#send local-address query
		self._use_global = false
		var l_data = {'used-global': false}
		_heartbeat_container.add(make_heartbeat_packet('local-global-inqury', l_data))
		#set back to unconfirmed
		self._use_global = null
		
		
	func send_reliable_message(message):
		if not is_confirmed():
			return null
		var data = {
			'message': message,
			'message-id': self._get_unique_msg_id()
		}
		var packet = make_heartbeat_packet('reliable-peer-message', data, true) 
		_heartbeat_container.add(packet, false)
		
	func send_unreliable_message(message):
		if not is_confirmed():
			return null
		make_packet('unreliable-peer-message', {'message': message}).send()

		
	func _get_unique_msg_id():
		var ret = _sent_message_id_counter
		_sent_message_id_counter += 1
		#handle overflow... if it gets to this point 
		#though, a LOT of messages must have been sent
		if _sent_message_id_counter < 0:
			_sent_message_id_counter = 0
		return ret
	func add_id_to_msg_history(msg_id):
		_ids_of_received_messaged.push_back(msg_id)
		if _ids_of_received_messaged.size() > 20:
			_ids_of_received_messaged = _ids_of_received_messaged[-10]
	func msg_history_contains(msg_id):
		return _ids_of_received_messaged.has(msg_id)
	
	func make_heartbeat_packet(type, data, send_immediately=true, seconds_between_resends=-1):
		return HeartbeatPacket.new(_your_name, name(), _socket, address(), type, data, 
									send_immediately, seconds_between_resends)
	
	func make_packet(type, data):
		return Packet.new(your_name(), name(), socket(), address(), type, data)

class PeerContainer:
	var _peers = {}
	func get_peer(peer_name):
		if _peers.has(peer_name):
			return _peers[peer_name]
		return null
	func get_confirmed():
		var ret = []
		for peer in _peers.values():
			if peer.is_confirmed():
				ret.push_back(peer.info())
		return ret
	func get_unconfirmed():
		var ret = []
		for peer in _peers.values():
			if not peer.is_confirmed():
				ret.push_back(peer.info())
		return ret
	func add(peer):
		_peers[peer.name()] = peer
	func remove(peer_name):
		if _peers.has(peer_name):
			_peers.erase(peer_name)
