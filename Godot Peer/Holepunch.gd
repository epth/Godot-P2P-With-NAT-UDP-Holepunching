#Author: Daniel Dowsett
#Year: 2018
#Desription: A P2P backend for Godot games offering password
#authorisation for server hosts and reliable messaging. Takes care
#of managing connections, offering signals and functions to build apps 
#upon.
#NOTE: Make sure the relevant ports are open on the firewall
#and that Godot is not blocked on the firewall.

extends Node

#############################################################
#############################################################
#                           SIGNALS                         #
#############################################################
signal confirmed_as_client
signal confirmed_as_server
signal peer_joined
signal peer_dropped


signal packet_sent
signal packet_received
signal packet_blocked
signal packet_timeout
signal packet_expired

signal received_unreliable_message_from_peer
signal received_reliable_message_from_peer 
signal peer_confirmed_reliable_message_received
signal reliable_message_timeout

signal received_server_list
signal error
signal session_terminated 


#############################################################
#############################################################
#                        CLASS VARIABLS                     #
#############################################################
const secs_between_peer_checks = 15
const secs_reg_valid = 60 
const secs_between_reg_refresh = 15
const secs_to_await_reply = 1
const attempts_before_expiration = 5
#peers can't have same name as handshake server
const _HS_SERVER_NAME = "_HANDSHAKE_SERVER"

var _user_name = null
var _i_am_server = null
var _server_name = null
var _peers = null
var _packets = PacketContainer.new()
var _socket = PacketPeerUDP.new()
var _local_address = null
var _global_address = null
var _server_address = null
var _handshake_server = null
var _password = null
var _seconds_ticker = 0




#############################################################
#############################################################
#          PROCESS HEARTBEATS AND INCOMING                  #
#############################################################

func _process(delta):
	_seconds_ticker += delta
	if _seconds_ticker > 1:
		_seconds_ticker = 0
		#copy because we remove packets from _packets within loop
		for packet in _packets.get_packets_array_copy():
			var packet_expired = packet.seconds_tick()
			if packet_expired:
				_packets.remove_all_of_peer_and_type(packet.dest_name, packet.type)
				if packet.type == 'requesting-server-list':
					emit_signal('error', 'failed to get list from server')
					return
				if packet.type == 'registering-server':
					emit_signal('error', 'unable to communicate with handshake server')
					quit_connection()
					return
				if packet.type == 'refreshing-server-registration':
					emit_signal('error', 'unable to communicate with handshake server')
					quit_connection()
					return
				if packet.type == 'requesting-to-join-server':
					emit_signal('error', 'unable to communicate with handshake server')
					quit_connection()
					return
				if packet.type == 'address-inquiry':
					emit_signal('error', 'peer connection with ' + packet.dest_name + ' failed.')
					if _i_am_server:
						drop_peer(packet.dest_name)
					else:
						quit_connection()
					return
				if packet.type == 'peer-check':
					if _i_am_server:
						emit_signal("error", "lost connection with client peer: " 
												+ packet.dest_name)
						drop_peer(packet.dest_name)
					elif packet.dest_name == _server_name:
						emit_signal("error", "lost connection with server peer")
						quit_connection()
					else:
						var peer = _peers.get(packet.dest_name)
						if peer:
							peer.add_outgoing_reliable_periodic('peer-check', {}, secs_between_peer_checks)
					return
				if packet.type == 'reliable-peer-message':
					emit_signal('reliable_message_timeout', packet.get_copy_of_json_data())
					return
				else:
					#we don't care whether this packet made it
					#includes: 
						# reliable-peer-message-response
						# peer-check-response
					#because if they fail, the peer will resend their original request anyway
					return

	while _socket.get_available_packet_count() > 0:
		var packet = _get_incoming_packet()
		if packet == null:
			#note: you'll get a block on the second address inquiry response received
			#because the peer will have confirmed as the first address- so there's
			#an address mismatch. 
			#
			#You'll also get a block if you're acting handshake server and peers send
			#the handshake any packets (unless they're handled in _get_incoming_packet directly)
			#These include heartbeat packets and drop-me packets.
			emit_signal('packet_blocked', [_socket.get_packet_ip(), _socket.get_packet_port()])
			return
			
		var packet_data =  packet.get_copy_of_json_data()
		
		emit_signal('packet_received', packet_data.duplicate())
		
		if packet.type == 'server-error':
			emit_signal('error', packet_data['message'])
			quit_connection()
			break
		
		elif packet.type == 'providing-server-list':
			if not _packets.contains_peer_and_type(_handshake_server.name(), 
													'requesting-server-list'):
				return
			_packets.remove_all_of_type('requesting-server-list')
			emit_signal('received_server_list', packet.sender_address.duplicate(),
												packet_data['servers'])
		
		elif packet.type == 'confirming-registration':
			if not _packets.contains_peer_and_type(_handshake_server.name(), 
													'registering-server'):
				return
			_packets.remove_all_of_type('registering-server')
			var data = {
				'seconds-before-expiry': secs_reg_valid
			}
			_handshake_server.add_outgoing_reliable_periodic('refreshing-server-registration', 
															data, secs_between_reg_refresh)
			_server_address =  packet.dest_address
			_global_address = packet.dest_address
			emit_signal('confirmed_as_server', packet.sender_address.duplicate())
		
		elif packet.type == 'confirming-registration-refresh':
			_packets.reset_expiry_for_all_of_type('refreshing-server-registration')
		
		
		#server is handshake server (on LAN)
		elif packet.type == 'requesting-to-join-server':
			#create peer - don't add! we just need it to send
			var peer = Peer.new(self, packet.sender_name, packet_data['password'],
								_socket, _packets, packet.sender_address)
			peer.send_to_as_handshake = true
			var my_info = {
				'peer-name': _user_name,
				'local-address': _local_address,
				'global-address': packet.dest_address
			}
			peer.add_outgoing_unreliable_now('providing-peer-handshake-info',
											 my_info, packet.sender_address)
			
			var their_info = {
				'peer-name': packet.sender_name,
				'local-address': packet_data['local-address'],
				'global-address': packet.sender_address
			}
			_handle_handshake_info(their_info)
			
			
		#server is handshake server (LAN)
		elif packet.type == 'requesting-server-list':
			#create peer - don't add! we just need it to send
			var peer = Peer.new(self, packet.sender_name, packet_data['password'],
								_socket, _packets, packet.sender_address)
			peer.send_to_as_handshake = true
			var data = {'servers': 
							[{
								'name': _user_name, 
								'password-required': _password != _user_name
							}]
						}
			peer.add_outgoing_unreliable_now('providing-server-list',
											 data, packet.sender_address)
			
		
		elif packet.type == 'providing-peer-handshake-info':
			if not _i_am_server:
				if not _packets.contains_peer_and_type(_handshake_server.name(), 
														'requesting-to-join-server'):
					return
			_handle_handshake_info(packet_data)
			

		elif packet.type == 'address-inquiry':
			var peer_name = packet.sender_name
			var address = packet.sender_address
			var peer = _peers.get(peer_name)
			if peer == null:
				emit_signal('error', 'address inquiry from unknown peer')
				return
			peer.add_outgoing_unreliable_now('address-inquiry-response', packet_data, address)


		elif packet.type == 'address-inquiry-response':
			_packets.remove_all_of_peer_and_type(packet.sender_name, 'address-inquiry')
			var peer = _peers.get(packet.sender_name)
			if peer and not peer.is_confirmed():
				peer.confirm(packet_data['used-global'])
				peer.add_outgoing_reliable_periodic('peer-check', {}, secs_between_peer_checks)
				if _i_am_server:
					emit_signal('peer_joined', peer.name())
					peer.send_peer_list_update('add', _peers.get_confirmed())
					for existing_peer in _peers.get_confirmed():
						if existing_peer.name() != peer.name():
							existing_peer.send_peer_list_update('add', [peer])
				else:
					_server_address =  peer.address()
					_global_address = packet.dest_address
					emit_signal('confirmed_as_client', 
								get_server_address().duplicate())
					emit_signal('peer_joined', peer.name())
		
		
		elif packet.type == 'peer-check':
			var peer = _peers.get(packet.sender_name)
			if peer and peer.is_confirmed():
				#If this fails, they'll send again because THEY care about it
				peer.add_outgoing_unreliable_now('peer-check-response', packet_data)
		
		elif packet.type == 'peer-check-response':
			_packets.reset_expiry_for_all_of_peer_and_type(packet.sender_name, 'peer-check')
		
		elif packet.type == 'unreliable-peer-message':
			emit_signal('received_unreliable_message_from_peer', packet.get_copy_of_json_data())

			
		elif packet.type == 'reliable-peer-message':

			var peer = _peers.get(packet.sender_name)
			if not peer.msg_history_contains(packet_data['message-id']):
				peer.add_id_to_msg_history(packet_data['message-id'])
				emit_signal('received_reliable_message_from_peer', packet.get_copy_of_json_data())
			peer.add_outgoing_unreliable_now('reliable-peer-message-response', packet_data)

		
		elif packet.type == 'reliable-peer-message-response':
			var type = 'reliable-peer-message'
			var key = 'message-id'
			var value = packet_data['message-id']
			_packets.remove_all_of_peer_and_type_with_key_value(packet.sender_name, type, 
																 key, value)
			emit_signal('peer_confirmed_reliable_message_received', packet.get_copy_of_json_data())
			
		elif packet.type == 'update-peer-list':
			_peers.get(packet.sender_name).add_outgoing_unreliable_now('update-peer-list-response', {})
			_update_peer_list(packet_data['action'], packet_data['peer-infos'])
			

		elif packet.type == 'update-peer-list-response':
			_packets.remove_all_of_peer_and_type(packet.sender_name, 'update-peer-list')

		elif packet.type == 'drop-me':
			if packet.sender_name == get_server_name():
				emit_signal("error", "server peer disconnected")
				quit_connection()
			elif _i_am_server:
				drop_peer(packet_data['name'])

#############################################################
#############################################################
#                EXTERNALLY VISIBLE METHODS                 #
#############################################################

func get_user_name():
	return _user_name

func get_password():
	return _password
	
func get_server_name():
	return _server_name
	
func get_peers():
	if _peers != null:
		return _peers.get_confirmed_names()
	else:
		return []

func i_am_server():
	return _i_am_server

func get_server_address():
	if _server_address != null:
		return _server_address.duplicate()
	else:
		return null

func get_handshake_server_address():
	if _handshake_server != null:
		return _handshake_server.address().duplicate()
	else:
		return null

func get_peer_info(peer_name):
	if _peers == null:
		return null
	var peer = _peers.get(peer_name)
	if peer == null:
		return null
	return peer.info().duplicate()


func send_message_to_peer(peer_name, message, reliable=false):
	if _peers == null:
		emit_signal('error', 'unitialised')
		return
	if peer_name == null: #broadcast
		for peer in _peers.get_confirmed():
			peer.send_message(message, true, reliable)
	else:
		if _peers.get(peer_name) == null:
			emit_signal('error', 'no peer named "' + peer_name + '"')
			return
		_peers.get(peer_name).send_message(message, false, reliable)

func request_server_list(handshake_address):
	if not _handshake_server or _handshake_server.address() != handshake_address:
		_packets.remove_all_of_peer(_HS_SERVER_NAME)
		_handshake_server = Peer.new(self, _HS_SERVER_NAME, _generate_random_alpha_numeric(10),
									  _socket, _packets, handshake_address)
	var data = {'password': _handshake_server.password()}
	_handshake_server.add_outgoing_reliable_now('requesting-server-list', data)

func quit_connection():
	
	if _handshake_server != null:
		var data = {'name': _user_name}
		_handshake_server.add_outgoing_unreliable_now('drop-me', data)
	if _peers:
		for peer in _peers.get_confirmed():
			var data = {'name': _user_name}
			peer.add_outgoing_unreliable_now('drop-me', data)
	
	var ret_info = {
		"i_am_server" : i_am_server(),
		"server_address": get_server_address(),
		"user_name" : get_user_name(),
		"my_address": _global_address
	}
	_user_name = null
	_peers = null
	_i_am_server = null
	_server_name = null
	_handshake_server = null
	_local_address = null
	_password = null
	_packets = PacketContainer.new()
	_socket = PacketPeerUDP.new()
	emit_signal('session_terminated')
	return ret_info

func drop_connection_with_handshake_server():
	_packets.remove_all_of_peer(_HS_SERVER_NAME)
	if _handshake_server != null:
		var data = {'name': _user_name}
		_handshake_server.add_outgoing_unreliable_now('drop-me', data)
	_handshake_server = null

func is_connected():
	return _user_name != null


func drop_peer(peer_name):
	if _i_am_server:
		var peer = _peers.get(peer_name)
		if peer:
			_packets.remove_all_of_peer(peer_name)
			_peers.remove(peer_name)
			if peer.is_confirmed():
				emit_signal('peer_dropped', peer_name)
				for existing_peer in _peers.get_confirmed():
					existing_peer.send_peer_list_update('remove', [peer])
		else:
			emit_signal('error', 'no peer named ' + peer_name)
	else:
		emit_signal('error', 'only server can drop peers')

func init_server(handshake_address, local_address, server_name, password=null):
	if not _common_init(server_name, handshake_address, local_address):
		return 
	self._i_am_server = true
	self._server_name = server_name
	self._password = password
	if self._password == "" or self._password == null:
		_password = server_name
		
	if _i_am_handshake_server():
		emit_signal('confirmed_as_server', _local_address.duplicate())
		return
	
	var data = {
		'local-address': self._local_address,
		'seconds-before-expiry': self.secs_reg_valid,
		'password': _handshake_server.password(),
		'password-required' : self._password != server_name
	}
	_handshake_server.add_outgoing_reliable_now('registering-server', data)


	
func init_client(handshake_address, local_address, user_name, server_name, password=null):
	if not _common_init(user_name, handshake_address, local_address):
		return
	self._i_am_server = false
	self._server_name = server_name
	self._password = password
	if self._password == "" or self._password == null:
		_password = server_name
	var data = {
		'local-address': self._local_address,
		'server-name': server_name,
		'password': _handshake_server.password()
	}
	_handshake_server.add_outgoing_reliable_now('requesting-to-join-server', data)



#############################################################
#############################################################
#                        HELPER METHODS                     #
#############################################################

func _common_init(user_name, handshake_address, local_address):
	if user_name == _HS_SERVER_NAME or user_name == "":
		emit_signal('error', 'invalid user name: "' + user_name + '"')
		return false
	_user_name = user_name
	_local_address = [local_address[0], int(local_address[1])]
	_socket = PacketPeerUDP.new()
	_packets = PacketContainer.new()
	_peers = PeerContainer.new()
	handshake_address = [handshake_address[0], int(handshake_address[1])]
	_handshake_server = Peer.new(self, _HS_SERVER_NAME, _generate_random_alpha_numeric(10),
									  _socket, _packets, handshake_address)
	if _socket.listen(_local_address[1]) != OK:
		emit_signal('error', 'invalid listener port')
		quit_connection()
		return false
	return true


func _addresses_are_equal(lhs, rhs):
	return str(lhs[0]) == str(rhs[0]) and int(lhs[1]) == int(rhs[1])

func _update_peer_list(action, peer_infos):
	if _i_am_server:
		print('peer list should not be updated using _update_peer_list from server')
		return
		
	if action == 'add':
		for peer_name in peer_infos.keys():
			if peer_name ==_user_name or _peers.get(peer_name) != null:
				continue
			var peer_info = peer_infos[peer_name]
			var peer = Peer.new(self, peer_name, _password, _socket, _packets,
							peer_info['global-address'], peer_info['local-address'])
			peer.confirm(peer_info['use-global'])
			_peers.add(peer)
			peer.add_outgoing_reliable_periodic('peer-check', {}, secs_between_peer_checks)
			emit_signal('peer_joined', peer_name)
	elif action == 'remove':
		for peer_name in peer_infos.keys():
			_packets.remove_all_of_peer(peer_name)
			_peers.remove(peer_name)
			emit_signal('peer_dropped', peer_name)
	
	
func _generate_random_alpha_numeric(length):
	var allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	randomize()
	var random_string = ""
	for i in range(0, length):
		random_string += allowed_chars[randi() % allowed_chars.length()]
	return random_string


func _get_incoming_packet():
	var bytes = _socket.get_packet()
	var sender_address = [_socket.get_packet_ip(), _socket.get_packet_port()]
	
	var json_string = bytes.get_string_from_utf8()
	var result = JSON.parse(json_string)
	if result.error != OK:
		return null
	
	var jdata = result.result
	if not jdata.has('__type'):
		return null
	if not jdata.has('__destination-address'):
		return null
	if not jdata.has('__destination-name'):
		return null
	if not jdata.has('__hash-string'):
		return null
	if not jdata.has('__sender-name'):
		return null
	
	var i_am_handshake_server = _i_am_handshake_server()
	
	#either came from a handshake server or thinks we're a handshake server
	if jdata['__sender-name'] == null:
		if _addresses_are_equal(sender_address, _handshake_server.address()):
			jdata['__sender-name'] = _HS_SERVER_NAME
			jdata['__destination-name'] = _user_name
		elif i_am_handshake_server:
			#"" so it plays well for user on signal packet_received
			#(ie for string cocnatenation)
			jdata['__sender-name'] = "" 
			jdata['__destination-name'] = _HS_SERVER_NAME
		else:
			return null
	
	if not (jdata['__destination-name'] == _user_name
			or i_am_handshake_server and jdata['__destination-name'] 
											== _HS_SERVER_NAME):
			return null
	
	#Note: the hash is not checked for these packets
	if (jdata['__type'] == 'requesting-to-join-server' 
		or jdata['__type'] == 'requesting-server-list'):
		if not i_am_handshake_server:
			return null
		var is_outgoing = false
		return HPacket.new(self, jdata['__sender-name'], _user_name, _socket, 
							sender_address, jdata['__destination-address'], 
							jdata['__type'], jdata, is_outgoing)
	
	var peer
	if _peers and _peers.get(jdata['__sender-name']):
		peer = _peers.get(jdata['__sender-name'])
	elif _handshake_server:
		peer = _handshake_server
	if peer:
		return peer.make_incoming_packet(jdata, sender_address)
	else:
		return null


func _i_am_handshake_server():
	return (_handshake_server and _local_address
		and _addresses_are_equal(_local_address, _handshake_server.address()))

func _handle_handshake_info(info):
	#remove ignores if there are none matching
	_packets.remove_all_of_type('requesting-to-join-server')
	var peer_name = info['peer-name']

	var existing_peer = _peers.get(peer_name)
	
	if existing_peer and not existing_peer.is_confirmed():
		return
		
	var same_address = false
	if existing_peer:
		same_address = (_addresses_are_equal(existing_peer.address(), 
											info['global-address']) 
					    or _addresses_are_equal(existing_peer.address(), 
												info['local-address']))
	if peer_name == _user_name or (existing_peer and not same_address):
		emit_signal('error', 'attempted connection with invalid peer name: "' 
					+ peer_name + '"')
		if not _i_am_server:
			quit_connection()
	else:
		var peer = Peer.new(self, peer_name, _password, 
							self._socket, self._packets,
							info['global-address'], info['local-address'])
		_peers.add(peer)
		peer.send_address_inquiry()
			
			
#############################################################
#############################################################
#                        PACKET CLASSES                     #
#       use peers - NOT the Packet                          #
#############################################################


class HPacket:
	
	var sender_name
	var dest_name
	var type
	#for outgoing, this will be null
	var sender_address
	var dest_address
	var _holepunch_ref 
	var _outgoing
	var _socket
	var _data_as_json
	var _repeat_after_secs
	var _repeat_countdown
	var _await_reply_countdown
	var _attempts_countdown
	var _awaiting_reply = false
	var _sent_once_already = false
	var _resend_on_fail
	
	#if send_immediately=false and repeat_after_secs == null the packet will stay 
	#in memory, never sending
	func _init(holepunch_ref, sender_name, dest_name, _socket, sender_address, dest_address, 
				type, data_as_json, outgoing=true,resend_on_fail=true, send_immediately=true, 
				repeat_after_secs=null):
		self._holepunch_ref = holepunch_ref
		self._resend_on_fail = resend_on_fail
		self.sender_name = sender_name
		self.dest_name = dest_name
		self.type = type
		self._outgoing = outgoing
		self.sender_address = sender_address
		self.dest_address = dest_address
		self._socket = _socket
		self._data_as_json = data_as_json
		self._repeat_countdown = repeat_after_secs
		self._repeat_after_secs = repeat_after_secs
		self._await_reply_countdown = secs_to_await_reply
		self._attempts_countdown = attempts_before_expiration
		if self._outgoing and send_immediately:
			send()
			
			
	func get_copy_of_json_data():
		return _data_as_json.duplicate()
	
	func send():
		if self._outgoing:
			var bin_data = JSON.print(self._data_as_json).to_utf8()
			self._socket.set_dest_address(dest_address[0], dest_address[1])
			self._socket.put_packet(bin_data)
			self._awaiting_reply = true
			self._sent_once_already = true
			self._holepunch_ref.emit_signal('packet_sent', get_copy_of_json_data())
		else:
			print('attempted to send incoming packet.')
			
	func seconds_tick():
				
		#Returns true if the packet has expired
		if _awaiting_reply:
			_await_reply_countdown -= 1
			if _await_reply_countdown <= 0:
				
				print("no reply for: " + type)
				#we still wait because although we don't want to send on fail, 
				#we might still like to wait for reply in case one does come back
				if _resend_on_fail:
					_holepunch_ref.emit_signal('packet_timeout', 
												get_copy_of_json_data(), 
												_attempts_countdown > 0)
				else:
					return true
				_attempts_countdown -= 1
				if _attempts_countdown > 0:
					_await_reply_countdown = secs_to_await_reply
					send()
				else:
					_holepunch_ref.emit_signal('packet_expired', get_copy_of_json_data())
					return true
					
		elif _repeat_after_secs:
			_repeat_countdown -= 1
			if _repeat_countdown <= 0:
				reset_expiry()
				send()
		return false

	func reset_expiry():
		_awaiting_reply = false
		_attempts_countdown = attempts_before_expiration
		_await_reply_countdown = secs_to_await_reply
		_repeat_countdown = _repeat_after_secs

class PacketContainer:
	var _packets = []
	
	func add(packet, replace_same_peer_and_type = true):
		if replace_same_peer_and_type:
			remove_all_of_peer_and_type(packet.dest_name, packet.type)
		_packets.push_back(packet)
	
	func contains_type(type):
		for packet in _packets:
			if packet.type == type:
				return true
		return false
		
	func contains_peer_and_type(peer_name, type):
		for packet in _packets:
			if packet.dest_name == peer_name and packet.type == type:
				return true
		return false
		
	func contains_peer_and_type_with_key_value(peer_name, type, key, value):
		for packet in _packets.duplicate():
			if packet.dest_name == peer_name:
				if packet.type == type:
					var data = packet.get_copy_of_json_data()
					if data.has(key) and data[key] == value:
							return true
		return false
		
	func remove_all_of_peer(peer_name):
		for packet in _packets.duplicate():
			if packet.dest_name == peer_name:
				_packets.erase(packet)
	
	func remove_all_of_type(type):
		for packet in _packets.duplicate():
			if packet.type == type:
				_packets.erase(packet)
	
	func remove_all_of_peer_and_type(peer_name, type):
		"""remove all packets that match peer AND type"""
		for packet in _packets.duplicate():
			if packet.dest_name == peer_name and packet.type == type:
				_packets.erase(packet)
	
	func remove_all_of_peer_and_type_with_key_value(peer_name, type, key, value):
		"""remove all packets that match peer AND type AND that have a key with value"""
		for packet in _packets.duplicate():
			if packet.dest_name == peer_name:
				if packet.type == type:
					var data = packet.get_copy_of_json_data()
					if data.has(key) and data[key] == value:
							_packets.erase(packet)
			
	func reset_expiry_for_all_of_peer(peer_name):
		for packet in _packets:
			if packet.dest_name == peer_name:
				packet.reset_expiry()
				
	func reset_expiry_for_all_of_type(type):
		for packet in _packets.duplicate():
			if packet.type == type:
				packet.reset_expiry()
	
	func reset_expiry_for_all_of_peer_and_type(peer_name, type):
		"""reset all packets that match peer AND type"""
		for packet in _packets:
			if packet.dest_name == peer_name and packet.type == type:
				packet.reset_expiry()
				
	func get_packets_array_copy():
		return _packets.duplicate()








#############################################################
#############################################################
#                        PEER CLASSES                       #
#############################################################
#This has to come after the packet classes or reference errors materialise

class Peer:
	var send_to_as_handshake = false
	var _peer_name = null
	var _holepunch_ref = null
	var _local_address = null
	var _global_address = null
	var _password = null
	var _ids_of_received_messaged = []
	var _use_global = 'undecided'
	var _sent_message_id_counter = 0
	var _socket = null
	var _packets = null
	
	func _init(holepunch_ref, peer_name, password, socket, packet_container, 
				global_address, local_address=null):
		self._holepunch_ref = holepunch_ref
		self._peer_name = peer_name
		self._password = password
		self._socket = socket
		self._packets = packet_container
		self._global_address = [global_address[0], int(global_address[1])]
		if local_address != null:
			self._local_address = [local_address[0], int(local_address[1])]
		else:
			confirm(true)
	
	func name():
		return _peer_name
	func your_name():
		return self._holepunch_ref.get_user_name()
	func password():
		return _password
	func socket():
		return _socket
	
	func info():
		if is_confirmed():
			return {'name': name(), 'address': address()}
		else:
			return {'name': name(), 'local-address': local_address(), 
									'global-address': global_address()}
	
	func confirm(use_global):
		self._use_global = use_global
	func is_confirmed():
		return typeof(_use_global) == TYPE_BOOL
	
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
	
	func send_address_inquiry():
		var repeat = null
		var send_now = true
		var resend_on_fail = true
		var g_data = {'used-global': true}
		add_outgoing_packet('address-inquiry', g_data, send_now, repeat, resend_on_fail, 
							global_address())
		var l_data = {'used-global': false}
		var replace = false
		add_outgoing_packet('address-inquiry', l_data, send_now, repeat, resend_on_fail,
							local_address(), replace)

		
	func send_message(message, is_broadcast, is_reliable):
		var data = {'is-broadcast': is_broadcast}
		data['from'] = _holepunch_ref.get_user_name()
		data['to'] = name()
		data['message'] = message
		if is_reliable:
			data['message-id'] = self._get_unique_msg_id()
			add_outgoing_reliable_now('reliable-peer-message', data, null)
		else:
			add_outgoing_unreliable_now('unreliable-peer-message', data, null)


	func add_id_to_msg_history(msg_id):
		_ids_of_received_messaged.push_back(msg_id)
		if _ids_of_received_messaged.size() > 50:
			#there's actually no better way to do this yet... would prefer [-25:]
			var new_array = []
			for i in range(25, _ids_of_received_messaged.size()):
				new_array.push_back(_ids_of_received_messaged[i])
			_ids_of_received_messaged = new_array
	
	func msg_history_contains(msg_id):
		return _ids_of_received_messaged.has(msg_id)
	
	func add_outgoing_reliable_now(type, data, custom_address=null):
		add_outgoing_packet(type, data, true, null, true, custom_address)
	
	func add_outgoing_unreliable_now(type, data, custom_address=null):
		add_outgoing_packet(type, data, true, null, false, custom_address)
		
	func add_outgoing_reliable_periodic(type, data, period, custom_address=null):
		add_outgoing_packet(type, data, false, period, true, custom_address)
	
	func add_outgoing_packet(type, data, send_now=true, repeat=null, resend_on_fail=true,
							  custom_address=null, replace_same_peer_and_type=false):
		data = data.duplicate()
		var address = custom_address
		if address == null:
			address = address()
		var outgoing = true
		data = _add_security_outgoing(type, data, address)
		var your_name = your_name()
		if send_to_as_handshake:
			your_name = null
		var packet = HPacket.new(_holepunch_ref, your_name, name(), socket(), null, address, type, 
								data, outgoing, resend_on_fail, send_now, repeat)
		_packets.add(packet, replace_same_peer_and_type)
		
		
	func make_incoming_packet(jdata, sender_address):
		if is_confirmed() and sender_address != address():
			return null
		elif sender_address != local_address() and sender_address != global_address():
			return null
		
		#check hashes match
		var sender_hash = jdata['__hash-string']
		jdata.erase('__hash-string')
		var jdata_copy = jdata.duplicate()
		jdata_copy['password'] = password()
		if jdata_copy['__sender-name'] == _HS_SERVER_NAME:
			jdata_copy['__sender-name'] = null
		var jstring = _get_sorted_joined_string_elements_from_array(jdata_copy.keys())
		jstring += _get_sorted_joined_string_elements_from_array(jdata_copy.values())
		var hash_string =jstring.sha256_text()
		if hash_string != sender_hash:
			if jdata['__destination-name'] != _HS_SERVER_NAME:
				var msg = "packet has incorrect password (hash mismatch)"
				if _holepunch_ref.i_am_server():
					msg = ("packet from " + jdata['__sender-name']
				 			+ " has incorrect pasword (hash mismatch)")
					_holepunch_ref.emit_signal("error", msg)
					_holepunch_ref.drop_peer(jdata['__sender-name'])
				else: 
					_holepunch_ref.emit_signal("error", msg)
					_holepunch_ref.quit_connection()
			return null
		
		#all good
		var outgoing = false
		return HPacket.new(_holepunch_ref, name(), your_name(), socket(), sender_address, 
							jdata['__destination-address'], jdata['__type'], jdata, outgoing)


	
	func _get_unique_msg_id():
		var id = _sent_message_id_counter
		_sent_message_id_counter += 1
		#overflow
		if _sent_message_id_counter < 0:
			_sent_message_id_counter = 0
		return id
		
	func _get_sorted_joined_string_elements_from_array(array):
		var string_elements = []
		for element in array:
			if typeof(element) == TYPE_STRING:
				string_elements.push_back(element)
		string_elements.sort()
		var string_of_sorted_strings = ''
		for string_element in string_elements:
				string_of_sorted_strings += string_element
		return string_of_sorted_strings
		
	func _add_security_outgoing(type, data, address):
		data['__type'] = type
		if send_to_as_handshake:
			data['__sender-name'] = null
		else:
			data['__sender-name'] = your_name()
		data['__destination-name'] = name()
		data['__destination-address'] = address
		var copy_for_hashing = data.duplicate()
		copy_for_hashing['password'] = password()
		var jstring = _get_sorted_joined_string_elements_from_array(copy_for_hashing.keys())
		jstring += _get_sorted_joined_string_elements_from_array(copy_for_hashing.values())
		var hash_string =jstring.sha256_text()
		data['__hash-string'] = hash_string
		return data
	
	func send_peer_list_update(action, peers):
		var type = 'update-peer-list'
		var data = {'action': action}
		data['peer-infos'] = {}
		for peer in peers:
			data['peer-infos'][peer.name()] = {
				'global-address': peer.global_address(),
				'local-address': peer.local_address(),
				'use-global': peer.address() == peer.global_address()
			}
		add_outgoing_reliable_now(type, data)


class PeerContainer:
	var _peers = {}
	func get_confirmed():
		var ret = []
		for peer in _peers.values():
			if peer.is_confirmed():
				ret.push_back(peer)
		return ret
	func get(peer_name):
		if _peers.has(peer_name):
			return _peers[peer_name]
		return null
	func get_confirmed_names():
		var ret = []
		for peer in _peers.values():
			if peer.is_confirmed():
				ret.push_back(peer.name())
		return ret
	func get_unconfirmed_names():
		var ret = []
		for peer in _peers.values():
			if not peer.is_confirmed():
				ret.push_back(peer.name())
		return ret
	func add(peer):
		_peers[peer.name()] = peer
	func remove(peer_name):
		if _peers.has(peer_name):
			_peers.erase(peer_name)