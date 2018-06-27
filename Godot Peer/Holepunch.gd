extends Node

"""
todo
	* documentation
	* remove signal for reliable message confirmation - 
				it's ambiguous now that server is routing messages
"""


#############################################################
#############################################################
#                           SIGNALS                         #
#############################################################
signal confirmed_as_client
signal confirmed_as_server

signal session_terminated 
signal packet_sent
signal packet_received
signal packet_blocked
signal client_confirmed
signal received_unreliable_message_from_peer
signal received_reliable_message_from_peer 
signal peer_confirmed_reliable_message_received
signal reliable_message_timeout
signal peer_timeout
signal peer_connection_failed
signal error
signal received_server_list
signal peer_list_updated



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
					quit_connection()
					return
				if packet.type == 'refreshing-server-registration':
					quit_connection()
					return
				if packet.type == 'requesting-to-join-server':
					quit_connection()
					return
				if packet.type == 'address-inquiry':
					emit_signal('peer_connection_failed', packet.dest_name)
					if _i_am_server:
						#no official peer drop here- they were never really connected
						_peers.remove(packet.dest_name)
					else:
						quit_connection()
					return
				if packet.type == 'peer-check':
					emit_signal('peer_timeout', packet.dest_name)
					if _i_am_server:
						drop_peer(packet.dest_name)
					else:
						quit_connection()
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
			emit_signal('packet_blocked', [_socket.get_packet_ip(), _socket.get_packet_port()])
			return
		var packet_data =  packet.get_copy_of_json_data()
		emit_signal('packet_received', packet.get_copy_of_json_data())
		
		if packet.type == 'server-error':
			emit_signal('error', packet_data['message'])
			quit_connection()
			break
		
		elif packet.type == 'providing-server-list':
			_packets.remove_all_of_type('requesting-server-list')
			var info = {
				'server-list': packet_data['server-list'],
				'server-address': packet.sender_address
			}
			
			emit_signal('received_server_list', info)
		
		elif packet.type == 'confirming-registration':
			_packets.remove_all_of_type('registering-server')
			var data = {
				'seconds-before-expiry': secs_reg_valid
			}
			_handshake_server.add_outgoing_reliable_periodic('refreshing-server-registration', 
													data, secs_between_reg_refresh)
			print("global address: " + str(packet.dest_address))
			_server_address =  packet.dest_address
			_global_address = packet.dest_address
			emit_signal('confirmed_as_server', packet.sender_address)
		
		elif packet.type == 'confirming-registration-refresh':
			_packets.reset_expiry_for_all_of_type('refreshing-server-registration')
		
		elif packet.type == 'providing-peer-handshake-info':
			#remove ignores if there are none matching
			_packets.remove_all_of_type('requesting-to-join-server')
			var peer_name = packet_data['peer-name']
			#only add if we haven't already
			if _peers.get(peer_name) != null or peer_name == _user_name:
				emit_signal('error', 'attempted connection with invalid peer name: "' + peer_name + '"')
				if not _i_am_server:
					quit_connection()
			else:
				var peer = Peer.new(self, peer_name, _password, 
									self._socket, self._packets,
									packet_data['global-address'], packet_data['local-address'])
				_peers.add(peer)
				peer.send_address_inquiry()
		
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
					emit_signal('client_confirmed', peer.name())
					peer.send_peer_list_update('add', _peers.get_all())
					for existing_peer in _peers.get_all():
						if existing_peer.name() != peer.name():
							existing_peer.send_peer_list_update('add', [peer])
				else:
					_server_address =  peer.address()
					_global_address = packet.dest_address
					emit_signal('confirmed_as_client', get_server_address())
		
		elif packet.type == 'peer-check':
			var peer = _peers.get(packet.sender_name)
			if peer and peer.is_confirmed():
				#If this fails, they'll send again because THEY care about it
				peer.add_outgoing_unreliable_now('peer-check-response', packet_data)
		
		elif packet.type == 'peer-check-response':
			_packets.reset_expiry_for_all_of_peer_and_type(packet.sender_name, 'peer-check')
		
		elif packet.type == 'unreliable-peer-message':
			if _i_am_server:
				var peers_to_send_msg = []
				if packet_data['is-broadcast']:
					peers_to_send_msg = _peers.get_all()
				else:
					var peer = _peers.get(packet_data['to'])
					if peer:
						peers_to_send_msg.append(peer)
				for peer in peers_to_send_msg:
					if peer.name() != packet.sender_name:
						peer.send_unreliable_message(packet_data['message'], 
													 packet_data['from'], peer.name())
			if packet_data['is-broadcast'] or packet_data['to'] == _user_name:
				emit_signal('received_unreliable_message_from_peer', packet.get_copy_of_json_data())

			
		elif packet.type == 'reliable-peer-message':
			if _i_am_server:
				var peers_to_send_msg = []
				if packet_data['is-broadcast']:
					peers_to_send_msg = _peers.get_all()
				else:
					var peer = _peers.get(packet_data['to'])
					if peer:
						peers_to_send_msg.append(peer)
				for peer in peers_to_send_msg:
					if peer.name() != packet.sender_name:
						peer.send_reliable_message(packet_data['message'], 
													packet_data['from'], peer.name(), 
													packet_data['message-id'])
			if packet_data['is-broadcast'] or packet_data['to'] == _user_name:
				var peer = _peers.get(packet.sender_name)
				if peer and peer.is_confirmed():
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
		


#############################################################
#############################################################
#                EXTERNALLY VISIBLE METHODS                 #
#############################################################

func get_user_name():
	return _user_name

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



		

func send_unreliable_message_to_peer(peer_name, message):
	_send_message_to_peer(peer_name, message, false)


func send_reliable_message_to_peer(peer_name, message):
	_send_message_to_peer(peer_name, message, true)

func request_server_list(handshake_address):
	if not _handshake_server or _handshake_server.address() != handshake_address:
		_packets.remove_all_of_peer(_HS_SERVER_NAME)
		_handshake_server = Peer.new(self, _HS_SERVER_NAME, _generate_random_alpha_numeric(10),
									  _socket, _packets, handshake_address)
	var data = {'password': _handshake_server.password()}
	_handshake_server.add_outgoing_reliable_now('requesting-server-list', data)

func quit_connection():
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
	_handshake_server = null

func is_connected():
	return _user_name != null

func drop_peer(peer_name):
	if _i_am_server:
		var peer = _peers.get(peer_name)
		if peer:
			var peer_infos = {}
			peer_infos[peer.name()] = {
				'global-address': peer.global_address(),
				'local-address': peer.local_address(),
				'use-global': peer.address() == peer.global_address()
			}
			_update_peer_list('remove', peer_infos) 
			for existing_peer in _peers.get_all():
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
	if not self._password:
		_password = server_name
	var data = {
		'local-address': self._local_address,
		'seconds-before-expiry': self.secs_reg_valid,
		'password': _handshake_server.password()
	}
	_handshake_server.add_outgoing_reliable_now('registering-server', data)


	
func init_client(handshake_address, local_address, user_name, server_name, password=null):
	if not _common_init(user_name, handshake_address, local_address):
		return
	self._i_am_server = false
	self._server_name = server_name
	self._password = password
	if not self._password:
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

func _update_peer_list(action, peer_infos):
	if action == 'add':
		for peer_name in peer_infos.keys():
			if peer_name ==_user_name:
				continue
			var peer_info = peer_infos[peer_name]
			var peer = Peer.new(self, peer_name, _password, _socket, _packets,
							peer_info['global-address'], peer_info['local-address'])
			peer.confirm(peer_info['use-global'])
			_peers.add(peer)
		emit_signal('peer_list_updated', _peers.get_confirmed_names())
	elif action == 'remove':
		for peer_name in peer_infos.keys():
			_packets.remove_all_of_peer(peer_name)
			_peers.remove(peer_name)
		emit_signal('peer_list_updated', _peers.get_confirmed_names())
	
	
func _generate_random_alpha_numeric(length):
	var allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	randomize()
	var random_string = ""
	for i in range(0, length):
		random_string += allowed_chars[randi() % allowed_chars.length()]
	print(random_string)
	return random_string


func _get_incoming_packet():
	var bytes = _socket.get_packet()
	var sender_address = [_socket.get_packet_ip(), _socket.get_packet_port()]
	
	var json_string = bytes.get_string_from_utf8()
	var result = JSON.parse(json_string)
	if result.error != OK:
		return null
	
	var jdata = result.result
	var peer 
	if jdata.has('__sender-name') and _peers.get(jdata['__sender-name']):
		peer = _peers.get(jdata['__sender-name'])
	elif _handshake_server:
		peer = _handshake_server
	if not peer:
		return null
	return peer.check_security_and_make_incoming_packet(jdata, sender_address)


func _send_message_to_peer(peer_name, message, reliable):
	if _peers == null:
		emit_signal('error', 'unitialised')
		return
	if peer_name != null and _peers.get(peer_name) == null:
		emit_signal('error', 'no peer named "' + peer_name + '"')
		return
		
	if _i_am_server:
		var peers_to_send_to = []
		if peer_name == null:
			peers_to_send_to = _peers.get_all()
		else:
			var peer = _peers.get(peer_name)
			if peer:
				peers_to_send_to.append(peer)
		for peer_to_send_to in peers_to_send_to:
			if reliable:
				peer_to_send_to.send_reliable_message(message, _user_name, 
														peer_to_send_to.name())
			else:
				peer_to_send_to.send_unreliable_message(message, _user_name, 
														peer_to_send_to.name())
	else:
		if reliable:
			_peers.get(_server_name).send_reliable_message(message, _user_name, peer_name)
		else:
			_peers.get(_server_name).send_unreliable_message(message, _user_name, peer_name)
			
			
			
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
				if not _resend_on_fail:
					return true
				_attempts_countdown -= 1
				if _attempts_countdown > 0:
					print("attempting to resend type: " + type)
					_await_reply_countdown = secs_to_await_reply
					send()
				else:
					print("packet expired")
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

	

	func send_reliable_message(message, from_name, to_name, unique_id_override=null):
		var is_broadcast = to_name == null
		var data = {'is-broadcast': is_broadcast}
		data['from'] = from_name
		if not is_broadcast:
			data['to'] = to_name
		data['message'] = message
		if unique_id_override == null:
			data['message-id'] = self._get_unique_msg_id()
		else:
			data['message-id'] = unique_id_override
		add_outgoing_reliable_now('reliable-peer-message', data, null)

	func send_unreliable_message(message,  from_name, to_name):
		var is_broadcast = to_name == null
		var data = {'is-broadcast': is_broadcast}
		data['from'] = from_name
		if not is_broadcast:
			data['to'] = to_name
		data['message'] = message
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
		var address = custom_address
		if address == null:
			address = address()
		var outgoing = true
		data = _add_security_outgoing(type, data, address)
		var packet = HPacket.new(_holepunch_ref, your_name(), name(), socket(), null, address, type, 
								data, outgoing, resend_on_fail, send_now, repeat)
		_packets.add(packet, replace_same_peer_and_type)
		
		
	func check_security_and_make_incoming_packet(jdata, sender_address):
		#check everything is there
		if is_confirmed() and sender_address != address():
			return null
		elif sender_address != local_address() and sender_address != global_address():
			return null
		if not jdata.has('__type'):
			return null
		if not jdata.has('__destination-address'):
			return null
		if not jdata.has('__destination-name') or jdata['__destination-name'] != your_name():
			return null
		if not jdata.has('__hash-string'):
			return null
		
		#check hashes match
		var sender_hash = jdata['__hash-string']
		jdata.erase('__hash-string')
		var jdata_copy = jdata.duplicate()
		jdata_copy['password'] = password()
		var jstring = _get_sorted_joined_string_elements_from_array(jdata_copy.keys())
		jstring += _get_sorted_joined_string_elements_from_array(jdata_copy.values())
		var hash_string =jstring.sha256_text()
		if hash_string != sender_hash:
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
	
	func get_all():
		return _peers.values()
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