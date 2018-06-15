extends Panel

class Packet:
	var peer_name # null if handshake server
	var udp_socket_instance
	var data_as_json
	var type
	
	func _init(peer_name, udp_socket_instance, type, data_as_json):
		self.peer_name = peer_name
		self.udp_socket_instance = udp_socket_instance
		self.data_as_json = data_as_json
		self.data_as_json['type'] = type
		self.type = type
	func send():
		var bin_data = JSON.print(self.data_as_json).to_utf8()
		self.udp_socket_instance.put_packet(bin_data)

class HeartbeatPacket extends Packet:
	var seconds_counter = 0
	var seconds_before_expiry
	var seconds_between_resends
	func _init(peer_name, udp_socket_instance, type, data_as_json, 
				seconds_between_resends, seconds_before_expiry).(peer_name, 
				udp_socket_instance, type, data_as_json):
		self.seconds_before_expiry = seconds_before_expiry
		self.seconds_between_resends = seconds_between_resends
	func seconds_tick():
		seconds_counter += 1
		if seconds_counter >= seconds_between_resends:
			print("sent")
			send()
		if seconds_counter >= seconds_before_expiry:
			print("packet expired")
			return true
		else:
			print(seconds_before_expiry - seconds_counter)
			return false
	func reset_expiry():
		print("expiry reset")
		seconds_counter = 0

class PacketContainer:
	var packets = []
	func add(packet):
		packets.push_back(packet)
	func remove_peer(peer_name):
		var packets_to_remove = []
		for packet in packets:
			if packet.peer_name == peer_name:
				packets_to_remove.push_back(packet)
		for packet_to_remove in packets_to_remove:
			packets.erase(packet_to_remove)
	func reset_expiry_for_peer(peer_name):
		for packet in packets:
			if packet.peer_name == peer_name:
				packet.reset_expiry()
	func duplicate():
		return packets.duplicate()
	func clear():
		packets = []



class UnconfirmedPeer:
	var local_udp_socket_instance
	var global_udp_socket_instance
	var username
	
	
	
onready var _handshake_ip_field = find_node("HandshakeServerIPField")
onready var _handshake_port_field = find_node("HandshakeServerPortField")
onready var _local_ip_field = find_node("LocalIPField")
onready var _local_port_field = find_node("LocalPortField")
onready var _join_username_field = find_node("JoinUserNameField")
onready var _register_servername_field = find_node("RegisterServerNameField")
onready var _join_servername_field = find_node("JoinServerNameField")
onready var _register_server_button = find_node("RegisterServerButton")
onready var _join_server_button = find_node("JoinServerButton")
onready var _peer_message_field = find_node("PeerMessageField")
onready var _peer_username_field = find_node("PeerUserNameField")
onready var _send_message_button = find_node("SendMessageButton")
onready var _print_peers_button = find_node("PrintPeersButton")
onready var _output_field = find_node("Output", true)

var confirmed_peers = {}
var unconfirmed_peers = {}
var heartbeat_packets = PacketContainer.new()
var handshake_server_socket = null
var seconds_ticker = 0
var i_am_server = null
const SECONDS_BETWEEN_HEARTBEATS = 15
const SERVER_NAME = null


func _ready():
	_send_message_button.connect('pressed', self, '_send_message_to_peer')
	_print_peers_button.connect('pressed', self, '_print_peers')
	_register_server_button.connect('pressed', self, '_register_server')
	_join_server_button.connect('pressed', self, '_join_server')
	
	_handshake_ip_field.text = '35.197.160.85'
	_handshake_port_field.text = '5160'
	_local_ip_field.text = '192.168.1.127'
	_local_port_field.text = '3334'
	

func out(message):
	_output_field.text += message + '\n'
	#set scroll to end
	_output_field.cursor_set_line(_output_field.get_line_count()+1, true)

func _send_message_to_peer():
	pass

func _print_peers():
	out("blah")


func _process(delta):
	seconds_ticker += delta
	if seconds_ticker > 1:
		seconds_ticker = 0
		for packet in heartbeat_packets.duplicate():
			var packet_expired = packet.seconds_tick()
			if packet_expired:
				if not i_am_server:
					give_up()
				else:
					if packet.type == 'registering-server':
						give_up()
					else:
						heartbeat_packets.remove_peer(packet.peer_name)
						#todo: remove matching unconfirmed peers
						#todo: remove confirmed matching peers
	if 	handshake_server_socket:
		while handshake_server_socket.get_available_packet_count() > 0: 
			var array_bytes = handshake_server_socket.get_packet()
			var json_string = array_bytes.get_string_from_utf8()
			var jData = JSON.parse(json_string)
			if jData['type'] == 'confirming-registration':
				heartbeat_packets.reset_expiry_for_peer(SERVER_NAME)


func give_up():
	out("given up")
	_join_server_button.disabled = false
	_register_server_button.disabled = false
	heartbeat_packets.clear()
	handshake_server_socket = null

#############################################################
#############################################################
#            
#############################################################
func _register_server():
	
	if not self._init_server_socket():
		return
	if _register_servername_field.text.empty():
		out("server name required for registration")
		return
	if _local_ip_field.text.empty():
		out("local ip required for registration")
		return
	if _local_port_field.text.empty():
		out("local port required for registration")
		return false
		
	var data = {
		'user-name' : _register_servername_field.text,
		'seconds-before-expiry': 60,
		'local-ip': _local_ip_field.text,
		'local-port': int(_local_port_field.text)
	}
	i_am_server = true
	var registration_packet = HeartbeatPacket.new(SERVER_NAME, handshake_server_socket, 
											  	 'registering-server', data, 15, 5)
	heartbeat_packets.add(registration_packet)
	registration_packet.send()
	_join_server_button.disabled = true
	_register_server_button.disabled = true
	out("sending registration to handshake server")

func _join_server():
	if not self._init_server_socket():
		return
	if _join_username_field.text.empty():
		out("missing user name")
		return
	if _join_servername_field.text.empty():
		out("specify which server to join (by their username)")
		return
	if _local_ip_field.text.empty():
		out("local ip required for registration")
		return
	if _local_port_field.text.empty():
		out("local port required for registration")
		return
	i_am_server = false
	var data = {
		'user-name' : _join_username_field.text,
		'server-name': _join_servername_field.text,
		'local-ip': _local_ip_field.text,
		'local-port': int(_local_port_field.text)
	}
	var request_to_join_packet = HeartbeatPacket.new(SERVER_NAME, handshake_server_socket, 
											  	 'requesting-to-join-server', data, 15, 5)
	heartbeat_packets.add(request_to_join_packet)
	request_to_join_packet.send()
	heartbeat_packets.add(request_to_join_packet)
	_join_server_button.disabled = true
	_register_server_button.disabled = true
	out("sending request for info to handshake server")



func _init_server_socket():
	"""start listening to handshake server. Returns false if init fails"""
	#check if something given for fields required for handshake server init
	if _handshake_ip_field.text.empty():
		out("handshake ip required")
		return false
	if _handshake_port_field.text.empty():
		out("handshake port required")
		return false
	if _local_port_field.text.empty():
		out("local port required")
		return false
	#start listening
	handshake_server_socket = PacketPeerUDP.new()
	if handshake_server_socket.listen(int(_local_port_field.text)) != OK:
		out("invalid local port")
		return false
	#set address for sending packets
	handshake_server_socket.set_dest_address(_handshake_ip_field.text, 
 											 int(_handshake_port_field.text))
	return true
