extends Panel
#get a handle to all these elements
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

func _ready():
	#connect button-press signals
	_send_message_button.connect('pressed', self, '_send_message_to_peer')
	_print_peers_button.connect('pressed', self, '_print_peers')
	_register_server_button.connect('pressed', self, '_register_server')
	_join_server_button.connect('pressed', self, '_join_server')
	#connect P2P signals
	$HolePunch.connect('connection_lost', self, '_give_up')
	$HolePunch.connect('peer_dropped', self, '_peer_dropped')
	$HolePunch.connect('peer_confirmed', self, '_new_peer')
	$HolePunch.connect('packet_received', self, '_packet_received')
	$HolePunch.connect('message_from_peer', self, '_message_from_peer')
	$HolePunch.connect('error', self, '_holepunch_error')
	#defaults
	_handshake_ip_field.text = '35.197.160.85'
	_handshake_port_field.text = '5160'
	_local_ip_field.text = '192.168.1.127'
	_local_port_field.text = '3334'


func _holepunch_error(message):
	out("error: " + message)

func _give_up(is_server):
	out("Connection lost. Am I server? " + str(is_server) + ". Resetting...")
	_join_server_button.disabled = false
	_register_server_button.disabled = false

func _peer_dropped(peer_name):
	out("Peer dropped: " + peer_name)

func _new_peer(info):
	out("New peer:")
	out("    " + info['peer-name'] + " at " + str(info['adress']))

func _packet_received(jData):
	out("packet received of type:" + jData['type'])
	
func _message_from_peer(jData):
	out("message from " + jData['sender'])
	out("   " + str(jData['message']))


func _register_server():
	var handshake_ip = _handshake_ip_field.text
	var handshake_port = int(_handshake_port_field.text)
	var local_ip = _local_ip_field.text
	var local_port = int(_local_port_field.text)
	var server_name = _register_servername_field.text
	$HolePunch.init_server(handshake_ip, handshake_port, local_ip, local_port, server_name)

func _join_server():
	var handshake_ip = _handshake_ip_field.text
	var handshake_port = int(_handshake_port_field.text)
	var local_ip = _local_ip_field.text
	var local_port = int(_local_port_field.text)
	var server_name = _join_servername_field.text
	var user_name = _join_username_field.text
	$HolePunch.init_client(handshake_ip, handshake_port, local_ip, local_port, user_name, server_name) 


func _print_peers():
	out("connected peers:")
	for peer in $HolePunch.confirmed_peers.values():
		out("    " + str(peer))

func out(message):
	"""prints a message to the gui console"""
	_output_field.text += message + '\n'
	#set scroll to end
	_output_field.cursor_set_line(_output_field.get_line_count()+10, true)
