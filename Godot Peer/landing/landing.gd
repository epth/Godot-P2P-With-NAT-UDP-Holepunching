extends Panel

onready var _handshake_ip_field = find_node("HandshakeServerIPField")
onready var _handshake_port_field = find_node("HandshakeServerPortField")
onready var _local_ip_field = find_node("LocalIPField")
onready var _local_port_field = find_node("LocalPortField")
onready var _username_field = find_node("UserNameField")
onready var _password_field = find_node("PasswordField")
onready var _server_field = find_node("ServerField")
onready var _register_server_button = find_node("RegisterServerButton")
onready var _join_server_button = find_node("JoinServerButton")
onready var _print_peers_button = find_node("PrintPeersButton")
onready var _get_server_list_button = find_node("GetServerListButton")
onready var _go_to_lobby_button = find_node("GoToLobbyButton")
onready var _reset_button = find_node("ResetButton")
onready var _exit_button = find_node("ExitButton")
onready var _console_field = find_node("OutputField", true)
onready var _input_field = find_node("InputField", true)

func _ready():
	#connect button-press signals
	_print_peers_button.connect('pressed', self, '_print_peers')
	_register_server_button.connect('pressed', self, '_register_server')
	_join_server_button.connect('pressed', self, '_join_server')
	_get_server_list_button.connect('pressed', self, '_request_server_list')
	_go_to_lobby_button.connect('pressed', self, '_go_to_lobby')
	_reset_button.connect('pressed', self, '_reset')
	_exit_button.connect('pressed', self, '_exit')
	_input_field.connect('text_entered', self, '_input_entered')
	
	#connect P2P signals
	holepunch.connect('confirmed_as_server', self, '_confirmed_as_server')
	holepunch.connect('confirmed_as_client', self, '_confirmed_as_client')
	holepunch.connect('peer_joined', self, '_peer_joined')
	holepunch.connect('peer_dropped', self, '_peer_dropped')
	
	holepunch.connect('error', self, '_error')
	holepunch.connect('session_terminated', self, '_session_terminated')
	holepunch.connect('received_server_list', self, '_print_server_list')
	
	holepunch.connect('received_unreliable_message_from_peer', self, '_message_received')
	holepunch.connect('received_reliable_message_from_peer', self, '_message_received')
	holepunch.connect('reliable_message_timeout', self, '_reliable_message_timeout')
	
	#other signals
	holepunch.connect('packet_sent', self, '_packet_sent')
	holepunch.connect('packet_received', self, '_packet_received')
	holepunch.connect('packet_blocked', self, '_packet_blocked')
	holepunch.connect('packet_timeout', self, '_packet_timeout')
	holepunch.connect('packet_expired', self, '_packet_expired')
	holepunch.connect('peer_confirmed_reliable_message_received', self, '_confirmed_message')
	
	
	#defaults
	_handshake_ip_field.text =  '127.0.0.1'# '35.197.160.85'
	_handshake_port_field.text = '5160'
	_local_ip_field.text = '192.168.1.127'
	_local_port_field.text = '3334'
	_username_field.text = 'euler'


func out(message):
	"""prints a message to the gui console"""
	_console_field.add_text(message)
	_console_field.newline()


######################################
##           INPUTS
######################################

func _input_entered(text):
	if not holepunch.is_connected():
		out("Error: no peers to send message to")
		_input_field.clear()
		return
		
	var peer_name = null
	if text.begins_with("@"):
		var name_end = text.length()
		if text.find(" ") != -1:
			name_end = text.find(" ")
		peer_name = text.substr(1, name_end - 1)
		text = text.substr(name_end, text.length() - name_end)
		out(holepunch.get_user_name() + " @" + peer_name + ":")
	else:
		out(holepunch.get_user_name() + ":")
	out("   " + text)
	holepunch.send_message_to_peer(peer_name, text, true)
	_input_field.clear()
	
func _exit():
	get_tree().quit()
	
	
func _reset():
	holepunch.quit_connection()
	_console_field.clear()

func _go_to_lobby():
	out("This is where the demo ends...")
	
func _request_server_list():
	var handshake_ip = _handshake_ip_field.text
	var handshake_port = int(_handshake_port_field.text)
	out("Request for servers sent to " + handshake_ip)
	holepunch.request_server_list([handshake_ip, handshake_port])


func _register_server():
	var handshake_address = [_handshake_ip_field.text, int(_handshake_port_field.text)]
	var local_address = [_local_ip_field.text, int(_local_port_field.text)]
	var user_name = _username_field.text
	var password = _password_field.text
	if password == "":
		password == null
	out("Attempting to register server...")
	holepunch.init_server(handshake_address, local_address, user_name, password)

func _join_server():
	var handshake_address = [_handshake_ip_field.text, int(_handshake_port_field.text)]
	var local_address = [_local_ip_field.text, int(_local_port_field.text)]
	var server_name = _server_field.text
	var user_name = _username_field.text
	var password = _password_field.text
	if password == "":
		password == null
	out("Attempting to join server...")
	holepunch.init_client(handshake_address, local_address, user_name, server_name, password) 


func _print_peers():
	out("Connected peers:")
	for peer_name in holepunch.get_peers():
		out("    " + peer_name)



######################################
##           SIGNALS
######################################

func _peer_joined(peer_name):
	out('Peer joined: ' + peer_name)
	
func _peer_dropped(peer_name):
	out('Peer dropped: ' + peer_name)


func _confirmed_as_server(server_address):
	out('Registered as server "' + holepunch.get_user_name() + '" at ' 
		 + str(holepunch.get_handshake_server_address()))
	

func _confirmed_as_client(server_address):
	out('Connected to "' + holepunch.get_server_name() + '" at ' 
			+ str(holepunch.get_server_address()) + ' as client')

func _message_received(data):
	if (data['is-broadcast']):
		out(data['from'] + ":")
	else:
		out(data['from'] + " @" + holepunch.get_user_name() + ":")
	out("   " + str(data['message']))

func _reliable_message_timeout(data):
	out("Message to " + str(data['to'])  + " has timed out")


func _peer_check_timeout(peer_name):
	out("Peer check timeout for peer: " + peer_name)
	
func _peer_handshake_timeout(peer_name):
	out("Failed to connect to " + peer_name)
	
	
func _print_server_list(info):
	out("Received server list from " + info['server-address'][0])
	out("Servers: ")
	for server in info['server-list']:
		out("    " +server)


func _error(message):
	out("Error: " + message)

func _session_terminated():
	out("Session terminated.")
	_join_server_button.disabled = false
	_register_server_button.disabled = false




func _packet_timeout(packet_data, is_resending):
	print("packet timed out of type: " + packet_data['__type'])
	if is_resending:
		print("attempting to resend...")
	
func _packet_expired(packet_data):
	print("packet expired out of type: " + packet_data['__type'])


func _packet_received(packet_data):
	print("packet received from " + packet_data['__sender-name'] + " of type " 
		+ packet_data['__type'])

func _packet_blocked(address):
	print("packet blocked from address: " + str(address))
		
func _packet_sent(packet_data):
	print("packet sent to " + packet_data['__destination-name'] + " of type " 
		+ packet_data['__type'])

func _confirmed_message(packet_data):
	print("peer " + packet_data['__sender-name'] + " has confirmed reliable message received")

