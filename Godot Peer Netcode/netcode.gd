extends Node

const PORT = 33334
const SERVER_ID = 1
const MAX_PLAYERS = 4
const COMPRESSION_MODE = NetworkedMultiplayerENet.COMPRESS_ZLIB
var me_as_peer = null #will hold the NetworkedMultiplayerENet
var my_info = {}

func _ready():
	get_tree().connect('network_peer_disconnected', self, '_player_disconnected')
	get_tree().connect('connected_to_server', self, '_connected_ok')
	get_tree().connect('server_disconnected', self, '_server_disconnected')



###########################################
###########################################
#####          CREATION               #####
###########################################

func create_server(player_info):
	global.player_infos = {}
	global.player_infos[SERVER_ID] = player_info
	my_info = player_info
	me_as_peer = NetworkedMultiplayerENet.new()
	me_as_peer.set_compression_mode(COMPRESSION_MODE)
	me_as_peer.create_server(PORT, MAX_PLAYERS)
	get_tree().set_network_peer(me_as_peer)
	return true

func join_server(server_ip, player_info):
	my_info = player_info
	me_as_peer = NetworkedMultiplayerENet.new()
	me_as_peer.set_compression_mode(COMPRESSION_MODE)
	me_as_peer.create_client(server_ip, PORT)
	get_tree().set_network_peer(me_as_peer)
	return true

func _connected_ok():
	var my_id = get_tree().get_network_unique_id()
	rpc("_register_player", my_id, my_info)

remote func _register_player(id, player_info):
	global.player_infos[id] = player_info
	if get_tree().is_network_server():
		#fill in the new guy about other players
		for peer_id in global.player_infos:
			rpc_id(id, "_register_player", peer_id, global.player_infos[peer_id])
	global.lobby_update_pending = true



###########################################
###########################################
#####          UPDATING               #####
###########################################


func propagate_player_info():
	var my_id = get_tree().get_network_unique_id()
	rpc("_update_player_info", my_id, global.player_infos[my_id])

remote func _update_player_info(id, player_info):
	global.player_infos[id] = player_info
	global.lobby_update_pending = true

func propagate_settings():
	rpc("_update_settings", global.settings)
	
remote func _update_settings(settings):
	global.settings = settings
	global.lobby_update_pending = true





###########################################
###########################################
#####          QUITTING               #####
###########################################

func clear_connection():
	me_as_peer.close_connection()
	global.player_infos = {}

func _player_disconnected(id):
	global.player_infos.erase(id)
	global.lobby_update_pending = true

func _server_disconnected():
	clear_connection()
	global.goto_scene(global.landing_page_scene)
