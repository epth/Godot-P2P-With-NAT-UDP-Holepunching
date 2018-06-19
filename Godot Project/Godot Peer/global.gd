extends Node

const landing_scene = preload("res://landing/Landing.tscn")
const lobby_scene  = preload("res://lobby/Lobby.tscn")

func goto_scene(packed_scene):
	get_tree().change_scene_to(packed_scene)