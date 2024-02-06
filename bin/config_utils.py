import json


def get_config(config_file):
  with open(config_file, "r") as f:
    config = json.load(f)
  return config


def get_database_name():
  config = get_config()
  return config["database"]["name"]
