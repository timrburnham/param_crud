import configparser
from pathlib import Path

config = configparser.ConfigParser(interpolation=None)
config.read(Path.home() / 'secret.ini')
