import logging
import os


def setup():
    name = os.environ.get('EVIL_MINIONS_LOG_LEVEL', 'INFO')
    level = getattr(logging, name.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    if not root.handlers:
        logging.basicConfig(level=level, format='%(levelname)s:%(message)s')
