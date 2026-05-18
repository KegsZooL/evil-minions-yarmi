import logging
import os
import sys


def setup():
    name = os.environ.get('EVIL_MINIONS_LOG_LEVEL', 'INFO')
    level = getattr(logging, name.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)

    for h in root.handlers[:]:
        root.removeHandler(h)

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter('%(levelname)s:%(message)s'))
    root.addHandler(handler)
