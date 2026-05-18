'''Relays ZeroMQ traffic between processes'''

import logging
import zmq

from evilminions.worker_logging import setup as setup_worker_logging


def start_proxy(semaphore):
    setup_worker_logging()
    log = logging.getLogger(__name__)

    log.debug("Starting proxy...")
    context = zmq.Context()
    xsub = context.socket(zmq.PULL)
    xsub.bind('ipc:///tmp/evil-minions-pull.ipc')
    xpub = context.socket(zmq.PUB)
    xpub.bind('ipc:///tmp/evil-minions-pub.ipc')
    log.debug("Proxy ready")
    semaphore.release()
    zmq.proxy(xpub, xsub)
