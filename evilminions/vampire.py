import logging
import inspect
import os
import threading
import time

import tornado.gen
import tornado.ioloop
import zmq

import salt.payload
from salt.channel.client import AsyncPubChannel
from salt.channel.client import AsyncReqChannel

log = logging.getLogger(__name__)

_PROXY_PULL = 'ipc:///tmp/evil-minions-pull.ipc'


class Vampire(object):
    def __init__(self):
        self.context = zmq.Context.instance()
        self._push = None
        self._push_lock = threading.Lock()

    def attach(self):
        AsyncReqChannel.dump = self.dump
        AsyncReqChannel._original_send = AsyncReqChannel.send
        AsyncReqChannel.send = _dumping_send
        AsyncReqChannel._original_crypted_transfer_decode_dictentry = AsyncReqChannel.crypted_transfer_decode_dictentry
        AsyncReqChannel.crypted_transfer_decode_dictentry = _dumping_crypted_transfer_decode_dictentry

        AsyncPubChannel.dump = self.dump
        AsyncPubChannel._original_on_recv = AsyncPubChannel.on_recv
        AsyncPubChannel.on_recv = _dumping_on_recv

    def _push_close(self):
        if self._push is not None:
            try:
                self._push.close(linger=0)
            except Exception:
                pass
            self._push = None

    def _push_connect(self):
        if self._push is not None:
            return
        sock = self.context.socket(zmq.PUSH)
        try:
            sock.setsockopt(zmq.SNDHWM, 100000)
            sock.setsockopt(zmq.LINGER, 3000)
            sock.connect(_PROXY_PULL)
            self._push = sock
        except Exception:
            sock.close(linger=0)
            raise

    def dump(self, load, socket, method, **kwargs):
        if log.isEnabledFor(logging.DEBUG):
            cmd = load.get('cmd') if isinstance(load, dict) else None
            fun = load.get('fun') if isinstance(load, dict) else None
            fun_args = load.get('fun_args') if isinstance(load, dict) else None
            arg = load.get('arg') if isinstance(load, dict) else None
            jid = load.get('jid') if isinstance(load, dict) else None
            log.debug(
                "Vampire.dump socket=%s cmd=%s fun=%s jid=%s fun_args=%r arg=%r pid=%s",
                socket, cmd, fun, jid, fun_args, arg, os.getpid(),
            )

        header = {
            'socket': socket,
            'time': time.time(),
            'pid': os.getpid(),
            'method': method,
            'kwargs': kwargs,
        }
        event = {
            'header': header,
            'load': load,
        }

        payload = salt.payload.dumps(event)
        with self._push_lock:
            try:
                self._push_connect()
                self._push.send(payload)
            except Exception as exc:
                log.error("Event: {}".format(event))
                log.error("Unable to dump event: {}".format(exc))
                self._push_close()


@tornado.gen.coroutine
def _dumping_send(self, load, **kwargs):
    self.dump(load, 'REQ', 'send', **kwargs)
    ret = yield self._original_send(load, **kwargs)
    raise tornado.gen.Return(ret)


@tornado.gen.coroutine
def _dumping_crypted_transfer_decode_dictentry(self, load, **kwargs):
    self.dump(load, 'REQ', 'crypted_transfer_decode_dictentry', **kwargs)
    ret = yield self._original_crypted_transfer_decode_dictentry(load, **kwargs)
    raise tornado.gen.Return(ret)


def _dumping_on_recv(self, callback):
    if callback is None:
        try:
            return self._original_on_recv(None)
        except OSError as exc:
            if "Stream is closed" in str(exc):
                return None
            raise

    def _logging_callback(load):
        self.dump(load, 'PUB', 'on_recv')
        result = callback(load)
        if inspect.isawaitable(result):
            async def _await_result():
                await result
            tornado.ioloop.IOLoop.current().spawn_callback(_await_result)
    try:
        return self._original_on_recv(_logging_callback)
    except OSError as exc:
        if "Stream is closed" in str(exc):
            return None
        raise
