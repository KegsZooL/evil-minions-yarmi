'''Implements one evil minion'''

from copy import deepcopy
import fnmatch
import hashlib
import ipaddress
import logging
import os
import socket
import time
from collections import OrderedDict
from uuid import UUID, uuid5

import tornado.gen
import zmq

import salt.channel.client

from evilminions.utils import replace_recursively, fun_call_id_variants


def _jid_key_from_pub(load):
    j = load.get('jid')
    if j is None:
        inner = load.get('load')
        if isinstance(inner, dict):
            j = inner.get('jid')
    if j is None:
        return None
    return str(j)


def _primary_master_host(opts):
    m = opts.get('master') if isinstance(opts, dict) else None
    if isinstance(m, (list, tuple)) and m:
        m = m[0]
    if m is None:
        return None
    s = str(m).strip()
    return s or None


def _ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def _salt_server_id_from_minion_id(minion_id):
    src = str(minion_id or '')
    hash_ = int(hashlib.sha256(src.encode('utf-8')).hexdigest(), 16)
    return abs(hash_ % (2**31))


def _outgoing_ipv4_towards_master(host, port=4506):
    if not host:
        return None
    try:
        mip = socket.gethostbyname(host)
    except socket.gaierror:
        return None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((mip, port))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def _is_loopback_iface(name):
    n = (name or '').lower()
    return (
        n in ('lo', 'loopback')
        or n.startswith(('lo.', 'lo:'))
        or (len(n) > 2 and n.startswith('lo') and n[2:].isdigit())
    )


def _is_ipv4_string(value):
    if not isinstance(value, str):
        return False
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _apply_real_ipv4_to_network_grains(grains, real_ip):
    if not isinstance(grains, dict) or not real_ip:
        return

    if 'fqdn_ip4' in grains:
        grains['fqdn_ip4'] = [real_ip]

    if isinstance(grains.get('ipv4'), list):
        lo = [x for x in grains['ipv4'] if isinstance(x, str) and x.startswith('127.')]
        grains['ipv4'] = [real_ip] + [x for x in lo if x != real_ip]

    ip4 = grains.get('ip4_interfaces')
    if isinstance(ip4, dict):
        grains['ip4_interfaces'] = {
            ifn: (addrs if isinstance(addrs, list) else [addrs]) if _is_loopback_iface(ifn) else [real_ip]
            for ifn, addrs in ip4.items()
        }

    ipif = grains.get('ip_interfaces')
    if isinstance(ipif, dict):
        out = {}
        for ifn, addrs in ipif.items():
            if not isinstance(addrs, list):
                out[ifn] = addrs
            elif _is_loopback_iface(ifn):
                out[ifn] = addrs
            else:
                out[ifn] = [real_ip] + [a for a in addrs if not _is_ipv4_string(a)]
        grains['ip_interfaces'] = out


class HydraHead(object):
    def __init__(self, minion_id, io_loop, keysize, opts, grains, ramp_up_delay, slowdown_factor, reactions, reactions_by_jid,
                 mimic_poll_interval=0.05, grains_profile=None):
        self.minion_id = minion_id
        self.io_loop = io_loop
        self.ramp_up_delay = ramp_up_delay
        self.slowdown_factor = slowdown_factor
        self.reactions = reactions
        self.reactions_by_jid = reactions_by_jid
        self.mimic_poll_interval = mimic_poll_interval
        self.current_time = 0
        self.grains_profile = self._build_effective_grains_profile(grains, grains_profile)
        self.log = logging.getLogger(__name__)
        self._apply_real_ip_network_overlay(opts)

        self.current_jobs = []
        self.pub_channel = None
        self._seen_returns = OrderedDict()
        self._dedup_ttl_sec = float(os.environ.get('EVIL_MINIONS_DEDUP_TTL_SEC', '180'))
        self._dedup_max = int(os.environ.get('EVIL_MINIONS_DEDUP_MAX', '30000'))

        self.replacements = {grains['id']: minion_id}
        machine_id = grains.get('machine_id')
        if machine_id:
            self.replacements[machine_id] = hashlib.md5(minion_id.encode('utf-8')).hexdigest()
        uuid_value = grains.get('uuid')
        if uuid_value:
            self.replacements[uuid_value] = str(uuid5(UUID('d77ed710-0deb-47d9-b053-f2fa2ef78106'), minion_id))

        self.opts = deepcopy(opts)
        self.opts['id'] = minion_id
        primary_master = _primary_master_host(self.opts)
        if primary_master:
            self.opts['master'] = primary_master

        self.opts['master_uri'] = 'tcp://%s:4506' % self.opts['master']
        self.opts['master_ip'] = socket.gethostbyname(self.opts['master'])

        pki_base = os.environ.get('EVIL_MINIONS_PKI_BASE', '/var/lib/evil-minions/pki')
        pki_dir = os.path.join(pki_base, minion_id)
        try:
            _ensure_dir(pki_dir)
        except OSError as exc:
            self.log.warning(
                "Unable to create persistent pki_dir '%s' (%s), falling back to /tmp",
                pki_dir,
                exc,
            )
            pki_dir = '/tmp/%s' % minion_id
            _ensure_dir(pki_dir)

        cache_dir = os.path.join(pki_dir, 'cache', 'minion')
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)

        sock_dir = os.path.join(pki_dir, 'sock', 'minion')
        if not os.path.exists(sock_dir):
            os.makedirs(sock_dir)

        self.opts['pki_dir'] = pki_dir
        self.opts['sock_dir'] = sock_dir
        self.opts['cache_dir'] = cache_dir

        self.opts['keysize'] = keysize
        self.opts['acceptance_wait_time'] = 10
        self.opts['acceptance_wait_time_max'] = 0
        self.opts['auth_tries'] = 600
        self.opts['zmq_filtering'] = False
        self.opts['tcp_keepalive'] = True
        self.opts['tcp_keepalive_idle'] = 300
        self.opts['tcp_keepalive_cnt'] = -1
        self.opts['tcp_keepalive_intvl'] = -1
        self.opts['recon_max'] = 10000
        self.opts['recon_default'] = 1000
        self.opts['recon_randomize'] = True
        self.opts['ipv6'] = False
        self.opts['zmq_monitor'] = False
        self.opts['open_mode'] = False
        self.opts['verify_master_pubkey_sign'] = False
        self.opts['always_verify_signature'] = False

    def _build_effective_grains_profile(self, grains, grains_profile):
        effective = deepcopy(grains_profile) if isinstance(grains_profile, dict) else deepcopy(grains)
        real_master = grains.get('master') if isinstance(grains, dict) else None
        if real_master:
            effective['master'] = real_master
        else:
            effective.pop('master', None)
        effective['server_id'] = _salt_server_id_from_minion_id(self.minion_id)
        return effective

    def _apply_real_ip_network_overlay(self, opts):
        if os.environ.get('EVIL_MINIONS_REAL_IP_OVERLAY', 'true').strip().lower() in ('0', 'false', 'no'):
            return
        master_host = _primary_master_host(opts)
        real_ip = _outgoing_ipv4_towards_master(master_host)
        if not real_ip:
            self.log.warning(
                "Minion %s: no outgoing IPv4 to master %s; presence may skip this minion",
                self.minion_id,
                master_host,
            )
            return
        _apply_real_ipv4_to_network_grains(self.grains_profile, real_ip)
        self.log.debug(
            "Minion %s: grains network IPv4 -> %s (master %s)",
            self.minion_id,
            real_ip,
            master_host,
        )

    @tornado.gen.coroutine
    def start(self):
        yield tornado.gen.sleep(self.ramp_up_delay)
        self.log.info("HydraHead %s started", self.opts['id'])

        factory_kwargs = {'timeout': 60, 'safe': True, 'io_loop': self.io_loop}
        self.pub_channel = salt.channel.client.AsyncPubChannel.factory(self.opts, **factory_kwargs)
        self.tok = self.pub_channel.auth.gen_token(b'salt')
        yield self.pub_channel.connect()
        self.req_channel = salt.channel.client.AsyncReqChannel.factory(self.opts, **factory_kwargs)
        self.pub_channel.on_recv(self.mimic)
        self.io_loop.spawn_callback(self.emit_pillar_cache_warmup)
        self.io_loop.spawn_callback(self.emit_start_event)
        yield self.mimic({'load': {'fun': None, 'arg': None, 'tgt': [self.minion_id],
                                  'tgt_type': 'list', 'load': None, 'jid': None}})

    @tornado.gen.coroutine
    def emit_pillar_cache_warmup(self):
        request = {
            'cmd': '_pillar',
            'id': self.minion_id,
            'grains': self.grains_profile,
            'saltenv': self.opts.get('saltenv', 'base'),
            'pillarenv': self.opts.get('pillarenv'),
            'pillar_override': {},
            'extra_minion_data': {},
            'ver': '2',
        }
        try:
            yield self.req_channel.send(request, timeout=60)
        except Exception as exc:
            self.log.warning("Pillar warmup failed for %s: %s", self.minion_id, exc)

    @tornado.gen.coroutine
    def emit_start_event(self):
        tag = 'salt/minion/{}/start'.format(self.minion_id)
        ts = int(time.time())
        request = {
            'cmd': '_minion_event',
            'id': self.minion_id,
            'pretag': None,
            'data': 'Minion {} started at {}'.format(self.minion_id, time.strftime('%a %b %d %H:%M:%S %Y')),
            'tag': tag,
            'ts': ts,
        }
        yield self.req_channel.send(request, timeout=60)

    @tornado.gen.coroutine
    def mimic(self, load):
        '''Finds appropriate reactions to a PUB message and dispatches them'''
        load = load.get('load')
        if not isinstance(load, dict):
            return
        fun = load.get('fun')
        tgt = load.get('tgt')
        tgt_type = load.get('tgt_type')

        if tgt_type == 'glob':
            is_targeted = bool(tgt) and fnmatch.fnmatch(self.minion_id, tgt)
        elif tgt_type == 'list':
            if isinstance(tgt, str):
                is_targeted = self.minion_id == tgt
            elif isinstance(tgt, (list, tuple)) and len(tgt) > 256:
                try:
                    is_targeted = self.minion_id in frozenset(tgt)
                except TypeError:
                    is_targeted = self.minion_id in tgt
            elif isinstance(tgt, (list, tuple)):
                is_targeted = self.minion_id in tgt
            else:
                is_targeted = False
        else:
            is_targeted = tgt == self.minion_id

        if not is_targeted:
            return

        if fun is None:
            return

        if fun == 'test.ping':
            yield self.react_to_ping(load)
        elif fun == 'grains.items':
            yield self.react_to_grains_items(load)
        elif fun == 'grains.item':
            yield self.react_to_grains_item(load)
        elif fun == 'grains.get':
            yield self.react_to_grains_get(load)
        elif fun == 'saltutil.find_job':
            yield self.react_to_find_job(load)
        elif fun == 'saltutil.running':
            yield self.react_to_running(load)
        else:
            call_ids = []
            _seen = set()
            for args in (load.get('arg'), load.get('fun_args')):
                if args is None:
                    continue
                for cid in fun_call_id_variants(load['fun'], args):
                    if cid not in _seen:
                        _seen.add(cid)
                        call_ids.append(cid)
            jid_key = _jid_key_from_pub(load)

            self.log.debug(
                "Minion %s mimic: fun=%s arg=%r fun_args=%r jid=%s call_ids=%s",
                self.minion_id, fun, load.get('arg'), load.get('fun_args'), jid_key, call_ids,
            )
            if self.log.isEnabledFor(logging.DEBUG):
                self.log.debug(
                    "Minion %s reactions store: total_keys=%d fun_matching_keys=%s",
                    self.minion_id,
                    len(self.reactions),
                    [k for k in self.reactions if k[0] == fun],
                )

            reactions = None
            raw_to = load.get('to')
            try:
                wait_timeout = float(raw_to) if raw_to is not None else 10.0
            except (TypeError, ValueError):
                wait_timeout = 10.0
            deadline = time.time() + max(1.0, min(wait_timeout, 30.0))

            while time.time() < deadline:
                if jid_key and jid_key in self.reactions_by_jid:
                    reactions = self.reactions_by_jid[jid_key]
                    self.log.debug("Minion %s mimic: found reaction via jid=%s", self.minion_id, jid_key)
                    break
                for cid in call_ids:
                    reactions = self.get_reactions(cid)
                    if reactions:
                        self.log.debug("Minion %s mimic: found reaction via call_id=%s", self.minion_id, cid)
                        break
                if reactions:
                    break
                yield tornado.gen.sleep(self.mimic_poll_interval)

            if not reactions:
                self.log.error(
                    "Minion %s no reaction for fun=%s call_ids=%s jid=%s; "
                    "all_stored_keys_for_fun=%s reactions_by_jid_keys=%s",
                    self.minion_id, fun, call_ids, jid_key,
                    [k for k in self.reactions if k[0] == fun],
                    list(self.reactions_by_jid.keys()),
                )
                yield self.react_no_reaction(load)
                return

            self.current_time = reactions[0]['header']['time']
            yield self.react(load, reactions, pub_call_ids=set(call_ids))

    def get_reactions(self, call_id):
        reaction_sets = self.reactions.get(call_id)
        if not reaction_sets:
            return None

        future_reaction_sets = [s for s in reaction_sets if s[0]['header']['time'] >= self.current_time]
        if future_reaction_sets:
            return max(future_reaction_sets, key=lambda s: s[0]['header']['time'])

        return reaction_sets[-1]

    @tornado.gen.coroutine
    def react(self, load, original_reactions, pub_call_ids=None):
        self.current_jobs.append(load)
        try:
            reactions = replace_recursively(self.replacements, original_reactions)

            if pub_call_ids is None:
                pub_call_ids = set()
                for args in (load.get('arg'), load.get('fun_args')):
                    if args is None:
                        continue
                    for cid in fun_call_id_variants(load['fun'], args):
                        pub_call_ids.add(cid)

            for reaction in reactions:
                request = reaction['load']
                if 'tok' in request:
                    request['tok'] = self.tok
                if request['cmd'] == '_return' and request.get('fun') == load.get('fun'):
                    r_args = request.get('fun_args') or request.get('arg') or []
                    ret_ids = set(fun_call_id_variants(request.get('fun'), r_args))
                    if pub_call_ids and not (pub_call_ids & ret_ids):
                        continue
                    request['jid'] = load['jid']
                    if 'metadata' in load and isinstance(request.get('metadata'), dict):
                        request['metadata']['suma-action-id'] = load['metadata'].get('suma-action-id')
                header = reaction['header']
                duration = header['duration']
                yield tornado.gen.sleep(duration * self.slowdown_factor)
                method = header['method']
                kwargs = header['kwargs']
                if request.get('cmd') == '_return':
                    yield self._send_return(request, timeout=kwargs.get('timeout', 60))
                    continue
                yield getattr(self.req_channel, method)(request, **kwargs)
        finally:
            try:
                self.current_jobs.remove(load)
            except ValueError:
                pass

    def _should_drop_duplicate_return(self, request):
        '''
        Dedup _return only when jid is present.
        If jid is empty/None, do not dedup.
        '''
        jid = request.get('jid')
        if jid is None or jid == '':
            return False

        now = time.time()
        self._prune_seen_returns(now)
        dedup_key = (self.minion_id, str(jid))
        if dedup_key in self._seen_returns:
            self.log.debug("Drop duplicate _return for minion=%s jid=%s", self.minion_id, jid)
            return True

        self._seen_returns[dedup_key] = now
        self._seen_returns.move_to_end(dedup_key)
        if len(self._seen_returns) > self._dedup_max:
            self._seen_returns.popitem(last=False)
        return False

    def _prune_seen_returns(self, now):
        if not self._seen_returns:
            return
        ttl = max(1.0, self._dedup_ttl_sec)
        while self._seen_returns:
            _, ts = next(iter(self._seen_returns.items()))
            if now - ts <= ttl:
                break
            self._seen_returns.popitem(last=False)

    @tornado.gen.coroutine
    def _send_return(self, request, timeout=60):
        '''Send _return through a single dedup-aware path.'''
        if request.get('cmd') == '_return' and self._should_drop_duplicate_return(request):
            return
        yield self.req_channel.send(request, timeout=timeout)

    @tornado.gen.coroutine
    def react_no_reaction(self, load):
        '''Returns an explicit error if no baseline reaction is available yet'''
        fun = load.get('fun')
        request = {
            'cmd': '_return',
            'fun': fun,
            'fun_args': load.get('arg') or load.get('fun_args') or [],
            'id': self.minion_id,
            'jid': load.get('jid'),
            'retcode': 1,
            'return': "evil-minions: no real-minion baseline response for '{}' yet; run the command once against a real minion and retry".format(fun),
            'success': False,
        }
        yield self._send_return(request, timeout=60)

    @tornado.gen.coroutine
    def react_to_ping(self, load):
        '''Dispatches a reaction to a ping call'''
        request = {
            'cmd': '_return',
            'fun': load['fun'],
            'fun_args': load['arg'],
            'id': self.minion_id,
            'jid': load['jid'],
            'retcode': 0,
            'return': True,
            'success': True,
        }
        yield self._send_return(request, timeout=60)

    @tornado.gen.coroutine
    def react_to_grains_items(self, load):
        request = {
            'cmd': '_return',
            'fun': load['fun'],
            'fun_args': load['arg'],
            'id': self.minion_id,
            'jid': load['jid'],
            'retcode': 0,
            'return': self.grains_profile,
            'success': True,
        }
        yield self._send_return(request, timeout=60)

    @tornado.gen.coroutine
    def react_to_grains_item(self, load):
        args = load.get('arg') or []
        result = {}
        for key in args:
            result[key] = self.grains_profile.get(key)
        request = {
            'cmd': '_return',
            'fun': load['fun'],
            'fun_args': args,
            'id': self.minion_id,
            'jid': load['jid'],
            'retcode': 0,
            'return': result,
            'success': True,
        }
        yield self._send_return(request, timeout=60)

    @tornado.gen.coroutine
    def react_to_grains_get(self, load):
        args = load.get('arg') or []
        key = args[0] if args else None
        default = args[1] if len(args) > 1 else ''
        value = self._grains_get_value(key, default)
        request = {
            'cmd': '_return',
            'fun': load['fun'],
            'fun_args': args,
            'id': self.minion_id,
            'jid': load['jid'],
            'retcode': 0,
            'return': value,
            'success': True,
        }
        yield self._send_return(request, timeout=60)

    def _grains_get_value(self, key, default=''):
        if key is None:
            return default
        value = self.grains_profile
        for part in str(key).split(':'):
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default
        return value

    @tornado.gen.coroutine
    def react_to_find_job(self, load):
        '''Dispatches a reaction to a find_job call'''
        target_jid = (load.get('arg') or [None])[0]
        jobs = [j for j in self.current_jobs if j['jid'] == target_jid] if target_jid else []
        ret = {**jobs[0], 'pid': 1234} if jobs else {}

        request = {
            'cmd': '_return',
            'fun': load['fun'],
            'fun_args': load['arg'],
            'id': self.minion_id,
            'jid': load['jid'],
            'retcode': 0,
            'return': ret,
            'success': True,
        }
        yield self._send_return(request, timeout=60)

    @tornado.gen.coroutine
    def react_to_running(self, load):
        '''Dispatches a reaction to a running call'''
        request = {
            'cmd': '_return',
            'fun': load['fun'],
            'fun_args': load['arg'],
            'id': self.minion_id,
            'jid': load['jid'],
            'retcode': 0,
            'return': self.current_jobs,
            'success': True,
        }
        yield self._send_return(request, timeout=60)
