'''Replicates the behavior of a minion many times'''

import logging
import json
import math
import os
import random

import tornado.gen
import zmq
import zmq.eventloop.ioloop
import zmq.eventloop.zmqstream

import salt.config
import salt.loader
import salt.payload

from evilminions.hydrahead import HydraHead
from evilminions.utils import fun_call_id, fun_call_id_variants
from evilminions.worker_logging import setup as setup_worker_logging

_MAX_JID_REACTIONS = 10000
_MAX_CURRENT_REACTIONS = 2000
_CURRENT_REACTIONS_TTL = 300.0


class Hydra(object):
    def __init__(self, hydra_number):
        self.hydra_number = hydra_number
        self.current_reactions = {}
        self.reactions = {}
        self.reactions_by_jid = {}
        self.last_time = None
        self.log = None
        self._profiles = None
        self._profile_mul = None
        self._profile_add = 17
        self._assigned_minion_ids = set()
        self._id_source = None
        self._enforce_unique = None

    def start(self, hydra_count, chunk,
              ramp_up_delay, slowdown_factor, random_slowdown_factor, keysize,
              mimic_poll_interval, semaphore):
        self._id_source = os.environ.get('EVIL_MINIONS_ID_SOURCE', 'profile').strip().lower()
        self._enforce_unique = (
            os.environ.get('EVIL_MINIONS_ENFORCE_UNIQUE_IDS', 'true').strip().lower()
            not in ('0', 'false', 'no')
        )

        zmq.eventloop.ioloop.install()
        io_loop = zmq.eventloop.ioloop.ZMQIOLoop.current()

        context = zmq.Context()
        socket = context.socket(zmq.SUB)
        socket.connect('ipc:///tmp/evil-minions-pub.ipc')
        socket.setsockopt_string(zmq.SUBSCRIBE, "")
        stream = zmq.eventloop.zmqstream.ZMQStream(socket, io_loop)
        stream.on_recv(self.update_reactions)

        setup_worker_logging()
        self.log = logging.getLogger(__name__)

        opts = salt.config.minion_config('/etc/salt/minion')
        grains = salt.loader.grains(opts)
        self._load_grains_profiles()
        self.log.debug("Starting Hydra on: %s", chunk)

        first_head_number = chunk[0] if chunk else 0
        delays = [
            ramp_up_delay * ((head_number - first_head_number) * hydra_count + self.hydra_number)
            for head_number in chunk
        ]
        if self._profiles and chunk and (max(chunk) + 1) > len(self._profiles):
            self.log.warning(
                "Profiles count (%d) is lower than requested evil minions (%d); profile reuse is expected",
                len(self._profiles), max(chunk) + 1
            )

        slowdown_factors = self._resolve_slowdown_factors(slowdown_factor, random_slowdown_factor, len(chunk))
        heads = []
        for i, head_number in enumerate(chunk):
            generated_id = 'evil-{}'.format(head_number)
            grains_profile = self._pick_grains_profile(head_number)
            minion_id = self._resolve_minion_id(head_number, generated_id, grains_profile)
            heads.append(
                HydraHead(
                    minion_id, io_loop, keysize, opts, grains, delays[i],
                    slowdown_factors[i], self.reactions, self.reactions_by_jid,
                    grains_profile=grains_profile,
                    mimic_poll_interval=mimic_poll_interval
                )
            )

        for head in heads:
            io_loop.spawn_callback(head.start)

        semaphore.release()

        io_loop.start()

    def _resolve_slowdown_factors(self, slowdown_factor, random_slowdown_factor, heads_count):
        random.seed(self.hydra_number)
        return [
            slowdown_factor + random.randint(0, random_slowdown_factor * 100) / 100.0
            for _ in range(heads_count)
        ]

    def _load_grains_profiles(self):
        if self._profiles is not None:
            return
        env_path = os.environ.get('EVIL_MINIONS_GRAINS_PROFILES')
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidate_paths = []
        if env_path:
            candidate_paths.append(env_path)
        candidate_paths.extend([
            os.path.join(os.getcwd(), 'data', 'grains.json'),
            os.path.join(repo_root, 'data', 'grains.json'),
            '/opt/evil-minions/data/grains.json',
        ])
        seen = set()
        unique_paths = []
        for p in candidate_paths:
            if not p or p in seen:
                continue
            seen.add(p)
            unique_paths.append(p)

        loaded_from = None
        last_exc = None
        loaded = None
        for path in unique_paths:
            if not os.path.exists(path):
                continue
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                loaded_from = path
                break
            except Exception as exc:
                last_exc = exc

        try:
            if isinstance(loaded, list):
                self._profiles = [x for x in loaded if isinstance(x, dict)]
            else:
                self._profiles = []
        except Exception:
            self._profiles = []

        if self._profiles:
            m = len(self._profiles)
            mul = 65537
            while math.gcd(mul, m) != 1:
                mul += 2
            self._profile_mul = mul
            self.log.info("Loaded %d grains profiles from %s", m, loaded_from)
        else:
            self._profile_mul = None
            if loaded_from:
                self.log.warning("Grains profiles file found but empty/invalid list: %s", loaded_from)
            elif last_exc is not None:
                self.log.warning("Unable to parse grains profiles from candidates %s: %s", unique_paths, last_exc)
            else:
                self.log.warning("Grains profiles file not found in candidates: %s", unique_paths)

            strict = os.environ.get('EVIL_MINIONS_REQUIRE_GRAINS_PROFILES', 'true').strip().lower()
            if strict not in ('0', 'false', 'no'):
                raise RuntimeError(
                    "No grains profiles loaded; refusing to fallback to real host grains. "
                    "Set EVIL_MINIONS_GRAINS_PROFILES or disable strict mode with "
                    "EVIL_MINIONS_REQUIRE_GRAINS_PROFILES=0."
                )

    def _pick_grains_profile(self, head_number):
        if not self._profiles or self._profile_mul is None:
            return None
        m = len(self._profiles)
        idx = (self._profile_mul * head_number + self._profile_add) % m
        return self._profiles[idx]

    def _resolve_minion_id(self, head_number, generated_id, grains_profile):
        profile_id = None
        if isinstance(grains_profile, dict):
            profile_id = grains_profile.get('id')
            if profile_id is not None:
                profile_id = str(profile_id).strip()
                if profile_id == '':
                    profile_id = None

        if self._id_source == 'profile' and profile_id:
            candidate = profile_id
        else:
            candidate = generated_id

        if self._enforce_unique and candidate in self._assigned_minion_ids:
            candidate = '{}-evil-{}'.format(candidate, head_number)
            self.log.warning("Duplicate minion id detected, adjusted to %s", candidate)

        self._assigned_minion_ids.add(candidate)
        return candidate

    def _prune_current_reactions(self, current_time):
        if len(self.current_reactions) <= _MAX_CURRENT_REACTIONS:
            return
        stale = [
            pid for pid, events in self.current_reactions.items()
            if isinstance(pid, int) and events
            and (current_time - events[-1]['header']['time']) > _CURRENT_REACTIONS_TTL
        ]
        for pid in stale:
            del self.current_reactions[pid]

    @tornado.gen.coroutine
    def update_reactions(self, packed_events):
        for packed_event in packed_events:
            event = salt.payload.loads(packed_event)

            load = event['load']
            socket = event['header']['socket']
            current_time = event['header']['time']
            self.last_time = self.last_time or current_time

            if socket == 'PUB' and not self.reactions:
                initial_reactions = [
                    reaction
                    for pid, reactions in self.current_reactions.items()
                    for reaction in reactions
                ]
                self.reactions[fun_call_id(None, None)] = [initial_reactions]
                self.last_time = current_time

                self.log.debug(
                    "Hydra #{} learned initial reaction list ({} reactions)".format(
                        self.hydra_number, len(initial_reactions)
                    )
                )
                for reaction in initial_reactions:
                    cmd = reaction['load']['cmd']
                    pid_str = "pid={}".format(reaction['header']['pid'])
                    self.log.debug(" - {}({})".format(cmd, pid_str))

            if socket == 'REQ':
                if load['cmd'] in ('_auth', '_minion_event'):
                    self.last_time = current_time
                    continue
                pid = event['header']['pid']

                self.current_reactions[pid] = self.current_reactions.get(pid, []) + [event]

                if load['cmd'] == '_return':
                    orig_pid = pid
                    chain = self.current_reactions[orig_pid]
                    call_ids = set()
                    self.log.debug(
                        "Hydra #%d learning _return: fun=%s fun_args=%r arg=%r jid=%s pid=%s",
                        self.hydra_number, load.get('fun'), load.get('fun_args'), load.get('arg'),
                        load.get('jid'), orig_pid,
                    )
                    for args in (load.get('fun_args'), load.get('arg')):
                        if args is None:
                            continue
                        for cid in fun_call_id_variants(load['fun'], args):
                            call_ids.add(cid)
                    self.log.debug(
                        "Hydra #%d storing reaction for fun=%s call_ids=%s jid=%s chain_len=%d",
                        self.hydra_number, load.get('fun'), list(call_ids), load.get('jid'), len(chain),
                    )
                    for call_id in call_ids:
                        if call_id not in self.reactions:
                            self.reactions[call_id] = []
                        self.reactions[call_id].append(chain)
                    jid = load.get('jid')
                    if jid is not None:
                        self.reactions_by_jid[str(jid)] = chain
                        while len(self.reactions_by_jid) > _MAX_JID_REACTIONS:
                            self.reactions_by_jid.pop(next(iter(self.reactions_by_jid)))
                    self.log.debug(
                        "Hydra #{} learned reaction list ({} reactions) for fun {}".format(
                            self.hydra_number, len(chain), load.get('fun')
                        )
                    )
                    for _rxn in self.current_reactions[orig_pid]:
                        _rxn_load = _rxn['load']
                        _path = "path={} ".format(_rxn_load['path']) if 'path' in _rxn_load else ''
                        _pid_str = "pid={}".format(_rxn['header']['pid'])
                        self.log.debug(" - {}({}{})".format(_rxn_load['cmd'], _path, _pid_str))

                    self.current_reactions[orig_pid] = []
                    self._prune_current_reactions(current_time)

                event['header']['duration'] = current_time - self.last_time
                self.last_time = current_time
