'''Various utility functions'''

import logging

_log = logging.getLogger(__name__)

_NOISY_KEYS = frozenset({
    '__pub_arg',
    '__pub_fun',
    '__pub_fun_args',
    '__pub_id',
    '__pub_jid',
    '__pub_pid',
    '__pub_ret',
    '__pub_tgt',
    '__pub_tgt_type',
    '__pub_user',
    'jid',
    'pid',
    'metadata',
})


def replace_recursively(replacements, dump):
    if isinstance(dump, list):
        return [replace_recursively(replacements, e) for e in dump]
    if isinstance(dump, dict):
        return {k: replace_recursively(replacements, v) for k, v in dump.items()}
    if isinstance(dump, str):
        try:
            result = dump
            for original, new in replacements.items():
                result = result.replace(original, new)
            return result
        except UnicodeDecodeError:
            return dump
    if dump in replacements:
        return replacements[dump]
    return dump


def fun_call_id(fun, args):
    clean_args = [_zap_runtime_noise(_zap_uyuni_specifics(_zap_kwarg(arg))) for arg in args or []]
    result = (fun, _immutable(clean_args))
    if _log.isEnabledFor(logging.DEBUG):
        _log.debug("fun_call_id: fun=%s raw_args=%r -> clean_args=%r -> key=%r", fun, args, clean_args, result)
    return result


def fun_call_id_variants(fun, args):
    args = list(args or [])
    seen = set()
    variants = []
    while True:
        cid = fun_call_id(fun, args)
        if cid not in seen:
            seen.add(cid)
            variants.append(cid)
        if not args or not isinstance(args[-1], dict):
            break
        args = args[:-1]
    if _log.isEnabledFor(logging.DEBUG):
        _log.debug("fun_call_id_variants: fun=%s -> %d variants", fun, len(variants))
    return variants


def _zap_kwarg(arg):
    if isinstance(arg, dict):
        return {k: v for k, v in arg.items() if k != '__kwarg__'}
    return arg


def _zap_uyuni_specifics(data):
    if isinstance(data, dict):
        uyuni_repo = data.get('alias', '').startswith("susemanager:")
        if uyuni_repo:
            return {k: v for k, v in data.items() if k != 'token'}
        return {k: _zap_uyuni_specifics(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_zap_uyuni_specifics(e) for e in data]
    return data


def _zap_runtime_noise(data):
    if isinstance(data, dict):
        return {k: _zap_runtime_noise(v) for k, v in data.items() if k not in _NOISY_KEYS}
    if isinstance(data, list):
        return [_zap_runtime_noise(e) for e in data]
    return data


def _immutable(data):
    if isinstance(data, dict):
        return tuple((k, _immutable(v)) for k, v in sorted(data.items()))
    if isinstance(data, list):
        return tuple(_immutable(e) for e in data)
    return data
