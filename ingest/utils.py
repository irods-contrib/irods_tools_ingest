import json
import re
import io
import os
import hashlib
import base64
from abc import ABCMeta, abstractmethod
import irods.keywords as kw
from irods.password_obfuscation import decode


class IrodsChecksum(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self):
        pass

    def update(self, data):
        self._hasher.update(data)

    def digest(self):
        return self._hasher.digest()

    def hexdigest(self):
        return self._hasher.hexdigest()

    @abstractmethod
    def irods_digest(self):
        pass

    @abstractmethod
    def verify(self, obj):
        pass


class SHA256Checksum(IrodsChecksum):
    def __init__(self):
        self._hasher = hashlib.sha256()

    def irods_digest(self):
        return base64.b64encode(self._hasher.digest()).decode()

    def verify(self, obj):
        assert obj.checksum == "sha2:{0}".format(self.irods_digest())


class MD5Checksum(IrodsChecksum):
    def __init__(self):
        self._hasher = hashlib.md5()

    def irods_digest(self):
        return self._hasher.hexdigest()

    def verify(self, obj):
        assert obj.checksum == self.irods_digest()


def get_irods_hasher(parsed_args):
    try:
        hash_scheme = parsed_args.irods_environment['irods_default_hash_scheme']
    except KeyError:
        hash_scheme = 'SHA256'

    if hash_scheme.upper() == 'SHA256':
        return SHA256Checksum()

    if hash_scheme.upper() == 'MD5':
        return MD5Checksum()

    raise ValueError('{0} is not a supported hash scheme'.format(hash_scheme))


def set_options_from_args(parsed_args):
    options = {kw.OPR_TYPE_KW: 1}   # PUT_OPR

    if parsed_args.register_checksum:
        options[kw.REG_CHKSUM_KW] = ''

    return options


def send_file(session, file_path, obj_path, parsed_args):
    options = set_options_from_args(parsed_args)

    if parsed_args.verify_checksum:
        options[kw.REG_CHKSUM_KW] = ''
        send_chunks_and_compute_checksum(session, file_path, obj_path, parsed_args, options)
        return

    send_chunks(session, file_path, obj_path, parsed_args, options)


def chunks(f, chunksize=io.DEFAULT_BUFFER_SIZE):
    return iter(lambda: f.read(chunksize), b'')


def send_chunks(session, file_path, obj_path, parsed_args, options):
    with open(file_path, 'rb') as f, session.data_objects.open(obj_path, 'w', options) as o:
        for chunk in chunks(f, parsed_args.buffer_size):
            o.write(chunk)


def send_chunks_and_compute_checksum(session, file_path, obj_path, parsed_args, options):

    hasher = get_irods_hasher(parsed_args)

    with open(file_path, 'rb') as f, session.data_objects.open(obj_path, 'w', options) as o:
        for chunk in chunks(f, parsed_args.buffer_size):
            o.write(chunk)
            hasher.update(chunk)

    obj = session.data_objects.get(obj_path)
    hasher.verify(obj)


def irods_dest_path(path, parsed_args):
    '''
    Determines an iRODS destination path.
    Used by worker function.
    '''

    # in future use dest coll if provided
    irods_cwd = "/{irods_zone_name}/home/{irods_user_name}".format(
        **parsed_args.irods_environment)

    relative_path = os.path.relpath(path, parsed_args.prefix)
    return os.path.join(irods_cwd, relative_path)


def exclude(path, parsed_args):
    '''
    Returns True if path matches exclusion regex.
    '''

    if parsed_args.exclude is None:
        return False

    p = re.compile(parsed_args.exclude)
    return p.match(path)


def get_irods_env(env_file):
    with open(env_file, 'rt') as f:
        return json.load(f)


def get_irods_auth(env):
    try:
        irods_auth_file = env['irods_authentication_file']
    except KeyError:
        irods_auth_file = os.path.expanduser('~/.irods/.irodsA')

    with open(irods_auth_file, 'r') as f:
        return decode(f.read().rstrip('\n'))
