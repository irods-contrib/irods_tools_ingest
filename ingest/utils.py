import json
import re
import io
import os
import hashlib
import base64
import logging
from abc import ABCMeta, abstractmethod
import irods.keywords as kw
import irods.password_obfuscation as obf
import irods.exception as ex
import config


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


def get_irods_hasher(args):
    try:
        hash_scheme = args.irods_environment['irods_default_hash_scheme']
    except KeyError:
        hash_scheme = 'SHA256'

    if hash_scheme.upper() == 'SHA256':
        return SHA256Checksum()

    if hash_scheme.upper() == 'MD5':
        return MD5Checksum()

    raise ValueError('{0} is not a supported hash scheme'.format(hash_scheme))


def get_metadata(attributes=config.TEST_METADATA):
    meta_str = ""
    for attribute in attributes:
        try:
            meta_str += "{0};{1};{2};".format(*attribute)
        except IndexError:
            meta_str += "{0};{1};;".format(*attribute)

    return meta_str


def get_acls(acls=config.TEST_ACLS):
    return ";".join(["{0} {1}".format(*acl) for acl in acls])


def set_options_from_args(args):
    options = {kw.OPR_TYPE_KW: 1}   # PUT_OPR

    if args.register_checksum:
        options[kw.REG_CHKSUM_KW] = ''

    if args.metadata:
        options[kw.METADATA_INCLUDED_KW] = get_metadata()

    if args.acl:
        options[kw.ACL_INCLUDED_KW] = get_acls()

    return options


def send_file(session, file_path, obj_path, args):
    '''
    Main function for sending a file to iRODS
    '''

    if not args.force:
        try:
            # check if target is already there
            # avoid checksum if possible. size? ts? investigate sync mechanisms...
            # simple presence check for now
            obj = session.data_objects.get(obj_path)
            logging.info("skipping {0} (exists)".format(file_path))
            return
        except ex.DataObjectDoesNotExist:
            pass

    logging.info("uploading {0} as {1}".format(file_path, obj_path))

    options = set_options_from_args(args)

    if args.verify_checksum:
        options[kw.REG_CHKSUM_KW] = ''
        send_chunks_and_compute_checksum(session, file_path, obj_path, args, options)
        return

    send_chunks(session, file_path, obj_path, args, options)


def chunks(f, chunksize=io.DEFAULT_BUFFER_SIZE):
    return iter(lambda: f.read(chunksize), b'')


def send_chunks(session, file_path, obj_path, args, options):
    with open(file_path, 'rb') as f, session.data_objects.open(obj_path, 'w', options) as o:
        for chunk in chunks(f, args.buffer_size):
            o.write(chunk)


def send_chunks_and_compute_checksum(session, file_path, obj_path, args, options):

    hasher = get_irods_hasher(args)

    with open(file_path, 'rb') as f, session.data_objects.open(obj_path, 'w', options) as o:
        for chunk in chunks(f, args.buffer_size):
            o.write(chunk)
            hasher.update(chunk)

    obj = session.data_objects.get(obj_path)
    hasher.verify(obj)


def make_collection(session, target, args):
    try:
        session.collections.create(target)
    except ex.CATALOG_ALREADY_HAS_ITEM_BY_THAT_NAME:
        # TODO: if args.force, force create to update timestamp
        pass


def irods_dest_path(path, args):
    '''
    Determines an iRODS destination path.
    Used by worker function.
    '''

    # in future use dest coll if provided
    irods_cwd = "/{irods_zone_name}/home/{irods_user_name}".format(
        **args.irods_environment)

    relative_path = os.path.relpath(path, args.prefix)
    return os.path.join(irods_cwd, relative_path)


def exclude(path, args):
    '''
    Returns True if path matches exclusion regex.
    '''

    if args.exclude is None:
        return False

    p = re.compile(args.exclude)
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
        return obf.decode(f.read().rstrip('\n'))
