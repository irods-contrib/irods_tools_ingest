import json
import re
import io
import os
import irods.keywords as kw
from irods.password_obfuscation import decode


def chunks(f, chunksize=io.DEFAULT_BUFFER_SIZE):
    return iter(lambda: f.read(chunksize), b'')


def put_file(session, file_path, obj_path, args):
    options = {}

    if args.register_checksum:
        options[kw.REG_CHKSUM_KW] = ''

    with open(file_path, 'rb') as f, session.data_objects.open(obj_path, 'w', options) as o:
        for chunk in chunks(f, args.buffer_size):
            o.write(chunk)


def irods_dest_path(path, args):
    '''
    Determines an iRODS destination path.
    Used by worker function.
    '''

    # in future use dest coll if provided
    irods_cwd = "/{irods_zone_name}/home/{irods_user_name}".format(**args.irods_environment)

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
        return decode(f.read().rstrip('\n'))
