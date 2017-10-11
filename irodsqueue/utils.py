import json
import sys
import re
import io
import os
import hashlib
import base64
import logging
import importlib
from abc import ABCMeta, abstractmethod
import time
import datetime
import irods.keywords as kw
import irods.password_obfuscation as obf
import irods.exception as ex
from irodsqueue import DEFAULT_HASH_SCHEME

from redis import Redis
from rq import Queue

from rq.utils import make_colorizer
from rq.connections import get_current_connection

yellow = make_colorizer('yellow')


logger = logging.getLogger('rq.worker')


class IrodsChecksum(metaclass=ABCMeta):

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
        assert obj.checksum == "sha2:{}".format(self.irods_digest())


class MD5Checksum(IrodsChecksum):
    def __init__(self):
        self._hasher = hashlib.md5()

    def irods_digest(self):
        return self._hasher.hexdigest()

    def verify(self, obj):
        assert obj.checksum == self.irods_digest()


def get_irods_hasher(params):
    try:
        hash_scheme = params.hash_scheme
    except AttributeError:
        hash_scheme = DEFAULT_HASH_SCHEME

    if hash_scheme.upper() == 'SHA256':
        return SHA256Checksum()

    if hash_scheme.upper() == 'MD5':
        return MD5Checksum()

    raise ValueError('{} is not a supported hash scheme'.format(hash_scheme))


def extract_metadata(path, options, params):
    module_name = 'irods_metadata_extract'

    try:
        # import from cache
        module = importlib.import_module(module_name)

    except ImportError:
        # load module from file
        spec = importlib.util.spec_from_file_location(module_name, params.extract_metadata)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # for subsequent imports
        sys.modules[module_name] = module

    # invoke metadata extraction function from module
    options[kw.METADATA_INCLUDED_KW] = module.extract_metadata(path=path)


def get_acls(acls=None):
    # testing, move to a unit test
    if not acls:
        acls = [('read', 'public')]

    return ";".join(["{} {}".format(*acl) for acl in acls])


def set_options_from_params(path, params):
    options = {kw.OPR_TYPE_KW: 1}   # PUT_OPR

    if params.register_checksum:
        options[kw.REG_CHKSUM_KW] = ''

    if params.extract_metadata:
        extract_metadata(path, options, params)

    if params.acl:
        options[kw.ACL_INCLUDED_KW] = get_acls()

    return options


def send_file(session, file_path, obj_path, params):
    '''
    Main function for sending a file to iRODS
    '''

    if not params.force:
        try:
            # check if target is already there
            # avoid checksum if possible. size? ts? investigate sync mechanisms...
            # simple presence check for now
            obj = session.data_objects.get(obj_path)
            logger.info("skipping {} (exists)".format(file_path))
            return
        except ex.DataObjectDoesNotExist:
            pass

    logger.info(yellow("process {} uploading {}".format(os.getpid(), obj_path)))

    options = set_options_from_params(file_path, params)

    if params.verify_checksum:
        options[kw.REG_CHKSUM_KW] = ''
        send_chunks_and_compute_checksum(
            session, file_path, obj_path, params, options)
        return

    send_chunks(session, file_path, obj_path, params, options)


def chunks(f, chunksize=io.DEFAULT_BUFFER_SIZE):
    return iter(lambda: f.read(chunksize), b'')


def send_chunks(session, file_path, obj_path, params, options):
    with open(file_path, 'rb') as f, session.data_objects.open(obj_path, 'w', **options) as o:
        for chunk in chunks(f, params.chunk_size):
            o.write(chunk)


def send_chunks_and_compute_checksum(session, file_path, obj_path, params, options):

    hasher = get_irods_hasher(params)

    with open(file_path, 'rb') as f, session.data_objects.open(obj_path, 'w', **options) as o:
        for chunk in chunks(f, params.chunk_size):
            o.write(chunk)
            hasher.update(chunk)

    obj = session.data_objects.get(obj_path)
    hasher.verify(obj)


def irods_dest_path(path, session, params):
    '''
    Determines an iRODS destination path.
    Used by worker function.
    '''

    # in future use dest coll if provided
    irods_cwd = "/{}/home/{}".format(session.zone, session.username)

    relative_path = os.path.relpath(path, params.prefix)
    return os.path.join(irods_cwd, relative_path)


def exclude(path, params):
    '''
    Returns True if path matches exclusion regex.
    '''

    if not params.exclude:
        return False

    p = re.compile(params.exclude)
    return p.match(path)


def dirs(path):
    '''
    Returns path and its parent directories.
    '''
    parent = os.path.dirname(path)

    if not parent:
        return [path]

    return dirs(parent) + [path]


def add_timer(conn, job_queue, last_job_id):
    '''
    Adds a timer to a job queue
    '''
    ts_id = conn.incr('ingest_start_ts_id')
    job_queue.enqueue(record_start_time, timestamp_id=ts_id, at_front=True)
    job_queue.enqueue(log_duration, timestamp_id=ts_id, queue_name=job_queue.name, depends_on=last_job_id)


def read_reg_input_file(params):
    # create queue
    conn = Redis()
    job_queue = Queue(name=params.queue_name, connection=conn)

    # collections that have already been created so far
    # include None to take care of the empty dirname case
    collections = {None}

    with open(params.input) as f:
        for line in f:
            try:
                relative_target =  os.path.relpath(line.strip(), start=params.prefix)
            except ValueError:
                continue

            # start with intermediate collections needed for this object
            collection = os.path.dirname(relative_target) or None

            # if collection has already been created, so have its parents
            if collection not in collections:

                for coll in dirs(collection):
                    if coll not in collections:

                        # parent collection dependency
                        parent = os.path.dirname(coll) or None

                        # enqueue job
                        job_queue.enqueue(create_collection, coll, params, job_id=coll,
                                          depends_on=parent, at_front=False, timeout='10s')

                        # mark as created
                        collections.add(coll)

            # now that potential dependencies are enqueued we can process the file
            job_queue.enqueue(register_file, relative_target, params,
                              job_id=relative_target, depends_on=collection, timeout='10s')

    #### for testing ####
    if params.timer:
        add_timer(conn, job_queue, relative_target)
    #####################


# move elsewhere at some point
def walk_local_dir(file_callback, dir_callback, params):
    # create queue
    conn = Redis()
    job_queue = Queue(name=params.queue_name, connection=conn)

    # put source path in the queue
    source = params.source
    job_queue.enqueue(dir_callback, source, params,
                      job_id=source, at_front=True)

    # crawl target directory and put entries in the queue
    for root, dirs, files in os.walk(source, topdown=True):

        for name in dirs:
            dir_path = os.path.join(root, name)
            job_queue.enqueue(dir_callback, dir_path, params, job_id=dir_path,
                              depends_on=root, at_front=True, timeout='10s')

        for name in files:
            file_path = os.path.join(root, name)
            job_queue.enqueue(file_callback, file_path, params,
                              job_id=file_path, depends_on=root, timeout='10m')

    #### for testing ####
    if params.timer:
        add_timer(conn, job_queue, file_path)
    #####################



#########################################
#### Functions used as jobs in queue ####
#########################################
def make_collection(path, params, session):

    target = irods_dest_path(path, session, params)

    if exclude(path, params):
        logger.info("skipping {} (--exclude)".format(path))
        return

    logger.info(yellow("process {} creating {}".format(os.getpid(), target)))

    if not params.dry_run:
        try:
            session.collections.create(target)
        except ex.CATALOG_ALREADY_HAS_ITEM_BY_THAT_NAME:
            # TODO: if params.force, force create to update timestamp
            pass


def ingest_file(path, params, session):

    target = irods_dest_path(path, session, params)

    if exclude(path, params):
        logger.info("skipping {} (--exclude)".format(path))
        return

    if not params.dry_run:
        send_file(session, path, target, params)


# merge with make_collection
def create_collection(path, params, session):

    if exclude(path, params):
        logger.info("skipping {} (--exclude)".format(path))
        return

    # target collection path
    base_coll = params.destination or '/{}/home/{}'.format(session.zone, session.username)
    coll_path = os.path.join(base_coll, path)

    logger.info(yellow("process {} creating {}".format(os.getpid(), coll_path)))

    if not params.dry_run:
        try:
            session.collections.create(coll_path)
        except ex.CATALOG_ALREADY_HAS_ITEM_BY_THAT_NAME:
            # TODO: if params.force, force create to update timestamp
            pass


def register_file(path, params, session):

    if exclude(path, params):
        logger.info("skipping {} (--exclude)".format(path))
        return

    base_coll = params.destination or '/{}/home/{}'.format(session.zone, session.username)
    target = os.path.join(base_coll, path)

    file_path = os.path.join(params.prefix, path)

    logger.info(yellow("process {} registering {} as {}".format(os.getpid(), file_path, target)))

    if not params.dry_run:
        session.data_objects.register(file_path, target)


def record_start_time(timestamp_id, **kwargs):
    conn = get_current_connection()
    conn.set(timestamp_id, time.time())


def log_duration(timestamp_id, queue_name, **kwargs):
    '''
    A poor man's timer.
    There has to be a better way to time job batches...
    '''
    conn = get_current_connection()
    start_time = conn.get(timestamp_id)

    job_queue = Queue(name=queue_name, connection=conn)

    while not job_queue.is_empty():
        time.sleep(.5)

    duration = time.time() - float(start_time)
    td = datetime.timedelta(seconds=round(duration))

    time.sleep(.5) # just to make it show up at the bottom

    logger.info(yellow('Completed in {}'.format(td)))
