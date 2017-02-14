import sys
import os
import io
import time
import json
import logging
import argparse
import multiprocessing

from irods.session import iRODSSession


# Parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('source', help='source file or directory')
parser.add_argument('destination', nargs='?',
                    default="", help='destination collection')
parser.add_argument(
    "-f", "--force", help="overwrite existing objects", action="store_true")
parser.add_argument('-j', '--jobs', metavar='JOBS', default=8,
                    type=int, help='number of concurrent jobs', choices=range(1, 65))
parser.add_argument(
    "-n", "--dry-run", help="perform a trial run with no changes made", action="store_true")
parser.add_argument(
    "-v", "--verbose", help="increase verbosity", action="store_const", dest="loglevel", const=logging.INFO, default=logging.WARNING)
# parser.add_argument('-d', '--debug', help="print debug statements",
# action="store_const", dest="loglevel", const=logging.DEBUG,
# default=logging.WARNING)

args = parser.parse_args()


logging.basicConfig(stream=sys.stdout, level=args.loglevel,
                    format='[%(levelname)s] (%(processName)s) %(message)s')


buffer_size = 1024 * io.DEFAULT_BUFFER_SIZE


source_path = os.path.abspath(args.source)
os.stat(source_path)  # sanity check
prefix = os.path.dirname(source_path)

job_queue = multiprocessing.JoinableQueue()


def get_irods_env(env_file=os.path.expanduser('~/.irods/irods_environment.json')):
    with open(env_file, 'rt') as f:
        return json.load(f)


env = get_irods_env()

# in future use dest coll if provided
irods_cwd = "/{irods_zone_name}/home/{irods_user_name}".format(**env)


def chunks(f, chunksize=io.DEFAULT_BUFFER_SIZE):
    return iter(lambda: f.read(chunksize), b'')


def put_file(session, file_path, obj_path):
    obj = session.data_objects.create(obj_path)

    with open(file_path, 'rb') as f, obj.open('w') as o:
        for chunk in chunks(f, buffer_size):
            o.write(chunk)


def irods_dest_path(path):
    '''
    Determines an iRODS destination path.
    Used by worker function.
    '''
    relative_path = os.path.relpath(path, prefix)
    return os.path.join(irods_cwd, relative_path)


def upload(env, job_queue):
    '''
    worker function
    '''

    with iRODSSession(host=env['irods_host'], port=env['irods_port'], user=env['irods_user_name'], password='rods', zone=env['irods_zone_name']) as session:

        while True:
            path = job_queue.get()

            # kill pill
            if path is None:
                job_queue.task_done()
                break

            target = irods_dest_path(path)

            try:
                if os.path.islink(path):
                    logging.info("ignoring link {0}".format(path))

                elif os.path.isdir(path):
                    logging.info("creating {0}".format(target))

                    if not args.dry_run:
                        session.collections.create(target)

                    # add children to queue
                    for child in os.listdir(path):
                        job_queue.put(os.path.join(path, child))

                else:
                    logging.info("uploading {0} as {1}".format(path, target))

                    if not args.dry_run:
                        put_file(session, path, target)

            except:
                logging.error(str(path))
                # raise

            job_queue.task_done()


# Put source path in the queue
job_queue.put(source_path)


# Start worker processes
for _ in range(args.jobs):
    worker = multiprocessing.Process(target=upload, args=(env, job_queue))
    # worker.daemon = True
    worker.start()


# Block until workers are done
job_queue.join()

# Put kill pills in the queue
for _ in range(args.jobs):
    job_queue.put(None)


sys.exit(0)
