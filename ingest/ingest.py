#!/usr/bin/env python

import sys
import os
import io
import logging
import argparse
import multiprocessing
import utils
from worker import worker


# parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('source', help='source file or directory')
parser.add_argument('destination', nargs='?',
                    default="", help='destination collection')
parser.add_argument(
    "-f", "--force", help="overwrite existing objects", action="store_true")
parser.add_argument('-j', '--jobs', metavar='JOBS', default=8,
                    type=int, help='number of concurrent jobs', choices=range(1, 65))
parser.add_argument(
    "--metadata", help="send metadata along with objects", action="store_true")
parser.add_argument(
    "--acl", help="send access controls along with objects", action="store_true")
parser.add_argument(
    "-n", "--dry-run", help="perform a trial run with no changes made", action="store_true")
parser.add_argument(
    "-k", "--register-checksum", help="register a checksum for each object, server-side", action="store_true")
parser.add_argument(
    "-K", "--verify-checksum", help="send a checksum along with each object, verify and register it server-side", action="store_true")
parser.add_argument(
    "-v", "--verbose", help="increase verbosity", action="store_const", dest="loglevel", const=logging.INFO, default=logging.WARNING)
parser.add_argument('--exclude', metavar='PATTERN', type=str, help='exclude pathnames matching PATTERN')
# parser.add_argument('-d', '--debug', help="print debug statements",
# action="store_const", dest="loglevel", const=logging.DEBUG,
# default=logging.WARNING)

parsed_args = parser.parse_args()


logging.basicConfig(stream=sys.stdout, level=parsed_args.loglevel,
                    format='[%(levelname)s] (%(processName)s) %(message)s')


parsed_args.buffer_size = 1024 * io.DEFAULT_BUFFER_SIZE


parsed_args.source = os.path.abspath(parsed_args.source)
os.stat(parsed_args.source)  # sanity check
parsed_args.prefix = os.path.dirname(parsed_args.source)

job_queue = multiprocessing.JoinableQueue()


# use icommands env/auth for now
# get irods environment
try:
    irods_env_file = os.environ['IRODS_ENVIRONMENT_FILE']
except KeyError:
    irods_env_file = os.path.expanduser('~/.irods/irods_environment.json')

parsed_args.irods_environment = utils.get_irods_env(irods_env_file)


# put source path in the queue
job_queue.put(parsed_args.source)


# start worker processes
for _ in range(parsed_args.jobs):
    process = multiprocessing.Process(target=worker, args=(job_queue, parsed_args))
    # process.daemon = True
    process.start()


# block until workers are done
job_queue.join()

# put kill pills in the queue
for _ in range(parsed_args.jobs):
    job_queue.put(None)


sys.exit(0)
