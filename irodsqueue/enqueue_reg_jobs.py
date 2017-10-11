#!/usr/bin/env python3


import sys
import os
from mpi4py import MPI
from lib.parallelwalk  import ParallelWalk
import irodsqueue.utils as utils
from redis import Redis
from rq import Queue
import argparse
import logging


#logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)


def abort(code=0):
    MPI.COMM_WORLD.Abort(code)
    sys.exit(code)


class Enqueue(ParallelWalk):

    @property
    def job_queue(self):
        return self._job_queue

    @job_queue.setter
    def job_queue(self, value):
        self._job_queue = value

    @property
    def params(self):
        return self._params

    @params.setter
    def params(self, value):
        self._params = value

    def strip_prefix(self, path):
        return os.path.relpath(path, start=self.params.prefix)

    def ProcessFile(self, filename):
        filename = self.strip_prefix(filename)

        # parent collection dependency
        parent = os.path.dirname(filename) or None

        logger.debug('rank {}: Processing {}, depends on {}'.format(self.rank, filename, parent))

        self.job_queue.enqueue(utils.register_file, filename, self.params,
                               job_id=filename, depends_on=parent, timeout='10s')

        # update last processed entry
        self.results = filename

    def ProcessDir(self, dirname):
        dirname = self.strip_prefix(dirname)

        # parent collection dependency
        parent = os.path.dirname(dirname) or None

        logger.debug('rank {}: Processing {}, depends on {}'.format(self.rank, dirname, parent))

        self.job_queue.enqueue(utils.create_collection, dirname, self.params, job_id=dirname,
                               depends_on=parent, at_front=True, timeout='10s')

        # update last processed entry
        self.results = dirname


class MPIParser(argparse.ArgumentParser):

    def __init__(self, *args, **kwargs):
        self.rank = MPI.COMM_WORLD.Get_rank()
        super().__init__(*args, **kwargs)

    def error(self, message):
        if self.rank == 0:
            print(message, file=sys.stderr)
            self.print_usage()
            abort()

    def print_help(self, file=None):
        if self.rank == 0:
            super().print_help(file)
            abort()


try:
    comm = MPI.COMM_WORLD
    rank = comm.Get_rank()
    workers = comm.size

    parser = MPIParser()
    parser.add_argument('source')
    parser.add_argument('prefix')
    parser.add_argument('destination')
    parser.add_argument('--exclude', default='', metavar='PATTERN', help='Exclude pathnames matching PATTERN.')
    parser.add_argument('--dry-run', action='store_true', help='Perform a trial run with no changes made.')
    parser.add_argument('--timer', action='store_true', help='Time the execution of the worker job(s).')
    args = parser.parse_args()

    crawler = Enqueue(comm, results='')

    crawler.params = args
    crawler.job_queue = Queue(name='normal', connection=Redis())

    results = crawler.Execute(args.source)

    if rank == 0 and args.timer:
        utils.add_timer(crawler.job_queue.connection, crawler.job_queue, results.pop())

except (Exception, KeyboardInterrupt) as err:
    logger.exception('rank {}: {}'.format(rank, err))
    abort()

