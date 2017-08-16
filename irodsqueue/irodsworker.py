import os
from rq import SimpleWorker
from irods.session import iRODSSession


class IrodsWorker(SimpleWorker):
    '''
    Custom worker class.
    We extend SimpleWorker rather than Worker to have one session
    object per process (no forking).
    '''

    def work(self, *args, **kwargs):
        # use icommands env/auth for now
        try:
            env_file = os.environ['IRODS_ENVIRONMENT_FILE']
        except KeyError:
            env_file = os.path.expanduser('~/.irods/irods_environment.json')

        with iRODSSession(irods_env_file=env_file) as session:
            self.session = session
            super().work(*args, **kwargs)

    def perform_job(self, job, queue):
        # Pass session to our enqueued functions
        job.kwargs['session'] = self.session
        return super().perform_job(job, queue)
