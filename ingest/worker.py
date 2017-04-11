import os
import logging
import utils
from irods.session import iRODSSession


def upload(job_queue, args):
    '''
    main worker function.
    args is a namespace from parse_args() with additional arguments
    '''

    env = args.irods_environment

    with iRODSSession(host=env['irods_host'],
                      port=env['irods_port'],
                      user=env['irods_user_name'],
                      password=utils.get_irods_auth(env),
                      zone=env['irods_zone_name']
                      ) as session:

        while True:
            path = job_queue.get()

            # kill pill
            if path is None:
                job_queue.task_done()
                break

            target = utils.irods_dest_path(path, args)

            try:
                if utils.exclude(path, args):
                    logging.info("skipping {0} (--exclude)".format(path))

                elif os.path.islink(path):
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
                        utils.put_file(session, path, target, args)
                        #put_file(session, path, target)

            except:
                logging.error(str(path))
                raise

            job_queue.task_done()
