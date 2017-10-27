==========
irodsqueue
==========

*Instructions below are for testing the development code. Subject to change.*


Requirements
------------
- \*nix
- Python 3.4+
- Redis 4.0+. To download and install Redis see `here <https://redis.io/download#installation>`_
- `virtualenv <https://pypi.python.org/pypi/virtualenv>`_


Installation
------------
It is recommended to install this package in a virtual environment, e.g:

Make a virtual environment::

 virtualenv -p python3 testenv3

Activate the virtual environment::

 source testenv3/bin/activate

Install the latest PRC code from github::

 pip install git+https://github.com/irods/python-irodsclient

Install this repository's current development branch::

 pip install git+https://github.com/irods-contrib/irods_tools_ingest@dev


Usage
-----
Start redis::

 cd REDIS_DIR/src
 ./redis-server

From our virtual environment call the main app, e.g::

 irodsqueue --help
 irodsqueue ingest --help

Enqueue ingest jobs, for example to ingest a directory into iRODS::

 irodsqueue ingest -f --timer /PATH/TO/LOCAL/DIR

Once we have jobs in the queue we can launch workers to process them. Each worker is its own process. We use a custom worker class that opens and maintains iRODS sessions.
Open a separate terminal and activate our same virtual environment as above.

Test your iRODS connection::

 ils

Launch 16 worker processes (e.g. in bash)::

 for i in {1..16}; do sleep .1; rq worker -v --burst -w irodsqueue.irodsworker.IrodsWorker & done

Options
-------
You can specify a metadata extraction function to invoke as part of the ingest process, by using the --metadata option when enqueuing jobs.
The value should be the path to a python file containing a function named extract_metadata.
See `examples <https://github.com/irods-contrib/irods_tools_ingest/tree/dev/irodsqueue/metadata>`_

Enqueue jobs with metadata extraction::

 irodsqueue ingest -f --extract-metadata ~/tests/metadata/test.py --timer /PATH/TO/LOCAL/DIR

Enqueue jobs with file checksums::

 irodsqueue ingest -Kf --timer /PATH/TO/LOCAL/DIR

