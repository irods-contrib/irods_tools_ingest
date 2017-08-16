from setuptools import setup, find_packages
from irodsqueue import VERSION

setup(
    name="irodsqueue",
    version=VERSION,
    license='BSD',
    install_requires=[
        'rq',
        'Click',
        'python-irodsclient'
    ],
    entry_points='''
        [console_scripts]
        irodsqueue=irodsqueue.cli:main
    ''',
    packages=find_packages(),
    include_package_data=True,
)