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
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Development Status :: 2 - Pre-Alpha',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Operating System :: POSIX :: Linux',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    packages=find_packages(),
    include_package_data=True,
)