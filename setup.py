from setuptools import setup, find_packages


# Get package version
version = {}
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'irodsqueue/version.py')) as f:
    exec(f.read(), version)


setup(
    name="irodsqueue",
    version=version['__version__'],
    author='Antoine de Torcy',
    author_email='adetorcy@renci.org',
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