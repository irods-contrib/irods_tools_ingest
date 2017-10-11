import sys
import os
import types
import click
from click.decorators import pass_context

from irodsqueue import __version__ as VERSION, CHUNK_SIZE
import irodsqueue.utils as utils


@click.group()
@click.version_option(VERSION)
def main():
    '''iRODS queue command line interface.
    '''
    pass


@main.command()
@click.argument('source', required=True, type=click.Path(exists=True, resolve_path=True))
@click.argument('destination', default='')
@click.option('--chunk-size', default=CHUNK_SIZE, metavar='SIZE', help='Set buffer size in bytes for data transfers.', type=click.IntRange(256, None, clamp=True))
@click.option('--dry-run', is_flag=True, help='Perform a trial run with no changes made.')
@click.option('--timer', is_flag=True, help='Time the execution of the ingest job(s).')
@click.option('--exclude', default='', metavar='PATTERN', help='Exclude pathnames matching PATTERN.')
@click.option('-f', '--force', is_flag=True, help='Overwrite existing objects.')
@click.option('--extract-metadata', metavar='MODULE', help='Send metadata along with objects.')
@click.option('--acl', is_flag=True, help='Send access controls along with objects.')
@click.option('-k', '--register-checksum', is_flag=True, help='Register a checksum for each object, server-side.')
@click.option('-K', '--verify-checksum', is_flag=True, help='Send a checksum along with each object, verify and register it server-side.')
@click.option('--queue-name', default='normal')
@click.pass_context
def ingest(ctx, *args, **kwargs):
    '''Ingest stuff.
    '''
    params = types.SimpleNamespace(**ctx.params)

    os.stat(params.source)  # sanity check
    params.prefix = os.path.dirname(params.source)

    utils.walk_local_dir(utils.ingest_file, utils.make_collection, params)


@main.command()
@click.argument('input', type=click.Path(exists=True, resolve_path=True)) # make that an option
@click.argument('prefix', default='')
@click.argument('destination', default='')
@click.option('--dry-run', is_flag=True, help='Perform a trial run with no changes made.')
@click.option('--timer', is_flag=True, help='Time the execution of the worker job(s).')
@click.option('--exclude', default='', metavar='PATTERN', help='Exclude pathnames matching PATTERN.')
@click.option('--queue-name', default='normal')
@click.pass_context
def register(ctx, *args, **kwargs):
    '''Register stuff.
    '''
    params = types.SimpleNamespace(**ctx.params)

    # read list of paths to register from file
    utils.read_reg_input_file(params)
