#!/usr/bin/env python3
# coding: utf-8

# py-wp-backup
# Copyright (C) 2020 - Node
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import datetime
import ftplib
import os
import ssl
import sys
import tarfile

import ftps
import gnupg

import click

__version__ = '0.1.0'


class Mutex(click.Option):
    def __init__(self, *args, **kwargs):
        self.not_required_if: list = kwargs.pop("not_required_if")

        assert self.not_required_if, "'not_required_if' parameter required"
        kwargs["help"] = (kwargs.get("help", "") + "Option is mutually exclusive with " + ", ".join(
            self.not_required_if) + ".").strip()
        super(Mutex, self).__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
        current_opt: bool = self.name in opts
        for mutex_opt in self.not_required_if:
            if mutex_opt in opts:
                if current_opt:
                    raise click.BadOptionUsage(str(self.name),
                                               "Illegal usage: '" + str(
                                                   self.name) + "' is mutually exclusive with '" + str(mutex_opt) + "'")
                else:
                    self.prompt = None
        return super(Mutex, self).handle_parse_result(ctx, opts, args)


class ReusedSslSocket(ssl.SSLSocket):
    def unwrap(self):
        pass


class fixFTP_TLS(ftplib.FTP_TLS):
    """Explicit FTPS, with shared TLS session"""

    def ntransfercmd(self, cmd, rest=None):
        conn, size = ftplib.FTP.ntransfercmd(self, cmd, rest)
        if self._prot_p:
            conn = self.context.wrap_socket(conn,
                                            server_hostname=self.host,
                                            session=self.sock.session)  # reuses TLS session
            conn.__class__ = ReusedSslSocket  # we should not close reused ssl socket when file transfers finish
        return conn, size


@click.group(chain=True)
@click.option('--debug/--no-debug', default=False)
@click.option('--archive-retention', '-ar', type=int, default=7)
@click.pass_context
def cli(ctx, debug, archive_retention):
    click.clear()
    click.echo("                       _                _                \n"
               " __      ___ __       | |__   __ _  ___| | ___   _ _ __  \n"
               " \ \ /\ / / '_ \ _____| '_ \ / _` |/ __| |/ / | | | '_ \ \n"
               "  \ V  V /| |_) |_____| |_) | (_| | (__|   <| |_| | |_) |\n"
               "   \_/\_/ | .__/      |_.__/ \__,_|\___|_|\_\\__,_| .___/\n"
               "          |_|                                     |_|    \n"
               "v." + __version__ + " \n")

    click.echo('Debug mode is %s' % ('on' if debug else 'off'))
    click.echo('Retention of backups for ' + str(archive_retention) + ' days')
    ctx.obj['archive-retention'] = archive_retention
    ctx.obj['gpg_use'] = False
    ctx.obj['transfer_use'] = False


@cli.command()
@click.option('--gpg-key-file', cls=Mutex, not_required_if=['gpg_key_server', 'gpg_key_id'])
@click.option('--gpg-key-server', '-gks', type=str, default='keyserver.ubuntu.com')
@click.option('--gpg-key-id', '-gki', required=True)
@click.pass_context
def gpg(ctx, gpg_key_server, gpg_key_id, gpg_key_file):
    # Todo: Need cleanup, use try ?
    ctx.obj['gpg_use'] = True
    click.echo("GPG initialization...")
    gpg = gnupg.GPG()

    # export
    ctx.obj['gpg'] = gpg

    public_key_exist = gpg.list_keys(keys=gpg_key_id)

    if public_key_exist is None:
        if gpg_key_file is not None:
            click.echo('Import of the key located in the file: ' + gpg_key_file)
            gpg.import_keys(gpg_key_file.read())
        elif (gpg_key_id is not None) and (gpg_key_file is None):
            click.echo('Reception of the key: "' + gpg_key_id + '" on the "' + gpg_key_server + '" server...')
            imported_key = gpg.recv_keys(gpg_key_server, gpg_key_id)
            if imported_key.count is None:
                click.echo('Error. GPG')

            click.echo('The key has been successfully imported. Fingerprint: ' + imported_key.fingerprints[0])
    else:
        click.echo('The key: "' + gpg_key_id + '" already exists')

    # export
    ctx.obj['gpg_key_id'] = gpg_key_id


@cli.command()
@click.option('--host', '-h', required=True)
@click.option('--user', '-u', type=str, required=True)
@click.option('--passwd', '-p', type=str, required=True)
@click.option('--timeout', '-t', type=int, default=5, required=True)
@click.option('--mode', '-m', type=str, default='ftps', required=True)
@click.option('--remove-local', '-rml', type=bool, default=False, required=True)
@click.pass_context
def transfer(ctx, host, user, passwd, timeout, mode, remove_local):
    ctx.obj['transfer_use'] = True

    if mode == 'ftps':
        ftp_connect(host, user, passwd, timeout, ftps=True, close_immediately=True)
        ctx.obj['transfer_ftps'] = True
    elif mode == 'ftp':
        ftp_connect(host, user, passwd, timeout, ftps=False, close_immediately=True)
        ctx.obj['transfer_ftps'] = False

    ctx.obj['transfer_host'] = host
    ctx.obj['transfer_user'] = user
    ctx.obj['transfer_passwd'] = passwd
    ctx.obj['transfer_timeout'] = timeout
    ctx.obj['transfer_remove_local'] = remove_local


@cli.command()
@click.option('--wp-dir', '-wd', type=click.Path(exists=True, readable=True, dir_okay=True), default='', required=True)
@click.option('--archive-dir', '-a', type=click.Path(exists=True, writable=True, dir_okay=True), default='',
              required=True)
@click.pass_context
def wp(ctx, wp_dir, archive_dir):
    click.echo('WordPress backup launch...')
    click.echo('Installation directory: ' + wp_dir)
    click.echo('Backup archive directory: ' + archive_dir)

    # define file name
    FILENAME_PREFIX = "WP_BACKUP_"
    FILENAME = FILENAME_PREFIX + str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
    TMP_FILENAME = "TMP_" + FILENAME
    TMP_FILENAME_EXT = TMP_FILENAME + ".tar.gz"
    FILENAME_EXT = FILENAME + ".encrypted" + ".tar.gz"
    TMP_PATH_FILENAME = os.path.join(archive_dir, TMP_FILENAME_EXT)
    FINAL_PATH_FILENAME = os.path.join(archive_dir, FILENAME_EXT)

    # share params
    ctx.obj['backup_filename'] = FILENAME_EXT
    ctx.obj['backup_file_path'] = FINAL_PATH_FILENAME

    # gzip
    wp_backup_file = tar([wp_dir], TMP_PATH_FILENAME)

    # share params
    ctx.obj['wp_backup_file'] = wp_backup_file

    if ctx.obj['gpg_use']:
        encrypt_with_gpg(ctx.obj['gpg'], wp_backup_file, ctx.obj['gpg_key_id'], True, FINAL_PATH_FILENAME)

    if ctx.obj['transfer_use']:
        ftp = ftp_connect(ctx.obj['transfer_host'], ctx.obj['transfer_user'], ctx.obj['transfer_passwd'],
                          ctx.obj['transfer_timeout'], ctx.obj['transfer_ftps'], close_immediately=False)
        ftp_transfer_file(ftp, ctx.obj['backup_filename'], ctx.obj['backup_file_path'],
                          remove_local_file=ctx.obj['transfer_remove_local'], close=True)
        click.echo(ctx.obj['backup_file_path'])


def tar(src, out, mode='x:gz'):
    click.echo('Creating the compressed file...')
    try:
        tar = tarfile.open(out, mode)
        for file in src:
            tar.add(file)
            click.echo('File or folder "' + file + '" add to archive')
    except:
        click.echo('Error.', err=True)
    finally:
        tar.close()

    click.echo('Compression complete. File path: ' + tar.name)
    return tar.name


def encrypt_with_gpg(gpg, path, key, remove_file=False, output_path=None):
    uncrypted = open(path, "rb")

    if output_path is not None:
        output_path = output_path
    else:
        output_path = path + '.encrypted'

    encrypted = gpg.encrypt_file(uncrypted, key, output=output_path)
    uncrypted.close()

    if encrypted.ok:
        click.echo('The file: "' + path + '" has been encrypted using the key: "' + key + '"')
        click.echo('The encrypted file is available at the location: "' + output_path + '"')
    else:
        click.echo('Error during encryption: ' + encrypted.status)

    if remove_file:
        remove(path)


def remove(path):
    """
    Remove the file or directory
    """
    if os.path.isdir(path):
        try:
            os.rmdir(path)
        except OSError:
            click.echo("Unable to remove folder: %s" % path, err=True)
        else:
            click.echo('Deleted folder:' + path)
    else:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            click.echo("Unable to remove file: %s" % path, err=True)
        else:
            click.echo('Deleted file: "' + path + '"')


def ftp_connect(host, user, passwd, timeout=5, ftps=True, close_immediately=False):
    if ftps:
        try:
            ftps = fixFTP_TLS(host=host, timeout=timeout)
            ftps.ssl_version = ssl.PROTOCOL_TLS
            ftps.login(user=user, passwd=passwd)
            ftps.prot_p()
            ftp = ftps
        except ConnectionRefusedError as e:
            click.echo(e.strerror + '. IP: ' + host, err=True)
            sys.exit()
        else:
            ftps_or_ftp = 'FTPs'
    else:
        try:
            ftp = ftplib.FTP_TLS(host=host, timeout=timeout)
            ftp.login(user=user, passwd=passwd)
        except ConnectionRefusedError as e:
            click.echo(e.strerror + '. IP: ' + host, err=True)
            sys.exit()
        else:
            ftps_or_ftp = 'FTP'

    ftp.set_pasv(True)
    click.echo('Connected to the ' + ftps_or_ftp + ' server')

    if close_immediately:
        ftp.close()
        click.echo('Connection with the ' + ftps_or_ftp + ' server closed')

    return ftp


def ftp_transfer_file(ftp, filename, file_path, remove_local_file=False, close=True):
    ftp.storbinary('STOR ' + filename, open(file_path, 'rb'))
    if remove_local_file:
        remove(file_path)
    if close:
        ftp.close()


if __name__ == '__main__':
    cli(obj={})
