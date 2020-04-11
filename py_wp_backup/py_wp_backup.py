#!/usr/bin/env python
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
import re
import ssl
import subprocess
import sys
import tarfile
import tempfile
from pprint import pprint

import gnupg as gnupg_
import regex as regex
from wpconfigr import WpConfigFile

import click


class Mutex(click.Option):
    def __init__(self, *args, **kwargs):
        self.not_required_if = kwargs.pop("not_required_if")

        assert self.not_required_if, "'not_required_if' parameter required"
        kwargs["help"] = (kwargs.get("help", "") + "Option is mutually exclusive with " + ", ".join(
            self.not_required_if) + ".").strip()
        super(Mutex, self).__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
        current_opt = self.name in opts
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
               "          |_|                                     |_|    \n")

    click.echo('Debug mode is %s' % ('on' if debug else 'off'))
    click.echo('Retention of backups for ' + str(archive_retention) + ' days')
    ctx.obj['archive-retention'] = archive_retention
    ctx.obj['gpg_use'] = False
    ctx.obj['gpg_private_use'] = False
    ctx.obj['transfer_use'] = False
    ctx.obj['backup_use'] = False
    ctx.obj['restore_use'] = False

    # required_wp_cmd = 'backup'
    # required_wp_cmd_backup = ['--wp', '--sql']
    # required_wp_cmd_options = ['--wp-dir', '-wd', '--archive-dir', '-a']
    #
    # sys_argv_set = set(sys.argv)
    # required_wp_cmd_options_set = set(required_wp_cmd_options)
    # required_wp_cmd_backup_set = set(required_wp_cmd_backup)
    #
    # if (len(sys_argv_set.intersection(required_wp_cmd_backup_set)) > 0) and (required_wp_cmd in sys.argv) \
    #        and (len(sys_argv_set.intersection(required_wp_cmd_options_set)) == 2):
    #    ctx.obj['backup_use'] = True
    # else:
    #    click.echo('The "' + required_wp_cmd + '" command is required and options: ' +
    #               ', '.join(required_wp_cmd_options) + ' and and at least one: ' + ', '.join(required_wp_cmd_backup),
    #               err=True)
    #    exit(2)


@cli.command()
@click.option('--key-file', '-kf', default=None, cls=Mutex, not_required_if=['key_server', 'key_id'])
@click.option('--key-server', '-ks', type=str, default='keyserver.ubuntu.com')
@click.option('--key-id', '-ki', type=str, default=None, cls=Mutex,
              not_required_if=['private_key_file', 'private_key_file_remove'])
@click.option('--private-key-file', '-pkf', type=click.Path(exists=True, readable=True, file_okay=True),
              default=None, cls=Mutex, not_required_if=['key_server', 'key_id', 'key_file'])
@click.option('--private-key-pass', '-pkp', cls=Mutex,
              not_required_if=['key_server', 'key_id', 'key_file'], prompt=True, hide_input=True)
@click.option('--private-key-file-remove', '-pkf', default=True, required=False, cls=Mutex,
              not_required_if=['key_server', 'key_id', 'key_file'])
@click.pass_context
def gpg(ctx, key_server, key_id, key_file, private_key_file, private_key_file_remove, private_key_pass):
    # Todo: Need cleanup, use try ?
    # if not (ctx.obj['backup_use'] or ctx.obj['restore_use']):
    #    click.echo('To use this command, the "backup" or "restore" command is required.', err=True)
    #    exit(2)

    ctx.obj['gpg_use'] = True
    click.echo("GPG initialization...")
    gpg = gnupg_.GPG()

    # export
    ctx.obj['gpg'] = gpg

    if key_id is not None:
        public_key_exist = gpg.list_keys(keys=key_id)

        if public_key_exist.fingerprints:
            click.echo('The key: "' + key_id + '" already exists')
        else:
            if key_file is not None:
                click.echo('Import of the key located in the file: "' + key_file + '"')

                with open(key_file) as f:
                    key_data = f.read()
                imported_key = gpg.import_keys(key_data)

            elif (key_id is not None) and (key_file is None):
                click.echo('Reception of the key: "' + key_id + '" on the "' + key_server + '" server...')
                imported_key = gpg.recv_keys(key_server, key_id)
                if imported_key.count is None:
                    click.echo('Error. GPG')
                    exit(2)

            click.echo('The key has been successfully imported. Fingerprint: ' + imported_key.fingerprints[0])

        # export
        ctx.obj['gpg_key_id'] = key_id

    # import private key
    if private_key_file is not None:
        ctx.obj['gpg_private_use'] = True
        ctx.obj['gpg_private_key_pass'] = private_key_pass
        ctx.obj['gpg_private_key_file_remove'] = private_key_file_remove

        if private_key_file is not None:
            click.echo('Import of the private key located in the file: "' + private_key_file + '"')
            with open(private_key_file) as f:
                private_key_data = f.read()
            imported_private_key = gpg.import_keys(private_key_data)
            ctx.obj['gpg_private_key_fingerprints'] = imported_private_key.fingerprints[0]
            if imported_private_key.count is None:
                click.echo('Error. GPG')
                exit(2)


@cli.command()
@click.option('--host', '-h', required=True)
@click.option('--user', '-u', type=str, required=True)
@click.option('--passwd', '-p', type=str, required=True)
@click.option('--timeout', '-t', type=int, default=5, required=True)
@click.option('--mode', '-m', type=str, default='ftps', required=True)
@click.option('--remove-local', '-rml', type=bool, default=False, required=True)
@click.pass_context
def transfer(ctx, host, user, passwd, timeout, mode, remove_local):
    #if not ctx.obj['backup_use']:
    #   click.echo('To use this command, the "backup" command is required.', err=True)
    #   exit(2)

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


def check_old_backup(file, days):
    # clean name
    filename_clean = os.path.basename(file.replace('.tar.gz', '').replace('.encrypted', '').replace('SQL_BACKUP_', '').
                                      replace('WP_BACKUP_', ''))
    date_format = '%Y-%m-%d-%H-%M-%S'
    date_now = datetime.datetime.now().strftime(date_format)
    a = datetime.datetime.strptime(filename_clean, date_format)
    b = datetime.datetime.strptime(date_now, date_format)
    delta = b - a

    if delta.days >= days:
        return True
    else:
        return False


@cli.command()
@click.option('--wp', '-w', type=bool, default=True, required=True)
@click.option('--sql', '-s', type=bool, default=True, required=True)
@click.option('--wp-dir', '-wd', type=click.Path(exists=True, readable=True, dir_okay=True), default='', required=True)
@click.option('--archive-dir', '-ad', type=click.Path(exists=True, writable=True, dir_okay=True), default='',
              required=True)
@click.pass_context
def backup(ctx, wp, sql, wp_dir, archive_dir):
    ctx.obj['backup_use'] = True

    if (wp is False) and (sql is False):
        click.echo('Please know at least one command for backup: "--wp" or "--sql" to use the backup command.')

    click.echo('Backup archive directory: ' + archive_dir)
    click.echo('Backup verification greater than ' + str(ctx.obj['archive-retention']) + ' day(s)')

    files = []
    if ctx.obj['transfer_use']:
        ftp = ftp_connect(ctx.obj['transfer_host'], ctx.obj['transfer_user'], ctx.obj['transfer_passwd'],
                          ctx.obj['transfer_timeout'], ctx.obj['transfer_ftps'], close_immediately=False)
        files = []

        try:
            files = ftp.nlst()
        except ftplib.error_perm as resp:
            click.echo('Files not found', err=True)
            exit(2)

        for f in files:
            if f.endswith('.tar.gz'):
                old_or_not = check_old_backup(f, ctx.obj['archive-retention'])
                if old_or_not:
                    ftp.delete(f)
                    click.echo('Remote backup deleted: "' + f + '"')

    for file in os.listdir(archive_dir):
        if file.endswith(".tar.gz"):
            old_or_not = check_old_backup(file, ctx.obj['archive-retention'])
            if old_or_not:
                os.remove(os.path.join(archive_dir, file))
                click.echo('Local backup deleted: "' + file + '"')

    if wp:
        click.echo('WordPress backup launch...')
        click.echo('Installation directory: ' + wp_dir)

        # define file name
        WP_FILENAME_PREFIX = "WP_BACKUP_"
        WP_FILENAME = WP_FILENAME_PREFIX + str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
        WP_UNCRYPTED_FILENAME = WP_FILENAME
        WP_UNCRYPTED_FILENAME_EXT = WP_UNCRYPTED_FILENAME + ".tar.gz"
        WP_CRYPTED_FILENAME_EXT = WP_FILENAME + ".encrypted" + ".tar.gz"
        WP_UNCRYPTED_PATH_FILENAME = os.path.join(archive_dir, WP_UNCRYPTED_FILENAME_EXT)
        WP_CRYPTED_PATH_FILENAME = os.path.join(archive_dir, WP_CRYPTED_FILENAME_EXT)

        if ctx.obj['gpg_use']:
            wp_backup_filename = WP_CRYPTED_FILENAME_EXT
            wp_backup_file_path = WP_CRYPTED_PATH_FILENAME
        else:
            wp_backup_filename = WP_UNCRYPTED_FILENAME_EXT
            wp_backup_file_path = WP_UNCRYPTED_PATH_FILENAME

        # gzip
        wp_backup_file = tar([wp_dir], WP_UNCRYPTED_PATH_FILENAME)

        # encrypt
        if ctx.obj['gpg_use']:
            encrypt_with_gpg(ctx.obj['gpg'], wp_backup_file, key=ctx.obj['gpg_key_id'],
                             remove_file=True,
                             output_path=WP_CRYPTED_PATH_FILENAME)

        # transfer
        if ctx.obj['transfer_use']:
            ftp = ftp_connect(ctx.obj['transfer_host'], ctx.obj['transfer_user'], ctx.obj['transfer_passwd'],
                              ctx.obj['transfer_timeout'], ctx.obj['transfer_ftps'], close_immediately=False)
            ftp_transfer_file(ftp, wp_backup_filename, wp_backup_file_path,
                              remove_local_file=ctx.obj['transfer_remove_local'], close=True)

    if sql:
        click.echo('SQL backup launch...')
        # define file name
        SQL_FILENAME_PREFIX = "SQL_BACKUP_"
        SQL_FILENAME = SQL_FILENAME_PREFIX + str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
        SQL_UNCRYPTED_FILENAME = SQL_FILENAME
        SQL_UNCRYPTED_FILENAME_EXT = SQL_UNCRYPTED_FILENAME + ".tar.gz"
        SQL_CRYPTED_FILENAME_EXT = SQL_FILENAME + ".encrypted" + ".tar.gz"
        SQL_PATH_FILENAME = os.path.join(archive_dir, SQL_FILENAME + '.sql')
        SQL_UNCRYPTED_PATH_FILENAME = os.path.join(archive_dir, SQL_UNCRYPTED_FILENAME_EXT)
        SQL_CRYPTED_PATH_FILENAME = os.path.join(archive_dir, SQL_CRYPTED_FILENAME_EXT)

        if ctx.obj['gpg_use']:
            sql_backup_filename = SQL_CRYPTED_FILENAME_EXT
            sql_backup_file_path = SQL_CRYPTED_PATH_FILENAME
        else:
            sql_backup_filename = SQL_UNCRYPTED_FILENAME_EXT
            sql_backup_file_path = SQL_UNCRYPTED_PATH_FILENAME

        # get wp-config params
        wp_config = WpConfigFile(os.path.join(wp_dir, 'wp-config.php'))
        wp_db_host_port = parse_hostport(wp_config.get('DB_HOST'))
        wp_db_host = wp_db_host_port[0]

        if wp_db_host_port[1] is None:
            wp_db_port = '3306'
        else:
            wp_db_port = wp_db_host_port[1]

        sql_backup(hostname=wp_db_host, port=wp_db_port, mysql_user=wp_config.get('DB_USER'),
                   mysql_pw=wp_config.get('DB_PASSWORD'), database=wp_config.get('DB_NAME'), out_file=SQL_PATH_FILENAME)

        # gzip
        sql_backup_file = tar([SQL_PATH_FILENAME], SQL_UNCRYPTED_PATH_FILENAME, accname=SQL_UNCRYPTED_FILENAME + '.sql')

        # delete not compressed file
        remove(SQL_PATH_FILENAME)

        # encrypt
        if ctx.obj['gpg_use']:
            encrypt_with_gpg(ctx.obj['gpg'], sql_backup_file, key=ctx.obj['gpg_key_id'],
                             remove_file=True,
                             output_path=SQL_CRYPTED_PATH_FILENAME)

        # transfer
        if ctx.obj['transfer_use']:
            ftp = ftp_connect(ctx.obj['transfer_host'], ctx.obj['transfer_user'], ctx.obj['transfer_passwd'],
                              ctx.obj['transfer_timeout'], ctx.obj['transfer_ftps'], close_immediately=False)
            ftp_transfer_file(ftp, sql_backup_filename, sql_backup_file_path,
                              remove_local_file=ctx.obj['transfer_remove_local'], close=True)


@cli.command()
@click.option('--wp-archive', '-wa', default=None, type=click.Path(exists=True, writable=False, file_okay=True))
@click.option('--sql-archive', '-sa', default=None, type=click.Path(exists=True, writable=False, file_okay=True))
@click.option('--wp-dir', '-wd', default=None, required=True)
@click.option('--sql-database', '-sd', default=None)
@click.pass_context
def restore(ctx, wp_archive, sql_archive, wp_dir, sql_database):
    ctx.obj['restore_use'] = True

    if (wp_archive is None) and (sql_archive is None):
        click.echo(
            'Please know at least one command for backup: "--wp-archive" or "--sql-archive" to use the restore command.', err=True)

    if (sql_archive is not None) and (wp_dir is None):
        click.echo('To use SQL restore please specify the option "--wp-dir"', err=True)

    if ctx.obj['transfer_use']:
        # get file in ftps
        pass

    if wp_archive is not None:
        if ctx.obj['transfer_use']:
            # future implementation
            pass
        else:
            # decrypt
            if ctx.obj['gpg_use']:
                stream = open(wp_archive, "rb")

                try:
                    tmp_file = tempfile.NamedTemporaryFile(delete=True, suffix=".tar.gz")
                except:
                    click.echo('Unable to create temporary file', err=True)
                    exit(2)
                else:
                    click.echo('Temporary file created: "' + tmp_file.name + '"')

                click.echo('Attempting to decrypt the file: ' + wp_archive)

                try:
                    ctx.obj['gpg'].decrypt_file(stream, passphrase=ctx.obj['gpg_private_key_pass'],
                                                output=tmp_file.name)
                    tar_decompress(tmp_file.name, wp_dir)
                except:
                    click.echo('Unable to decrypt the file', err=True)
                    exit(2)
                else:
                    click.echo('File successfully decrypted: ' + wp_archive)
                finally:
                    tmp_file.close()
                    stream.close()

                if ctx.obj['gpg_private_key_file_remove']:
                    ctx.obj['gpg'].delete_keys(ctx.obj['gpg_private_key_fingerprints'], secret=True,
                                               passphrase=ctx.obj['gpg_private_key_pass'])
                    click.echo('Removed GPG private key: ' + ctx.obj['gpg_private_key_fingerprints'])
            else:
                tar_decompress(wp_archive, wp_dir)

        click.echo('WordPress archive restored to location: "' + wp_dir + '"')

    if sql_archive is not None:

        if ctx.obj['gpg_use']:
            sql_stream = open(sql_archive, "rb")

            try:
                sql_compress_tmp_file = tempfile.NamedTemporaryFile(delete=True, suffix=".tar.gz")
            except:
                click.echo('Unable to create temporary file', err=True)
                exit(2)
            else:
                click.echo('Temporary file created: "' + sql_compress_tmp_file.name + '"')

            click.echo('Attempting to decrypt the file: ' + sql_archive)

            try:
                ctx.obj['gpg'].decrypt_file(sql_stream, passphrase=ctx.obj['gpg_private_key_pass'],
                                            output=sql_compress_tmp_file.name)

                sql_compress_path_file = sql_compress_tmp_file.name
            except:
                click.echo('Unable to decrypt the file', err=True)
                exit(2)
            else:
                click.echo('File successfully decrypted: ' + sql_archive)
            finally:
                sql_stream.close()

            if ctx.obj['gpg_private_key_file_remove']:
                ctx.obj['gpg'].delete_keys(ctx.obj['gpg_private_key_fingerprints'], secret=True,
                                           passphrase=ctx.obj['gpg_private_key_pass'])
                click.echo('Removed GPG private key: ' + ctx.obj['gpg_private_key_fingerprints'])
        else:
            sql_compress_path_file = sql_archive

        try:
            sql_tmp_dir_file = tempfile.TemporaryDirectory()
        except:
            click.echo('Unable to create temporary directory', err=True)
            exit(2)
        else:
            click.echo('Temporary directory created: "' + sql_tmp_dir_file.name + '"')

        sql_tmp_file = os.path.basename(sql_archive.replace('.encrypted.tar.gz', ''))
        sql_file = os.path.join(sql_tmp_dir_file.name, sql_tmp_file) + '.sql'

        tar_decompress(sql_compress_path_file, sql_tmp_dir_file.name)

        if ctx.obj['gpg_use']:
            sql_compress_tmp_file.close()

        # get wp-config params
        wp_config = WpConfigFile(os.path.join(wp_dir, 'wp-config.php'))

        wp_db_host_port = parse_hostport(wp_config.get('DB_HOST'))
        wp_db_host = wp_db_host_port[0]

        if wp_db_host_port[1] is None:
            wp_db_port = '3306'
        else:
            wp_db_port = wp_db_host_port[1]

        if sql_database is None:
            wp_db_name = wp_config.get('DB_NAME')
        else:
            wp_db_name = sql_database

        sql_restore(hostname=wp_db_host, port=wp_db_port, mysql_user=wp_config.get('DB_USER'),
                    mysql_pw=wp_config.get('DB_PASSWORD'), database=wp_db_name, file=sql_file)

        remove(sql_tmp_dir_file.name)


def tar(src, out, mode='x:gz', accname=None):
    click.echo('Creating the compressed file...')
    try:
        tar = tarfile.open(out, mode)
        for file in src:
            tar.add(file, accname)
            click.echo('File or folder "' + file + '" add to archive')
    except:
        click.echo('Error.', err=True)
    finally:
        tar.close()

    click.echo('Compression complete. File path: ' + tar.name)
    return tar.name


def tar_decompress(file, to):
    try:
        click.echo('Decompressing the archive: "' + file + '"')
        tf = tarfile.open(file)
        tf.extractall(path=to)
    except:
        click.echo('Unable to decompress the archive', err=True)
        exit(2)
    else:
        click.echo('File decompression performed: "' + file + '"')
    finally:
        tf.close()


def encrypt_with_gpg(gpg, path, key, remove_file=False, output_path=None):
    uncrypted = open(path, "rb")

    if output_path is not None:
        output_path = output_path
    else:
        output_path = path + '.encrypted'

    encrypted = gpg.encrypt_file(uncrypted, key, output=output_path, always_trust=True)
    uncrypted.close()

    if encrypted.ok:
        click.echo('The file: "' + path + '" has been encrypted using the key: "' + key + '"')
        click.echo('The encrypted file is available at the location: "' + output_path + '"')
    else:
        click.echo('Error during encryption: ' + encrypted.status, err=True)
        exit(2)

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
    # TODO: Try
    ftp.storbinary('STOR ' + filename, open(file_path, 'rb'))
    if remove_local_file:
        remove(file_path)
    if close:
        ftp.close()


def sql_backup(hostname, port, mysql_user, mysql_pw, database, out_file):

    try:
        p = subprocess.Popen(
            'mysqldump -u ' + mysql_user + ' --password=' + mysql_pw + ' -h ' + hostname + ' -P ' + port + ' -e --opt '
            + '-c ' + database + ' > ' + out_file,
            shell=True)
        # Wait for completion
        p.communicate()
        # Check for errors
        if p.returncode != 0:
            raise
        click.echo('SQL backup performed successfully. Database: ' + database)
    except:
        click.echo('Error during SQL Backup. Database: ' + database)
        exit(2)


def sql_restore(hostname, port, mysql_user, mysql_pw, database, file):
    try:
        p = subprocess.Popen(
            'mysql -u ' + mysql_user + ' --password=' + mysql_pw + ' -h ' + hostname + ' -P ' + port + ' ' + database + ' < ' + file,
            shell=True)
        # Wait for completion
        p.communicate()
        # Check for errors
        if p.returncode != 0:
            raise
        click.echo('SQL restore performed successfully. Database: ' + database)
    except:
        click.echo('Error during SQL restore. Database: ' + database)
        exit(2)


def parse_hostport(hp):
    regex = re.compile(r'''
    (                            # first capture group = Addr
      \[                         # literal open bracket                       IPv6
        [:a-fA-F0-9]+            # one or more of these characters
      \]                         # literal close bracket
      |                          # ALTERNATELY
      (?:                        #                                            IPv4
        \d{1,3}\.                # one to three digits followed by a period
      ){3}                       # ...repeated three times
      \d{1,3}                    # followed by one to three digits
      |                          # ALTERNATELY
      [a-zA-Z0-9.]+              # one or more hostname chars ([\w\d\.])      Hostname
    )                            # end first capture group
    (?:                          
      :                          # a literal :
      (                          # second capture group = PORT
        \d+                      # one or more digits
      )                          # end second capture group
     )?                          # ...or not.''', re.X)

    m = regex.match(hp)
    addr, port = m.group(1, 2)
    try:
        return (addr, int(port))
    except TypeError:
        # port is None
        return (addr, None)


def main():
    cli(obj={})


if __name__ == '__main__':
    main()
