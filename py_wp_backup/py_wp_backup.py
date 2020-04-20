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
import click
import gnupg as gnupg_
from wpconfigr import WpConfigFile


# Used by fixFTP_TLS
class ReusedSslSocket(ssl.SSLSocket):
    def unwrap(self):
        pass


# Fixed an issue in the "FTP_TLS" class allowing the use of FTPS.
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


# Called when the program starts, this part allows you to configure the backup retention time.
@click.group(chain=True)
@click.option('--archive-retention', '-ar', type=int, default=7, help='Number in days during which the backup made is '
                                                                      'kept.')
@click.pass_context
def cli(ctx, archive_retention):
    click.clear()
    click.echo("                       _                _                \n"
               " __      ___ __       | |__   __ _  ___| | ___   _ _ __  \n"
               " \ \ /\ / / '_ \ _____| '_ \ / _` |/ __| |/ / | | | '_ \ \n"
               "  \ V  V /| |_) |_____| |_) | (_| | (__|   <| |_| | |_) |\n"
               "   \_/\_/ | .__/      |_.__/ \__,_|\___|_|\_\\__,_| .___/\n"
               "          |_|                                     |_|    \n")

    click.echo('Retention of backups for ' + str(archive_retention) + ' days')
    ctx.obj['archive_retention'] = archive_retention
    # No command has been used yet. If used this value will change to "True".
    # The "ctx" values allow you to share the values​between the different commands.
    ctx.obj['gpg_use'] = False
    ctx.obj['gpg_private_use'] = False
    ctx.obj['transfer_use'] = False
    ctx.obj['backup_use'] = False
    ctx.obj['restore_use'] = False

    required_transfer_cmd = 'transfer'
    required_backup_cmd = 'backup'

    if (required_transfer_cmd in sys.argv) and (required_backup_cmd not in sys.argv):
        click.echo('To use this command, the "backup" command is required and must be positioned before "transfer".',
                   err=True)
        exit(1)


@cli.command()
@click.option('--key-file', '-kf', type=click.Path(exists=True, readable=True, file_okay=True), default=None,
              help='File containing the GPG public key. Allows you to use the program without searching on a public '
                   'server.')
@click.option('--key-id', '-ki', type=str, default=None, help='ID of the key to import from the server.')
@click.option('--key-server', '-ks', type=str, default='keyserver.ubuntu.com', show_default=True,
              help='Server where the request is made to retrieve the public key.')
@click.option('--private-key-file', '-pkf', type=click.Path(exists=True, readable=True, file_okay=True),
              default=None, help='When restoring if your backup is encrypted, this option must be specified in order '
                                 'to decrypt the backup. This option retrieves the private key and imports it.')
@click.option('--private-key-pass', '-pkp', required=False, hide_input=True, help='Secret phrase to import the private '
                                                                                  'key. For security reasons, '
                                                                                  'it is recommended not to define it, '
                                                                                  'it will be requested in a secure '
                                                                                  'manner at the time of execution.')
@click.option('--private-key-file-remove', '-pkf', default=True, help='Once the backup is restored you can delete the '
                                                                      'private key from GPG. If you use this option, '
                                                                      'please also delete your file containing the '
                                                                      'private key in your own secure manner.')
@click.pass_context
def gpg(ctx, key_server, key_id, key_file, private_key_file, private_key_file_remove, private_key_pass):
    # The gpg command is used.
    ctx.obj['gpg_use'] = True
    key_fingerprint = None

    click.echo("GPG initialization...")

    # Initializing GPG
    gpg = gnupg_.GPG()

    # Export of GPG to be able to use it in other commands.
    ctx.obj['gpg'] = gpg

    # If a key has been defined
    if (key_id is not None) and (key_file is None) and (private_key_file is None):

        public_key_exist = None
        public_key_exist = gpg.list_keys(keys=key_id)

        # Check that it does not already exist in GPG.
        if (public_key_exist is not None) and (len(public_key_exist.fingerprints) == 1):
            click.echo('The key: "' + key_id + '" already exists')
            key_fingerprint = public_key_exist[0]['fingerprint']
        else:
            click.echo('Reception of the key: "' + key_id + '" on the "' + key_server + '" server...')
            imported_key = gpg.recv_keys(key_server, key_id)

            if (imported_key.count != 1) or len(imported_key.results != 1):
                click.echo('Unable to import public key (' + key_id + ') from public server: ' + key_server
                           + '. GPG Error: ' + imported_key.stderr, err=True)
                exit(1)
            else:
                key_fingerprint = imported_key.results[0]['fingerprint']

    elif (key_id is None) and (key_file is not None) and (private_key_file is None):

        key_fingerprint = None

        # If a file has been specified for the public key
        click.echo('Import of the key located in the file: "' + key_file + '"')
        # Read the content and import the key
        with open(key_file) as f:
            key_data = f.read()

        try:
            imported_key = gpg.import_keys(key_data)
            key_fingerprint = imported_key.results[0]['fingerprint']
        except:
            click.echo('Unable to import public key. GPG Error: ' + imported_key.stderr, err=True)
            exit(1)
    elif (key_id is None) and (key_file is None) and (private_key_file is not None):
        # import private key
        ctx.obj['gpg_private_use'] = True
        ctx.obj['gpg_private_key_pass'] = private_key_pass
        ctx.obj['gpg_private_key_file_remove'] = private_key_file_remove

        if private_key_file is not None:
            click.echo('Import of the private key located in the file: "' + private_key_file + '"')
            with open(private_key_file) as f:
                private_key_data = f.read()

            # Try to import the private key
            try:
                imported_private_key = gpg.import_keys(private_key_data)
                ctx.obj['gpg_private_key_fingerprints'] = imported_private_key.fingerprints[0]
            except:
                click.echo('Unable to import private key. GPG Error: ' + imported_private_key.stderr, err=True)
                exit(1)
            else:
                click.echo('The private key has been successfully imported. Fingerprint: '
                           + imported_private_key.fingerprints[0])
    else:
        click.echo('You must specify the GPG public --key-id or --key-file.', err=True)
        exit(1)

    # Share key_id for others commands
    if key_fingerprint is not None:
        ctx.obj['gpg_key_id'] = key_fingerprint
        click.echo('The key has been successfully imported/defined. Fingerprint: ' + key_fingerprint)


@cli.command()
@click.option('--host', '-h', type=str, required=True, help='FTP(s) server address.')
@click.option('--user', '-u', type=str, required=True, help='Username for FTP(s).')
@click.option('--passwd', '-p', type=str, required=True, help='Password for FTP(s).')
@click.option('--timeout', '-t', type=int, default=5, required=True, help='Timeout for FTP(s).', show_default=True)
@click.option('--mode', '-m', type=str, default='ftps', required=True, show_default=True, help='Transfer mode, "ftps" '
                                                                                               'or "ftp".')
@click.option('--remove-local', '-rml', type=bool, default=False, required=True, show_default=True, help='Delete '
                                                                                                         'files after'
                                                                                                         ' transfer.')
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
@click.option('--wp', '-w', type=bool, default=True, required=True, help='Activate WordPress backup.',
              show_default=True)
@click.option('--sql', '-s', type=bool, default=True, required=True,
              help='Activate the backup of the WordPress database.', show_default=True)
@click.option('--wp-dir', '-wd', type=click.Path(exists=True, readable=True, dir_okay=True),
              help='WordPress path (used for website backup and WordPress database).', required=True)
@click.option('--archive-dir', '-ad', type=click.Path(exists=True, writable=True, dir_okay=True),
              help='Local path where backups are stored.', required=True)
@click.pass_context
def backup(ctx, wp, sql, wp_dir, archive_dir):
    ctx.obj['backup_use'] = True

    # Check if the mandatory arguments are valid.
    if (wp is False) and (sql is False):
        click.echo('Please know at least one command for backup: "--wp" or "--sql" to use the backup command.')

    click.echo('Backup archive directory: ' + archive_dir)
    click.echo('Backup verification greater than ' + str(ctx.obj['archive_retention']) + ' day(s)')

    files = []
    if ctx.obj['transfer_use']:
        # If the "transfer" command is used check the retention on the FTP(s).
        ftp = ftp_connect(ctx.obj['transfer_host'], ctx.obj['transfer_user'], ctx.obj['transfer_passwd'],
                          ctx.obj['transfer_timeout'], ctx.obj['transfer_ftps'], close_immediately=False)
        try:
            files = ftp.nlst()
        except ftplib.error_perm as resp:
            click.echo('Unable to access FTP file (s) to verify retention.', err=True)
        else:
            for f in files:
                if f.endswith('.tar.gz'):
                    old_or_not = check_old_backup(f, ctx.obj['archive_retention'])
                    if old_or_not:
                        ftp.delete(f)
                        click.echo('Remote backup deleted: "' + f + '"')

    # Check the retention in the local folder.
    for file in os.listdir(archive_dir):
        if file.endswith(".tar.gz"):
            old_or_not = check_old_backup(file, ctx.obj['archive_retention'])
            if old_or_not:
                os.remove(os.path.join(archive_dir, file))
                click.echo('Local backup deleted: "' + file + '"')

    if wp:
        # Launch of WordPress site backup
        click.echo('WordPress backup launch...')
        click.echo('Installation directory: ' + wp_dir)

        # Define the file name, with: extensions, date, encrypted name.
        WP_FILENAME_PREFIX = "WP_BACKUP_"
        WP_FILENAME = WP_FILENAME_PREFIX + str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
        WP_UNCRYPTED_FILENAME = WP_FILENAME
        WP_UNCRYPTED_FILENAME_EXT = WP_UNCRYPTED_FILENAME + ".tar.gz"
        WP_CRYPTED_FILENAME_EXT = WP_FILENAME + ".encrypted" + ".tar.gz"
        WP_UNCRYPTED_PATH_FILENAME = os.path.join(archive_dir, WP_UNCRYPTED_FILENAME_EXT)
        WP_CRYPTED_PATH_FILENAME = os.path.join(archive_dir, WP_CRYPTED_FILENAME_EXT)

        # If gpg is used encrypted file names
        if ctx.obj['gpg_use']:
            wp_backup_filename = WP_CRYPTED_FILENAME_EXT
            wp_backup_file_path = WP_CRYPTED_PATH_FILENAME
        else:
            wp_backup_filename = WP_UNCRYPTED_FILENAME_EXT
            wp_backup_file_path = WP_UNCRYPTED_PATH_FILENAME

        # Compress the archive (tar.gz)
        wp_backup_file = tar([wp_dir], WP_UNCRYPTED_PATH_FILENAME)

        # If gpg used, encrypt the archive.
        if ctx.obj['gpg_use']:
            encrypt_with_gpg(ctx.obj['gpg'], wp_backup_file, key=ctx.obj['gpg_key_id'],
                             remove_file=True,
                             output_path=WP_CRYPTED_PATH_FILENAME)

        # If "transfer" is used, transfer the archive to FTP(s)
        if ctx.obj['transfer_use']:
            ftp = ftp_connect(ctx.obj['transfer_host'], ctx.obj['transfer_user'], ctx.obj['transfer_passwd'],
                              ctx.obj['transfer_timeout'], ctx.obj['transfer_ftps'], close_immediately=False)
            ftp_transfer_file(ftp, wp_backup_filename, wp_backup_file_path,
                              remove_local_file=ctx.obj['transfer_remove_local'], close=True)

    if sql:
        # Launch of database backup
        click.echo('Database backup launch...')

        # Define the file name, with: extensions, date, encrypted name.
        SQL_FILENAME_PREFIX = "SQL_BACKUP_"
        SQL_FILENAME = SQL_FILENAME_PREFIX + str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
        SQL_UNCRYPTED_FILENAME = SQL_FILENAME
        SQL_UNCRYPTED_FILENAME_EXT = SQL_UNCRYPTED_FILENAME + ".tar.gz"
        SQL_CRYPTED_FILENAME_EXT = SQL_FILENAME + ".encrypted" + ".tar.gz"
        SQL_PATH_FILENAME = os.path.join(archive_dir, SQL_FILENAME + '.sql')
        SQL_UNCRYPTED_PATH_FILENAME = os.path.join(archive_dir, SQL_UNCRYPTED_FILENAME_EXT)
        SQL_CRYPTED_PATH_FILENAME = os.path.join(archive_dir, SQL_CRYPTED_FILENAME_EXT)

        # If gpg is used encrypted file names
        if ctx.obj['gpg_use']:
            sql_backup_filename = SQL_CRYPTED_FILENAME_EXT
            sql_backup_file_path = SQL_CRYPTED_PATH_FILENAME
        else:
            sql_backup_filename = SQL_UNCRYPTED_FILENAME_EXT
            sql_backup_file_path = SQL_UNCRYPTED_PATH_FILENAME

        # Retrieve information from the database in "wp-config.php"
        wp_config = WpConfigFile(os.path.join(wp_dir, 'wp-config.php'))
        wp_db_host_port = parse_hostport(wp_config.get('DB_HOST'))
        wp_db_host = wp_db_host_port[0]

        if wp_db_host_port[1] is None:
            wp_db_port = '3306'
        else:
            wp_db_port = wp_db_host_port[1]

        # Dump the database
        sql_backup(hostname=wp_db_host, port=wp_db_port, mysql_user=wp_config.get('DB_USER'),
                   mysql_pw=wp_config.get('DB_PASSWORD'), database=wp_config.get('DB_NAME'), out_file=SQL_PATH_FILENAME)

        # Compress the archive (tar.gz)
        sql_backup_file = tar([SQL_PATH_FILENAME], SQL_UNCRYPTED_PATH_FILENAME, accname=SQL_UNCRYPTED_FILENAME + '.sql')

        # Delete the uncompressed file.
        remove(SQL_PATH_FILENAME)

        # If gpg used, encrypt the archive.
        if ctx.obj['gpg_use']:
            encrypt_with_gpg(ctx.obj['gpg'], sql_backup_file, key=ctx.obj['gpg_key_id'],
                             remove_file=True,
                             output_path=SQL_CRYPTED_PATH_FILENAME)

        # If "transfer" is used, transfer the archive to FTP(s)
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

    # check that one of the options is specified
    if (wp_archive is None) and (sql_archive is None):
        click.echo(
            'Please know at least one command for backup: "--wp-archive" or "--sql-archive" to use the restore command.'
            , err=True)
        exit(1)

    # '--wp-dir' must be specified
    if (sql_archive is not None or wp_archive is not None) and (wp_dir is None):
        click.echo('To use restore please specify the option "--wp-dir"', err=True)
        exit(1)

    if (ctx.obj['gpg_use']) and (ctx.obj['gpg_private_use'] is not False):
        click.echo('To use gpg with "restore", please specify a private key', err=True)
        exit(1)

    if wp_archive is not None:
        # if gpg is used
        if ctx.obj['gpg_use'] and ctx.obj['gpg_private_use']:
            # open archive
            stream = open(wp_archive, "rb")

            # create temporary file
            try:
                tmp_file = tempfile.NamedTemporaryFile(delete=True, suffix=".tar.gz")
            except:
                click.echo('Unable to create temporary file', err=True)
                exit(1)
            else:
                click.echo('Temporary file created: "' + tmp_file.name + '"')

            click.echo('Attempting to decrypt the file: ' + wp_archive)

            # decrypt the archive
            try:
                ctx.obj['gpg'].decrypt_file(stream, passphrase=ctx.obj['gpg_private_key_pass'],
                                            output=tmp_file.name)
                tar_decompress(tmp_file.name, wp_dir)
            except:
                click.echo('Unable to decrypt the file', err=True)
                exit(1)
            else:
                click.echo('File successfully decrypted: ' + wp_archive)
            finally:
                tmp_file.close()
                stream.close()

            # Delete the private key from the secure "gpg" keychain if requested.
            if ctx.obj['gpg_private_key_file_remove']:
                ctx.obj['gpg'].delete_keys(ctx.obj['gpg_private_key_fingerprints'], secret=True,
                                           passphrase=ctx.obj['gpg_private_key_pass'])
                click.echo('Removed GPG private key: ' + ctx.obj['gpg_private_key_fingerprints'])
        else:
            # Extract files from the archive
            tar_decompress(wp_archive, wp_dir)

        click.echo('WordPress archive restored to location: "' + wp_dir + '"')

    if sql_archive is not None:
        # if gpg is used
        if ctx.obj['gpg_use']:
            # open archive
            sql_stream = open(sql_archive, "rb")

            # create temporary file
            try:
                sql_compress_tmp_file = tempfile.NamedTemporaryFile(delete=True, suffix=".tar.gz")
            except:
                click.echo('Unable to create temporary file', err=True)
                exit(1)
            else:
                click.echo('Temporary file created: "' + sql_compress_tmp_file.name + '"')

            click.echo('Attempting to decrypt the file: ' + sql_archive)

            try:
                ctx.obj['gpg'].decrypt_file(sql_stream, passphrase=ctx.obj['gpg_private_key_pass'],
                                            output=sql_compress_tmp_file.name)
                # Define the directory where the .SQL file is located
                sql_compress_path_file = sql_compress_tmp_file.name
            except:
                click.echo('Unable to decrypt the file', err=True)
                exit(1)
            else:
                click.echo('File successfully decrypted: ' + sql_archive)
            finally:
                sql_stream.close()

            # Delete the private key from the secure "gpg" keychain if requested.
            if ctx.obj['gpg_private_key_file_remove']:
                ctx.obj['gpg'].delete_keys(ctx.obj['gpg_private_key_fingerprints'], secret=True,
                                           passphrase=ctx.obj['gpg_private_key_pass'])
                click.echo('Removed GPG private key: ' + ctx.obj['gpg_private_key_fingerprints'])
        else:
            # Define the directory where the .SQL file is located
            sql_compress_path_file = sql_archive

        # Create a temporary folder that will contain the SQL file.
        try:
            sql_tmp_dir_file = tempfile.TemporaryDirectory()
        except:
            click.echo('Unable to create temporary directory', err=True)
            exit(1)
        else:
            click.echo('Temporary directory created: "' + sql_tmp_dir_file.name + '"')

        sql_tmp_file = os.path.basename(sql_archive.replace('.encrypted.tar.gz', ''))
        sql_file = os.path.join(sql_tmp_dir_file.name, sql_tmp_file) + '.sql'

        # Extract the .SQL file from the archive to the temporary folder
        tar_decompress(sql_compress_path_file, sql_tmp_dir_file.name)

        if ctx.obj['gpg_use']:
            # If "gpg" is used, close the encrypted archive once extracted
            sql_compress_tmp_file.close()

        # Retrieve information from the database in "wp-config.php"
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

        # Restore the database to the defined database
        sql_restore(hostname=wp_db_host, port=wp_db_port, mysql_user=wp_config.get('DB_USER'),
                    mysql_pw=wp_config.get('DB_PASSWORD'), database=wp_db_name, file=sql_file)

        # Delete the archive
        remove(sql_tmp_dir_file.name)


def tar(src, out, mode='x:gz', accname=None):
    """ Create a 'tar.gz' archive """
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
    """ Extract files from a 'tar.gz' archive """
    try:
        click.echo('Decompressing the archive: "' + file + '"')
        tf = tarfile.open(file)
        tf.extractall(path=to)
    except:
        click.echo('Unable to decompress the archive', err=True)
        exit(1)
    else:
        click.echo('File decompression performed: "' + file + '"')
    finally:
        tf.close()


def encrypt_with_gpg(gpg, path, key, remove_file=False, output_path=None):
    """ Encrypted file using gpg """
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
        exit(1)

    if remove_file:
        remove(path)


def remove(path):
    """ Remove the file or directory """
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
    """ Connect to an FTP(s) """
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
            ftp = ftplib.FTP(host=host, timeout=timeout)
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
    """ Upload a file to the FTP(s) server """
    ftp.storbinary('STOR ' + filename, open(file_path, 'rb'))
    if remove_local_file:
        remove(file_path)
    if close:
        ftp.close()


def sql_backup(hostname, port, mysql_user, mysql_pw, database, out_file):
    """ Dump a database """
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


def check_old_backup(file, days):
    """ Check if the file is older than "x" days """
    # Delete unwanted items to recover the date from the file
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


def sql_restore(hostname, port, mysql_user, mysql_pw, database, file):
    """ Restore a database """
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
    """ Separate address and port """
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
