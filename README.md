# py-wp-backup

## Installation
Install zip/unzip
```bash
apt install -y zip unzip
```

Download the program and extract (go to the folder where you want to install the program.)

```bash
wget --no-check-certificate https://github.com/frnode/py-wp-backup/archive/master.zip && unzip master.zip && mv py-wp-backup-master py-wp-backup && rm master.zip
```

Install the program

```bash
cd py-wp-backup && pip3 install -e .
```

## Use
See how to use the program
```bash
wp-backup --help
```
```bash
wp-backup subcommand --help
```

## Example
Create a backup with the site and the database, locally.
```bash
wp-backup --archive-retention "NUMBER OF DAYS TO KEEP BACKUPS" backup --wp 1 --sql 1 --wp-dir "WORDPRESS SITE PATH" --archive-dir PATH WHERE BACKUPS ARE STORED"
```

Create a backup with the site and the database, locally with a copy on FTP server.
```bash
wp-backup --archive-retention "NUMBER OF DAYS TO KEEP BACKUPS" transfer --host "HOST" --user "FTP USERNAME" --passwd "FTP PASSWORD" --remove-local 0 backup --wp 1 --sql 1 --wp-dir "WORDPRESS SITE PATH" --archive-dir "PATH WHERE BACKUPS ARE STORED"
```

Restore a backup
```bash
wp-backup restore --wp-archive "WORDPRESS SITE ARCHIVE PATH" --sql-archive "SQL ARCHIVE PATH" --wp-dir "WORDPRESS SITE PATH" --sql-database "NAME OF THE DATABASE ON WHICH RESTORE THE DATA"
```

Create a backup with the site and the database, locally with a copy on FTP server and encryption.
```bash
wp-backup --archive-retention "NUMBER OF DAYS TO KEEP BACKUPS" gpg --key-file "PUBLIC KEY PATH" transfer --host "HOST" --user "FTP USERNAME" --passwd "FTP PASSWORD" --remove-local 0 backup --wp 1 --sql 1 --wp-dir "WORDPRESS SITE PATH" --archive-dir "PATH WHERE BACKUPS ARE STORED"
```

Restore an encrypted backup
```bash
wp-backup gpg --private-key-file "PRIVATE KEY PATH" --private-key-pass restore --wp-archive "WORDPRESS SITE ARCHIVE PATH" --sql-archive "SQL ARCHIVE PATH" --wp-dir "RESTORATION PATH FOR THE SITE" --sql-database "NAME OF THE DATABASE ON WHICH RESTORE THE DATA"

# The private key password will be requested
```