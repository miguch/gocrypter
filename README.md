# gocrypter

A simple Go program to encrypt all files under a working directory.

All files will be encrypted using AES algorithm. The encryption key will be encrypted with RSA algorithm and placed in the header of the cipher file, together with the iv and encrypted filename.

Each file will be divided into chunks of 4 MB, each chunk will be encrypted separately.

RSA key pair will be generated with  a user-specified passphrase

### Options

- `-d` Program will decrypt files with this flag specified
- `-j` Followed by the number of parallel jobs
- `-f` Followed by a filename, program will only operate on the specified file, not the whole current directory.

The last argument of the program should be the passphrase.

### Examples

```
gocrypter -j 4 123123
```
Encrypt the whole current directory with 123123 as passphrase using 4 parallel jobs.

```
gocrypter -d -f 1.ci 123123
```
Decrypt file 1.ci using 123123 as passphrase


