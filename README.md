# gocrypter

A simple Go program to encrypt all files under a working directory.

All files will be encrypted using AES algorithm. The encryption key will be encrypted with RSA algorithm and placed in the header of the cipher file.

RSA key pair will be generated with  a user-specified passphrase