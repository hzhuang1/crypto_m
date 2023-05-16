#!/bin/bash -e

ALG="md5"

echo "MD5:"
echo -n hello | openssl md5 -c

echo "AES-128-CBC"
#openssl enc -aes-128-cbc -K e0e0e0e0f1f1f1f1 -iv 3031323334353637 -in message.plain -out message.enc
#openssl enc -aes-128-cbc -K e0e0e0e0f1f1f1f1 -iv 3031323334353637 -d -in message.enc -out message.out
#diff -puNr message.plain message.out

AES_CBC_KEY_STR=06a9214036b8a15b512e03d534120006
AES_CBC_IV_STR=3dafba429d9eb430b422da802c9fac41
openssl enc -aes-128-cbc -K ${AES_CBC_KEY_STR} -iv ${AES_CBC_IV_STR} -in message.plain -out message.enc
openssl enc -aes-128-cbc -K ${AES_CBC_KEY_STR} -iv ${AES_CBC_IV_STR} -d -in message.enc -out message.out
