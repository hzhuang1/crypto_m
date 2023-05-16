#!/bin/bash -e

ALG="aes-256-cbc"

echo "AES-128-CBC"
#openssl enc -aes-128-cbc -K e0e0e0e0f1f1f1f1 -iv 3031323334353637 -in message.plain -out message.enc
#openssl enc -aes-128-cbc -K e0e0e0e0f1f1f1f1 -iv 3031323334353637 -d -in message.enc -out message.out
#diff -puNr message.plain message.out

case $ALG in
	"md5")
		echo -n hello | openssl md5 -c
		;;
	"aes-128-cbc")
		# comes from testmgr.c of kernel crypto
		AES_128_CBC_KEY_STR=06a9214036b8a15b512e03d534120006
		AES_128_CBC_IV_STR=3dafba429d9eb430b422da802c9fac41
		openssl enc -aes-128-cbc -K ${AES_128_CBC_KEY_STR} -iv ${AES_128_CBC_IV_STR} -in aes_128_cbc.plain -out message.enc
		openssl enc -aes-128-cbc -K ${AES_128_CBC_KEY_STR} -iv ${AES_128_CBC_IV_STR} -d -in message.enc -out message.out
		diff -puNr aes_128_cbc.plain message.out
		;;
	"aes-256-cbc")
		# comes from testmgr.c of kernel crypto
		AES_256_CBC_KEY_STR=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
		AES_256_CBC_IV_STR=000102030405060708090a0b0c0d0e0f
		openssl enc -aes-256-cbc -K ${AES_256_CBC_KEY_STR} -iv ${AES_256_CBC_IV_STR} -in aes_256_cbc.plain -out message.enc
		openssl enc -aes-256-cbc -K ${AES_256_CBC_KEY_STR} -iv ${AES_256_CBC_IV_STR} -d -in message.enc -out message.out
		diff -puNr aes_256_cbc.plain message.out
		;;
	*)
		;;
esac
