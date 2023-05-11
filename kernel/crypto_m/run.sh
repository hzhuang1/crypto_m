#!/bin/sh
BUF_SIZE=131072
#BUF_SIZE=8192
#ALG="md5-generic"
#ALG="sha1-generic"
#ALG="sha256-generic"
#ALG="sha512-generic"
#ALG="xxhash64-generic"
#ALG="chacha20-generic"
#ALG="md4-generic"
ALG="xts(aes)"
for i in 256 512 1024 2048 4096 8192 16384 32768 65536 131072
do
	echo "insert module for $ALG with $i-byte"
	sudo insmod ./hash_m.ko alg_name=$ALG buf_size=$i
	sudo dmesg | tail -n 4
	echo "remove module"
	sudo rmmod hash_m
	sudo dmesg | tail -n 3
done
