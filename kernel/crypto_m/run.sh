#!/bin/sh
BUF_SIZE=131072
ALG="sha3-512-ce"
echo "Encrypt"
for i in 256 512 1024 2048 4096 8192 16384 32768 65536 131072
do
	echo "insert module for $ALG with $i-byte"
	sudo insmod ./hash_m.ko alg_name=$ALG buf_size=$i key_bits=192 encrypt_mode=1
	sudo rmmod hash_m
done
echo "Decrypt"
for i in 256 512 1024 2048 4096 8192 16384 32768 65536 131072
do
	echo "insert module for $ALG with $i-byte"
	sudo insmod ./hash_m.ko alg_name=$ALG buf_size=$i key_bits=192 encrypt_mode=0
	echo "remove module"
	sudo rmmod hash_m
	sudo dmesg | tail -n 3
done
