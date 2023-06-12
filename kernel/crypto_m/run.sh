#!/bin/sh
BUF_SIZE=131072
ALG=$1
#DECRYPT=1
echo "Encrypt"
for i in 256 512 1024 2048 4096 8192 16384 32768 65536 131072
do
	echo "insert module for $ALG with $i-byte"
	sudo insmod ./hash_m.ko alg_name=$ALG buf_size=$i key_bits=128 encrypt_mode=1
	sudo rmmod hash_m
done
if [ ! -z $DECRYPT ]; then
	echo "Decrypt"
	for i in 256 512 1024 2048 4096 8192 16384 32768 65536 131072
	do
		echo "insert module for $ALG with $i-byte"
		sudo insmod ./hash_m.ko alg_name=$ALG buf_size=$i key_bits=128 encrypt_mode=0
		echo "remove module"
		sudo rmmod hash_m
		sudo dmesg | tail -n 3
	done
fi
rm -f /tmp/log
dmesg | tail -n 90 > /tmp/log
