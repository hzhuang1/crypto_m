```
$make

$echo "insert module"
$sudo insmod ./hash_m.ko hash_name="md5" buf_size=8192
$sudo dmesg | tail -n 3
$echo "remove module"
$sudo rmmod hash_m
$sudo dmesg | tail -n 3
```
