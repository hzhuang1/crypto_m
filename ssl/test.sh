#!/bin/bash -e

ALG="md5"

echo -n hello | openssl md5 -c
