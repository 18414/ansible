#!/bin/bash


dt=`date +%F`

sed -i "s/abc/${dt}/g" old.txt
