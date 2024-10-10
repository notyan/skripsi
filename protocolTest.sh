#!/bin/bash
#Generate Keypair 
algorithm=("dilithium" "ecdsa" "rsa")
for alg in "${algorithm[@]}"
do
    for i in {1..3}
    do
        if [[ "$alg" == "dilithium" ]]: then
            python long-term.py $1 -o keys/cl_dilithium -pq;
            python client.py $1 -test -pq
        elif [[ "$alg" == "rsa" ]]: then
            python long-term.py $1 -o keys/cl_rsa -rsa;
            python client.py $1 -test -rsa;
        else
            python long-term.py $1 -o keys/cl_ecdsa;
            python client.py $1 -test;
        fi
    done
done