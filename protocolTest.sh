#!/bin/bash
#Generate Keypair 
algorithm=("dilithium" "ecdsa" "rsa")
for alg in "${algorithm[@]}"
do
    for i in {1..3}
    do
        case "$alg" in
            "dilithium")
                python long-term.py $1 -o keys/cl_dilithium -pq;
                python client.py $1 -test -pq
                ;;
            "rsa")
                python long-term.py $1 -o keys/cl_rsa -rsa;
                python client.py $1 -test -rsa
                ;;
            *)
                python long-term.py $1 -o keys/cl_ecdsa;
                python client.py $1 -test
                ;;
        esac
    done
done