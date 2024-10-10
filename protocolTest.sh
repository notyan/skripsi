#!/bin/bash
#Generate Keypair 
algorithm=("dilithium" "ecdsa" "rsa")
#algorithm=("dilithium" "ecdsa")
#Test For normal condition
for alg in "${algorithm[@]}"
do
    for i in {1..3}
    do
        case "$alg" in
            "dilithium")
                python long-term.py $i -o keys/cl_dilithium -pq --silent && 
                python pkExchange.py -f keys/cl_dilithium.pub --silent
                python client.py $i -test -pq
                ;;
            "rsa")
                python long-term.py $i -o keys/cl_rsa -rsa --silent &&
                python pkExchange.py -f keys/cl_rsa.pub --silent
                python client.py $i -test -rsa
                ;;
            *)
                python long-term.py $i -o keys/cl_ecdsa  --silent &&
                python pkExchange.py -f keys/cl_ecdsa.pub  --silent
                python client.py $i -test
                ;;
        esac
    done
done