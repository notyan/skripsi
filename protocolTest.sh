#!/bin/bash
#Generate Keypair 
algorithm=("dilithium" "ecdsa" "rsa")
#algorithm=("dilithium" "ecdsa")
#Test For normal condition
for alg in "${algorithm[@]}"
do
    keys="keys/cl_$alg"
    for i in {1..3}
    do
        case "$alg" in
            "dilithium")
                python long-term.py $i -o $keys -pq --silent && 
                python pkExchange.py $1 -f "$keys.pub" --silent &&
                python client.py $1 -test -f $keys
                ;;
            "rsa")
                python long-term.py $i -o $keys -rsa --silent &&
                python pkExchange.py $1 -f "$keys.pub" --silent &&
                python client.py $1 -test -f $keys
                ;;
            *)
                python long-term.py $i -o $keys --silent &&
                python pkExchange.py $1 -f "$keys.pub"  --silent &&
                python client.py $1 -test -f $keys
                ;;
        esac
    done
done