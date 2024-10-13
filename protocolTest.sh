#!/bin/bash
#Generate Keypair 
algorithm=("dilithium" "ecdsa" "rsa")
#algorithm=("dilithium")
#Test For normal condition
mkdir -p "keys"
for alg in "${algorithm[@]}"
do
    for i in {1..3}
    keys="keys/$alg$i"
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