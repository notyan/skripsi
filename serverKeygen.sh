#!/bin/bash
#Generate Keypair 
algorithm=("dil" "ecdsa" "rsa")
#algorithm=("dil" "ecdsa")
#Test For normal condition
mkdir -p "keys/server"
mkdir -p "keys/client"

for alg in "${algorithm[@]}"
do
    for i in {1..3}
    keys="keys/server/$alg$i"
    do
        case "$alg" in
            "dil")
                python long-term.py $i -o $keys -pq --silent 
                ;;
            "rsa")
                python long-term.py $i -o $keys -rsa --silent
                ;;
            *)
                python long-term.py $i -o $keys --silent
                ;;
        esac
    done
done