#!/bin/bash
#Generate Keypair 
algorithm=("dil" "ecdsa" "rsa")
#algorithm=("dil" "ecdsa")
#Test For normal condition
mkdir -p "keys/server"
mkdir -p "keys/client"

for alg in "${algorithm[@]}"
do
    keys="keys/server/$alg"
    for i in {1..3}
    do
        case "$alg" in
            "dil")
                python long-term.py $i -o $keys$i -pq --silent 
                ;;
            "rsa")
                python long-term.py $i -o $keys$i -rsa --silent
                ;;
            *)
                python long-term.py $i -o $keys$i --silent
                ;;
        esac
    done
done