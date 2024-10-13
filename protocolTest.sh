#!/bin/bash
#Generate Keypair 
#algorithm=("dil" "ecdsa" "rsa")
algorithm=("dil")
#Test For normal condition
mkdir -p "keys"
for alg in "${algorithm[@]}"
do
    keys="keys/$alg"
    for i in {1..3}
    do
        case "$alg" in
            "dil")
                python long-term.py $i -o $keys$i -pq --silent && 
                python pkExchange.py $1 -f "$keys$i.pub" --silent &&
                python client.py $1 -test -f $keys$i
                ;;
            "rsa")
                python long-term.py $i -o $keys$i -rsa --silent &&
                python pkExchange.py $1 -f "$keys$i.pub" --silent &&
                python client.py $1 -test -f $keys$i
                ;;
            *)
                python long-term.py $i -o $keys$i --silent &&
                python pkExchange.py $1 -f "$keys$i.pub"  --silent &&
                python client.py $1 -test -f $keys$i
                ;;
        esac
    done
done