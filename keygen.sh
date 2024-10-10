#!/bin/bash
#Generate Keypair 
algorithm=("dilithium" "ecdsa" "rsa")
for alg in "${algorithm[@]}"
do
    for i in {1..3}
    do
        case "$alg" in
            "dilithium")
                python long-term.py $i -o ../keys/dil$i -pq
                ;;
            "rsa")
                python long-term.py $i -o ../keys/rsa$i -rsa
                ;;
            *)
                python long-term.py $i -o ../keys/ecdsa$i
                ;;
        esac
    done
done