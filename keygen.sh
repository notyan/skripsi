#!/bin/bash
#Generate Keypair 
algorithm=("dilithium" "ecdsa" "rsa")
for alg in "${algorithm[@]}"
do
    for i in {1..3}
    do
        case "$alg" in
            "dilithium")
                python long-term.py $i -o ../keys/sv_dil$i -pq
                ;;
            "rsa")
                python long-term.py $i -o ../keys/sv_rsa$i -rsa
                ;;
            *)
                python long-term.py $i -o ../keys/sv_ecdsa$i
                ;;
        esac
    done
done