#!/bin/bash
#Generate Keypair 
#algorithm=("dil" "ecdsa" "rsa")
algorithm=("dil" "ecdsa")
#Test For normal condition
mkdir -p "keys"
if [[ -z $1 ]]; then
    echo -e "Error: Url is required \nUsage: $0 <URL> " >&2
    exit 1
fi

for alg in "${algorithm[@]}"
do
    keys="keys/$alg"
    for i in {1..3}
    do
        case "$alg" in
            "dil")
                python long-term.py $i -o $keys$i -pq --silent && 
                python pkExchange.py $1 -f "$keys$i.pub" --silent &&
                python client.py $1 -bench -f $keys$i
                ;;
            "rsa")
                python long-term.py $i -o $keys$i -rsa --silent &&
                python pkExchange.py $1 -f "$keys$i.pub" --silent &&
                python client.py $1 -bench -f $keys$i
                ;;
            *)
                python long-term.py $i -o $keys$i --silent &&
                python pkExchange.py $1 -f "$keys$i.pub"  --silent &&
                python client.py $1 -bench -f $keys$i
                ;;
        esac
    done
done