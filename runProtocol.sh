#!/bin/bash

# Check if we have at least 3 arguments (URL, -f, and filename)
if [ $# -lt 3 ]; then
    echo "Usage: $0 <URL> -f <Private Key file location>" >&2
    exit 1
fi

# Get the URL (first argument)
url="$1"
shift  # Remove the URL from the argument list

# Check for -f option
if [ "$1" != "-f" ]; then
    echo "Error: Second argument must be -f" >&2
    exit 1
fi
shift  # Remove -f from the argument list

# Check for -show option
isShow="$2"

# Get the filename
keys="$1"

# Validate URL (very basic check)
if [[ ! $url =~ ^https?:// ]]; then
    echo "Error: Invalid URL. Must start with http:// or https://" >&2
    exit 1
fi

#Run the Verification Key exchange first and then run the protocol
if [[ isShow ]]; then
    python pkExchange.py $url -f "$keys.pub" &&
    python client.py $url -f $keys -show
else
    python pkExchange.py $url -f "$keys.pub" &&
    python client.py $url -f $keys
fi