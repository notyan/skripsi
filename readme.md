# An Authenticated Key Exchange Protocol Simulation
Tested On Debian 12 (Bookworm)

## Installation
1. Run installation script  on both client and server
```
chmod +x install.sh && ./install.sh
```

## How to run
### Server
1. Install fastapi module
```
pip install fastapi[standard]==0.112.2
```
2. Run the server key generation
```
chmod +x serverKeygen.sh && ./serverKeygen.sh
```

3. Run the Server Api
```
python -m fastapi dev main.py --host 0.0.0.0 --port 8000
```
The api will run in port 8000

### Client
1. Generate Client Keypair
```
python long-term.py [security_level] -o [Output]
```
##### Flags
`-pq` Generate Dilithium keypair use 
`-rsa`  generate RSA keypair 
`--silent` Silence output

2. Exchange Verification Key with server
```
python pkExchange.py [url] -f [public_keys_files]
```

3. Run the simulation
```
python client.py [url] -f [private_keys_files]
```
##### Flags
`--test` Run test mode add

## Running Using Bash Script
### Run The protocol
```
chmod +x runProtocol.sh && ./runProtocol.sh [url] -f [Private Key gile]
```
Make sure to have the keypair berfore running the script, The script will automate the Verification Key exchange, and start the process
### Run Test
This script will run the whole protocol with all supported algorithm
```
chmod +x protocolTest.sh && /protocolTest.sh [url]
```
