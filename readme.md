# An Authenticated Key Exchange Protocol Simulation

## Installation
1. Run installation script  on both client and server
```
sudo chmod +x install.sh && sudo ./install.sh
```

### How to run
#### - Server
1. Install fastapi module
```
pip install fastapi==0.112.2
```

2. Run the Api
```
python -m fastapi dev main.py --host 0.0.0.0. --port 8000
```
The api will run in port 8000

#### - Client
1. Generate Client Keypair
```
python long-term.py [security_level] -o [Output]
```
To generate Dilithium keypair use `-pq` flag
To generate RSA keypair use `-rsa` flag
To silence the output add `--silent` flag
2. Exchange Verification Key with server
```
python pkExchange.py [url] -f [public_keys_files]
```

3. Run the simulation
```
python client.py [url] -f [private_keys_files]
```
To run test mode add `--test` flag
