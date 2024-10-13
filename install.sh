apt update && apt upgrade

#install dependencies
apt-get install wget git cmake build-essential libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev liblzma-dev -y

#Change python version into 3.12.5
cd ..
wget -O Python-3.12.5.tgz https://www.python.org/ftp/python/3.12.5/Python-3.12.5.tgz
tar xvf Python-3.12.5.tgz; cd Python-3.12.5 && ./configure --enable-optimizations
make altinstall
update-alternatives --install /usr/bin/python python /usr/local/bin/python3.12 1

#install pip
/usr/local/bin/python3.12 -m pip install --upgrade pip
update-alternatives --install /usr/bin/pip pip /usr/local/bin/pip3.12 1

#Creating virtual env
cd ..
python -m venv venv
. venv/bin/activate
python -m ensurepip --upgrade

#installing liboqs and liboqs python
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python && pip install . && cd ..
python liboqs-python/examples/kem.py

#installing other python dependencies
cd skripsi
pip install -r requirements.txt