from utils import pem

def writes(pq, isPub, key, path, printer=True): 
    if isPub:
        f = open(path + ".pub", "w")
        if pq:
            f.write(pem.pk_bytes_to_pem(key))
        else:
            f.write(pem.serialize(key, 1).decode("utf-8"))
        f.close()
        if printer:
            print("Public Key Written into " + path + ".pub")
    else:
        f = open(path, "w")
        if pq:
            f.write(pem.sk_bytes_to_pem(key))
        else:
            f.write(pem.serialize(key, 0).decode("utf-8"))  
        f.close()
        if printer:
            print("Private Key Written into " + path)

def reads(pq, isPub, path):
    if isPub:
        file = open(path + ".pub", "r")
        vk_pem = file.read()
        if pq:
            vk = pem.pk_pem_to_bytes(vk_pem)
        else:
            vk = pem.pem_to_key(vk_pem.encode(), 1)
        file.close()
        return vk
    else:
        #Read the Pem FIle
        file = open(path, "r")
        ssk_pem = file.read()
        if pq:
            #Change the pem format into bytes
            ssk = pem.sk_pem_to_bytes(ssk_pem)
        else:
            #Change the pem format into Instance
            ssk = pem.pem_to_key(ssk_pem.encode(), 0)
        file.close()
        return ssk