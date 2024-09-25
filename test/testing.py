from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from memory_profiler import memory_usage
import numpy as np

def benchmark_aes(key, data):
    encryptor = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return encrypted_data

def measure_memory_usage(runs=5):
    key = b'Sixteen byte key'
    data = b'Example data to encrypt'
    
    peak_memory_usage = []

    for _ in range(runs):
        mem_usage = memory_usage((benchmark_aes, (key, data)), max_usage=True)
        peak_memory_usage.append(mem_usage[0])  # Store the peak memory usage

    return peak_memory_usage

# Call the function to measure memory usage multiple times
num_runs = 5  # Number of times to run the profiling
results = measure_memory_usage(runs=num_runs)

# Calculate average and standard deviation
average_memory = np.mean(results)
std_dev_memory = np.std(results)

print(f"Peak Memory Usage Results: {results}")
print(f"Average Peak Memory Usage: {average_memory:.2f} MiB")
print(f"Standard Deviation of Peak Memory Usage: {std_dev_memory:.2f} MiB")
