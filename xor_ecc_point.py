#This document demonstrates that an elliptic curve point can be multiplied with a hash value, and the resultant can be XORed with other values,
#ensuring the protocol's feasibility and correctness.
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
# Step 1: Generate Random values: 
#pi, DID_i, n_i, tau_i, T_i (Current timestamp) 
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
# Step 2: Initialize the Elliptic Curve (SECP256k1) and Base Point (G)
# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
# Step 3: Computes SID_{i} == DID_{i} \oplus H(SID_{j}\|n_{i}\|\tau_{i}\|T_{i}).P_{pub} and DM_{i1} = H(SID_{j}\|n_{i}\|\tau_{i}\|T_{i}).G
# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
# Step 4: Determines DID_{i} from SID_{i} and DM_{i1}, while already having pi 
# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
# $DID_{i} = SID_{i} \oplus DM_{i1}.\pi$
# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

import hashlib
import time
import os
from ecdsa import SECP256k1, ellipticcurve

# Helper functions
def random_160bit_number():
    return int.from_bytes(os.urandom(20), 'big')

def hash_function(data):
    return hashlib.sha256(data).digest()

def point_to_bytes(point):
    x_bytes = point.x().to_bytes(32, 'big')
    y_bytes = point.y().to_bytes(32, 'big')
    return x_bytes + y_bytes

def bytes_to_point(bytes_data, curve):
    x = int.from_bytes(bytes_data[:32], 'big')
    y = int.from_bytes(bytes_data[32:], 'big')
    return ellipticcurve.Point(curve.curve, x, y)

# Generate random 160-bit values
pi = random_160bit_number()
DID_i = random_160bit_number()
n_i = random_160bit_number()
tau_i = random_160bit_number()  

# Generate current timestamp
T_i = int(time.time())

# Initialize elliptic curve and base point G
curve = SECP256k1
G = curve.generator

# Compute P_pub
P_pub = G * pi

# Hash SID_j, n_i, tau_i, T_i
# Assuming SID_j is given or another random 160-bit number
SID_j = random_160bit_number()
SID_j_bytes = SID_j.to_bytes(20, 'big')
n_i_bytes = n_i.to_bytes(20, 'big')
tau_i_bytes = tau_i.to_bytes(20, 'big')
T_i_bytes = T_i.to_bytes(8, 'big')

hash_input = SID_j_bytes + n_i_bytes + tau_i_bytes + T_i_bytes
hash_output = hash_function(hash_input)
hash_output_int = int.from_bytes(hash_output, 'big')

# Compute SID_i
P_pub_hash = P_pub * hash_output_int
P_pub_hash_bytes = point_to_bytes(P_pub_hash)
SID_i = DID_i ^ int.from_bytes(P_pub_hash_bytes[:20], 'big')

# Compute DM_i1
DM_i1 = G * hash_output_int

# Deduce DID_i
DM_i1_pi = DM_i1 * pi
DM_i1_pi_bytes = point_to_bytes(DM_i1_pi)
DID_i_deduced = SID_i ^ int.from_bytes(DM_i1_pi_bytes[:20], 'big')

# Print results
print(f"pi: {pi}")
print(f"P_pub: ({P_pub.x()}, {P_pub.y()})")
print(f"DID_i: {DID_i}")
print(f"n_i: {n_i}")
print(f"tau_i: {tau_i}")
print(f"T_i: {T_i}")
print(f"SID_i: {SID_i}")
print(f"DM_i1: ({DM_i1.x()}, {DM_i1.y()})")
print(f"DID_i_deduced: {DID_i_deduced}")

# Check if deduced DID_i is correct
assert DID_i == DID_i_deduced, "DID_i deduced does not match the original DID_i"
