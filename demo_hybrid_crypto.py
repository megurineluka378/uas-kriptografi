# Demo pendukung: Hybrid Encryption untuk Transaksi (AES-GCM + RSA-OAEP)                                                                                                                     
# Jalu Yudha Prasetya                                                                                                                                                                        
from cryptography.hazmat.primitives.asymmetric import rsa, padding                                                                                                                           
from cryptography.hazmat.primitives import hashes, serialization                                                                                                                             
from cryptography.hazmat.primitives.ciphers.aead import AESGCM                                                                                                                               
import os                                                                                                                                                                                    
                                                                                                                                                                                             
# 1. Kunci RSA bank (di produksi: disimpan di HSM)                                                                                                                                           
priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)                                                                                                                        
pub = priv.public_key()                                                                                                                                                                      
                                                                                                                                                                                             
# 2. Data transaksi dienkripsi dengan AES-GCM (kunci acak per transaksi)                                                                                                                     
dek = AESGCM.generate_key(bit_length=256)                                                                                                                                                    
aesgcm = AESGCM(dek)                                                                                                                                                                         
nonce = os.urandom(12)                                                                                                                                                                       
transaksi = b"TRANSFER| dari=1234567890 ke=0987654321 nominal=500000"                                                                                                                        
ct = aesgcm.encrypt(nonce, transaksi, None)   # AEAD: kerahasiaan + integritas                                                                                                               
                                                                                                                                                                                             
# 3. DEK dibungkus dengan kunci publik bank (envelope encryption)                                                                                                                            
wrapped_dek = pub.encrypt(dek, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),                                                                                                     
                                            algorithm=hashes.SHA256(), label=None))                                                                                                          
                                                                                                                                                                                             
# 4. Server membuka DEK lalu mendekripsi transaksi                                                                                                                                           
dek2 = priv.decrypt(wrapped_dek, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),                                                                                                   
                                              algorithm=hashes.SHA256(), label=None))                                                                                                        
pt = AESGCM(dek2).decrypt(nonce, ct, None)                                                                                                                                                   
print("Ciphertext :", ct.hex()[:64], "...")                                                                                                                                                  
print("Terverifikasi & terbuka:", pt.decode())
