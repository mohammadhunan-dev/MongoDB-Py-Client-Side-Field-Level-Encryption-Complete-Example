import os
import math
import io
import base64
import base64
import pymongo
from pymongo import MongoClient
from pymongo.encryption_options import AutoEncryptionOpts
import pymongocrypt
from bson import binary
from bson.binary import (Binary,
                         JAVA_LEGACY,
                         STANDARD,
                         UUID_SUBTYPE)
from bson.codec_options import CodecOptions
OPTS = CodecOptions(uuid_representation=STANDARD)

# Create a local master key
# path = "master-key.txt"
# fileBytes = os.urandom(96)
# f = open(path, 'wb')
# f.write(binary.Binary(fileBytes))
# f.close()

# # read the masterKey as binary
masterKeyLocal = binary.Binary(open("master-key.txt", 'rb').read(96))
#     print("----------")
#     print(type(masterKeyLocal))
#     print(len(masterKeyLocal))
#     print(masterKeyLocal)
#     print("----------")

local_master_key = binary.Binary(base64.b64decode(
    'CgOcoan3c/wm2c+WsOO6fXOUlJgd7SLQ1vl///aEFX6vXN9+7VOAP+iHKheZiYlB09ZS7CDcAQhlPeTeQNz03xiGbiCJJvl3uj4lnG+5i/udSLJAcwgtgtaedkFD0ROq'))
kms_providers = {'local': {'key': local_master_key}}


fle_opts = AutoEncryptionOpts(
    kms_providers, "demoFLE.keystore2", mongocryptd_bypass_spawn=True)

client = MongoClient("mongodb://localhost:27017/demoFLE",
                     auto_encryption_opts=fle_opts)

client_encryption = pymongo.encryption.ClientEncryption(
    kms_providers, "demoFLE.keystore2", client, OPTS)

client_encryption.create_data_key('local', key_alt_names=['pykey1'])

key1 = client.demoFLE.keystore2.find_one({"keyAltNames": "pykey1"})['_id']

client_encryption.close()
client.close()

# Re-connect with auto-encryption schema map

patientSchema = {
    "demoFLE.patientsPy": {
        "bsonType": 'object',
        "encryptMetadata": {
            "keyId": [key1]
        },
        "properties": {
            "insurance": {
                "bsonType": "object",
                "properties": {
                    "policyNumber": {
                        "encrypt": {
                            "bsonType": "int",
                            "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
                        }
                    }
                }
            },
            "medicalRecords": {
                "encrypt": {
                    "bsonType": "array",
                    "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
                }
            },
            "bloodType": {
                "encrypt": {
                    "bsonType": "string",
                    "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
                }
            },
            "ssn": {
                "encrypt": {
                    "bsonType": 'string',
                    "algorithm": 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic',
                }
            },
            "mobile": {
                "encrypt": {
                    "bsonType": 'string',
                    "algorithm": 'AEAD_AES_256_CBC_HMAC_SHA_512-Random',
                }
            }
        }
    }
}


fle_opts = AutoEncryptionOpts(kms_providers, "demoFLE.keystore2",
                              schema_map=patientSchema, mongocryptd_bypass_spawn=True)
client = MongoClient("mongodb://localhost:27017/demoFLE",
                     auto_encryption_opts=fle_opts)


doc = {
    "name": 'Jon Doe Z',
    "ssn": "901010001",
    "bloodType": "a-",
    "medicalRecords": [{"weight": 180}],
    "insurance": {
        "policyNumber": 1223,
        "provider": 'Maest Care'
    }
}

client.demoFLE.patientsPy.insert_one(doc)
client.demoFLE.patientsPy.find_one()

# client.demoFLE.peoplePy.insert_one({'ssn': '123-12-1234', 'name': "Tim doe"})
# client.demoFLE.peoplePy.find_one()
client.close()

client2 = MongoClient("localhost", 27017)
client2.demoFLE.patientsPy.find_one()

print("Encrypted insert & find succeeded.")
