# Basic client to test Guest Owner Proxy

import grpc
import base64

from pre_attestation_pb2_grpc import SetupStub
from pre_attestation_pb2 import BundleRequest, SecretRequest

channel = grpc.insecure_channel("localhost:50051")
client = SetupStub(channel)

def GetBundle():
    with open("pdh.cert", "rb") as f:
        pdh_bytes = f.read()

    request = BundleRequest(PlatformPublicKey = pdh_bytes, Policy = 0)
    response = client.GetLaunchBundle(request)
    print(response)

    godh_b64 = base64.b64encode(response.GuestOwnerPublicKey)
    with open("godh.txt", "w") as f:
        f.write(godh_b64.decode())

    launch_blob_b64 = base64.b64encode(response.LaunchBlob)
    with open("launch_blob.txt", "w") as f:
        f.write(launch_blob_b64.decode())


def GetSecret():
    # Make sure you get the full measurement, which includes a nonce.
    launch_measure_hex = "47e3e21b130e506727af0482f1987d805c7813d41f85560d6fcb56877f2cac5583310cde9c5d8f2113fa3f0cb507b495"
    launch_measure = bytes.fromhex(launch_measure_hex)

    request = SecretRequest(LaunchMeasurement = launch_measure, \
            ConnectionId = 1, \
            ApiMajor = 0, \
            ApiMinor = 23, \
            BuildId = 10, \
            Policy = 0, \
            KeysetId = "KEYSET-1")
    response = client.GetLaunchSecret(request)

    secret_header_b64 = base64.b64encode(response.LaunchSecretHeader).decode("utf-8")
    with open("secret_header.txt", "w") as f:
        f.write(secret_header_b64)

    secret_blob_b64 = base64.b64encode(response.LaunchSecretData).decode('utf-8')
    with open("secret_data.txt", "w") as f:
        f.write(secret_blob_b64)

    cmd = f"sev-inject-launch-secret packet-header={secret_header_b64} secret={secret_blob_b64} gpa=8000"
    print(cmd)

if __name__ == "__main__":
    # If you want to do an end-to-end test, you should run this once to get the
    # bundle. Then start a VM with the generated launch blob and session file
    # Use the -S flag so that you can get the measurement. Then replace the
    # measurement at the beginning of GetSecret with your new measurement
    # and run this again with GetBundle commented out. Assuming you have the
    # right digest, this should give you a measurement that you can
    # inject into your waiting VM.
    GetBundle()
    GetSecret()
