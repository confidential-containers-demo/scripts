# Basic client to test Guest Owner Proxy

import grpc
from pre_attestation_pb2_grpc import SetupStub
from pre_attestation_pb2 import BundleRequest, SecretRequest

channel = grpc.insecure_channel("localhost:50051")
client = SetupStub(channel)

request = BundleRequest(PlatformPublicKey = b"PDH goes here")
response = client.GetLaunchBundle(request)
print(response)

request = SecretRequest(LaunchMeasurement = b"launch measure goes here", \
        ConnectionId = 1)
response = client.GetLaunchSecret(request)
print(response)
