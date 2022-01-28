#!/usr/bin/env python3
# Basic client for the SEV/-ES Guest Owner Proxy

import argparse
import base64
import grpc
import sys

from pathlib import Path
from pre_attestation_pb2_grpc import SetupStub
from pre_attestation_pb2 import BundleRequest, SecretRequest

# SEV Host Settings
# The host phd and cert_chain must be install ahead of time
#   e.g., sudo sevtool --ofolder /opt/sev --pdh_cert_export
default_pdh="/opt/sev/pdh.cert"
default_cert="/opt/sev/cert_chain.cert"
default_policy = 0
default_connection_id = 9
default_keyset_id = "KEYSET-1"
default_server = "localhost:50051"
default_path = "/tmp"
# WARNING: default launch measure should not pass 
default_launch_measure= "gAxZlm0aF2r8vNTEE01fber98yWJC6K5NTRDUb3ik4LCZvtsXlnxm+zySQiGjTPA"

# SEV Hardware Specs
# These need to be set to match the underlying SEV architecture 
hw_api_major=0
hw_api_minor=22
hw_build_id=13
hw_gpa=8000


# TODO: use sevtool to generate phd & cert_chain at request time
def GetBundle(server, path, pdh, cert, policy):
    try:
        with open(pdh, "rb") as f:
            pdh_bytes = f.read()
    except Exception as e:
        print("Error: Failed to open {}".format(pdh), file=sys.stderr)
        exit(1)
    try:
        with open(cert, "rb") as f:
            cert_bytes = f.read()
    except Exception as e:
        print("Error: Failed to open {}".format(cert), file=sys.stderr)
        exit(1)

    request = BundleRequest(PlatformPublicKey = pdh_bytes, \
            CertificateChain = cert_bytes, \
            Policy = policy)
    # setup client connection
    channel = grpc.insecure_channel(server)
    client = SetupStub(channel)

    # process response 
    try:
        response = client.GetLaunchBundle(request)
    except grpc.RpcError as e:
        print("GRPC Error: {}".format(e.details()), file=sys.stderr)
        channel.close()
        exit(1)

    channel.close()
    godh_path = path + "/godh.txt"
    launch_blob_path = path + "/launch_blob.txt"
    godh_b64 = response.GuestOwnerPublicKey
    # TODO: error handle 
    Path(path).mkdir(parents=True, exist_ok=True)
    # output results 
    with open(godh_path, "w") as f:
        f.write(godh_b64.decode())
    launch_blob_b64 = response.LaunchBlob
    with open(launch_blob_path, "w") as f:
        f.write(launch_blob_b64.decode())
    # stdout
    print(godh_path+","+launch_blob_path+","+str(response.ConnectionId))


# TODO: use sevtool to pull SEV hw values (API major/minor, build_id) at request time 
def GetSecret(server, path, connection_id, keyset_id, launch_measure_str, policy):
    #prepare request
    secret_header_path = path + "/secret_header.txt"
    secret_data_path = path + "/secret_data.txt"
    #launch_measure 
    launch_measure = base64.b64decode(launch_measure_str.encode('ascii'))
    
    # setup client connection
    channel = grpc.insecure_channel(server)
    client = SetupStub(channel)
    request = SecretRequest(LaunchMeasurement = launch_measure, \
            ConnectionId = connection_id, \
            ApiMajor = hw_api_major, \
            ApiMinor = hw_api_minor, \
            BuildId = hw_build_id, \
            Policy = policy, \
            KeysetId = keyset_id)

    # process response
    try:
        response = client.GetLaunchSecret(request)
    except grpc.RpcError as e:
        print("GRPC Error: {}".format(e.details()), file=sys.stderr)
        exit(1)

    secret_header_b64 = base64.b64encode(response.LaunchSecretHeader).decode("utf-8")
    # output results 
    Path(path).mkdir(parents=True, exist_ok=True)
    with open(secret_header_path, "w") as f:
        f.write(secret_header_b64)
    secret_blob_b64 = base64.b64encode(response.LaunchSecretData).decode('utf-8')
    with open(secret_data_path, "w") as f:
        f.write(secret_blob_b64)
    # output
    out = f"{secret_header_b64},{secret_blob_b64},{hw_gpa}"
    print(out)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='test-client.py')
    subparsers = parser.add_subparsers(title='commands', dest='command', description='valid commands')
    # GetBundle args
    gb_parser = subparsers.add_parser('GetBundle')
    gb_parser.add_argument('-t', type=str, help='certificate chain', default=default_cert)
    gb_parser.add_argument('-k', type=str, help='platform dh key', default=default_pdh)
    gb_parser.add_argument('-p', type=int, help='policy', default=default_policy)
    # GetSecret args
    ss_parser = subparsers.add_parser('GetSecret')
    ss_parser.add_argument('-c', type=int, help='connection id', default=default_connection_id)
    ss_parser.add_argument('-i', type=str, help='keyset id', default=default_keyset_id)
    ss_parser.add_argument('-m', type=str, help='launch measure', default=default_launch_measure)
    ss_parser.add_argument('-p', type=int, help='policy', default=default_policy)
    # required args 
    parser.add_argument("server", help='server IP:port endpoint',default=default_server)
    parser.add_argument("path", help='path to connection directory',default=default_path)
    args = parser.parse_args()
    if args.command == 'GetBundle':
        GetBundle(args.server, args.path, args.k, args.t, args.p)
    elif args.command == 'GetSecret':
        GetSecret(args.server, args.path, args.c, args.i, args.m, args.p)
