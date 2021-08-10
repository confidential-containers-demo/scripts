#!/usr/bin/env python3

from optparse import OptionParser
from concurrent import futures
from os import path, mkdir, makedirs, urandom
from uuid import UUID
from Crypto.Cipher import AES
from Crypto.Util import Counter

from pre_attestation_pb2 import BundleResponse, SecretResponse
import pre_attestation_pb2_grpc

import grpc
import json
import subprocess
import time
import hmac
import base64
import hashlib

keysets = {}
sevtool_path = "/home/tobin/sev-tool/src/sevtool"
certs_path = "/tmp/sev-guest-owner-proxy/certs/"
connection_id = 0

def guid_to_le(guid_str):
    return UUID("{" + guid_str + "}").bytes_le

def construct_secret_entry(guid_str, secret_bytes):
    l = 16 + 4 + len(secret_bytes)
    entry = bytearray(l);
    entry[0:16] = guid_to_le(guid_str)
    entry[16:20] = l.to_bytes(4, byteorder='little')
    entry[20:20+len(secret_bytes)] = secret_bytes
    return entry


def cli_parsing():
    usage = '''usage: %prog [options] [command]
    '''

    _parser = OptionParser(usage)

    _parser.add_option("-p", "--port", \
                       dest = "grpc_port", \
                       default = 50051, \
                       help = "Set port for gRPC server.")

    _parser.add_option("-c", "--config", \
                       dest = "config_path", \
                       default = "keysets.json", \
                       help = "Path to keyset config file.")

    _parser.add_option("-k", "--keyfile", \
                       dest = "keyfile_path", \
                       default = "keys.json", \
                       help = "Path to keyfile.")

    _parser.set_defaults()
    (_options, _args) = _parser.parse_args()

    return _options

def main(options):
    try:
        with open(options.config_path) as f:
            global keysets
            keysets = json.load(f)
    except Exception as e:
        print("Failed to load config: {}".format(e.msg))

    # this will be replaced by an HSM probably
    try:
        with open(options.keyfile_path) as f:
            global keys
            keys = json.load(f)
    except Exception as e:
        print("Failed to load keyfile: {}".format(e.msg))


    #makedirs(certs_path, exist_ok = True)

    # this demo implementation isn't designed for parallelism.
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    pre_attestation_pb2_grpc.add_SetupServicer_to_server(SetupService(), server)

    server.add_insecure_port("[::]:{}".format(options.grpc_port))
    server.start()
    server.wait_for_termination()


class SetupService(pre_attestation_pb2_grpc.SetupServicer):
    def __init__(self):
        self.connection_id = 1

    def GetLaunchBundle(self, request, context):
        print("Servicing Launch Bundle Request")
        self.connection_id += 1

        # make dir for this conection
        connection_certs_path = path.join(certs_path, "connection{}".format(self.connection_id))
        makedirs(connection_certs_path, exist_ok=True)

        # save pdh to file
        with open(path.join(connection_certs_path,"pdh.cert"),"wb") as f:
            f.write(request.PlatformPublicKey)

        # generate launch blob
        # use sevtool for now. might switch in the future
        cmd = "sudo {} --ofolder {} --generate_launch_blob {}". \
                format(sevtool_path, connection_certs_path, request.Policy)
        subprocess.run(cmd.split())

        # read in the launch blob
        with open(path.join(connection_certs_path, "launch_blob.bin"), "rb") as f:
            launch_blob = f.read()

        # read in the guest owner public key
        with open(path.join(connection_certs_path, "godh.cert"), "rb") as f:
            godh = f.read()

        return BundleResponse(GuestOwnerPublicKey = godh, \
                LaunchBlob = launch_blob, \
                ConnectionId = connection_id)


    # TODO: make into smaller functions
    def GetLaunchSecret(self, request, context) :
        print("Serving Launch Secret Request")

        # check each of the parameters against the keyset
        if not request.KeysetId in keysets:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details('KEYSET INVALID')
            return SecretReponse()

        keyset = keysets[request.KeysetId]

        # policy
        if not request.Policy in keyset['allowed-policies']:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details('POLICY INVALID')
            return SecretReponse()

        # api
        if not request.ApiMajor >= keyset['min-api-major']:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details('API MAJOR VERSION INVALID')
            return SecretReponse()

        if request.ApiMajor == keyset['min-api-major'] and \
                not request.ApiMinor >= keyset['min-api-minor']:

            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details('API MINOR VERSION INVALID')
            return SecretReponse()

        # build
        if not request.BuildId in keyset['allowed-build-ids']:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details('BUILD-ID INVALID')
            return SecretReponse()


        # if the metadata checks out, check the measurement
        connection_certs_path = path.join(certs_path, \
                "connection{}".format(request.ConnectionId))

        # read in the tiktek
        with open(path.join(connection_certs_path,"tmp_tk.bin"), 'rb') as f:
            tiktek = f.read()

        TEK=tiktek[0:16]
        TIK=tiktek[16:32]

        launch_measure = request.LaunchMeasurement
        nonce = launch_measure[32:48]
        measure = launch_measure[0:32]

        measurement_valid = False

        # construct measurement for each digest
        for digest in keyset['allowed_digests']:
            h = hmac.new(TIK, digestmod='sha256')
            h.update(bytes([0x04]))
            h.update(request.ApiMajor.to_bytes(1,byteorder='little'))
            h.update(request.ApiMinor.to_bytes(1,byteorder='little'))
            h.update(request.BuildId.to_bytes(1,byteorder='little'))
            h.update(request.Policy.to_bytes(4,byteorder='little'))

            h.update(bytes.fromhex(digest))
            h.update(nonce)

            if measure == h.digest():
                measurement_valid = True
                break

        if not measurement_valid:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details('MEASUREMENT INVALID')
            return SecretReponse()

        # build the secret blob
        keydict = {}
        for keyid in keyset['allowed_keys']:
            if keyid in keys:
                keydict[keyid] = keys[keyid]

        keydict_bytes = (json.dumps(keydict) + "\x00").encode()
        guid = "e6f5a162-d67f-4750-a67c-5d065f2a9910"
        secret_entry = construct_secret_entry(guid, keydict_bytes)


        l = 16 + 4 + len(secret_entry)
        # SEV-ES requires rounding to 16
        l = (l + 15) & ~15
        secret = bytearray(l);
        secret[0:16] = UUID('{1e74f542-71dd-4d66-963e-ef4287ff173b}').bytes_le
        secret[16:20] = len(secret).to_bytes(4, byteorder='little')
        secret[20:20+len(secret_entry)] = secret_entry

        ##
        # encrypt the secret table with the TEK in ctr mode using a random IV
        ##
        IV=urandom(16)
        e = AES.new(TEK, AES.MODE_CTR, counter=Counter.new(128,initial_value=int.from_bytes(IV, byteorder='big')));
        encrypted_secret = e.encrypt(bytes(secret))

        FLAGS = 0

        ##
        # Table 55. LAUNCH_SECRET Packet Header Buffer
        ##
        header=bytearray(52);
        header[0:4]=FLAGS.to_bytes(4,byteorder='little')
        header[4:20]=IV
        h = hmac.new(TIK, digestmod='sha256');
        h.update(bytes([0x01]))
        # FLAGS || IV
        h.update(header[0:20])
        h.update(l.to_bytes(4, byteorder='little'))
        h.update(l.to_bytes(4, byteorder='little'))
        h.update(encrypted_secret)
        h.update(measure)
        header[20:52]=h.digest()

        return SecretResponse(LaunchSecretHeader = bytes(header), \
                LaunchSecretData = bytes(encrypted_secret))


if __name__ == "__main__":
    options = cli_parsing()
    main(options)
