#!/usr/bin/env python3

from optparse import OptionParser
from concurrent import futures

from pre_attestation_pb2 import BundleResponse, SecretResponse

import pre_attestation_pb2_grpc
import grpc


def cli_parsing():
    usage = '''usage: %prog [options] [command]
    '''

    _parser = OptionParser(usage)

    _parser.add_option("-p", \
                       dest = "grpc_port", \
                       default = 50051, \
                       help = "Set port for gRPC server.")


    _parser.set_defaults()
    (_options, _args) = _parser.parse_args()

    return _options

def main(options) :
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    pre_attestation_pb2_grpc.add_SetupServicer_to_server(SetupService(), server)

    server.add_insecure_port("[::]:{}".format(options.grpc_port))
    server.start()
    server.wait_for_termination()


class SetupService(pre_attestation_pb2_grpc.SetupServicer) :
    def GetLaunchBundle(self, request, context) :
        print("Servicing Launch Bundle Request")

        print(request)
        return BundleResponse(GuestOwnerPublicKey = b"GODH", LaunchBlob = b"LAUNCHBLOB", \
                Policy = 0x0, ConnectionId = 1)

    def GetLaunchSecret(self, request, context) :
        print("Serving Launch Secret Request")

        print(request)
        return SecretResponse(LaunchSecret = b"SECRETBLOB")


if __name__ == "__main__":
    options = cli_parsing()
    main(options)
