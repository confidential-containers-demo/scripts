#!/usr/bin/env python3
#
# Keyprovider that keeps track of the keys.

from concurrent import futures
from keyprovider_pb2 import keyProviderKeyWrapProtocolInput, keyProviderKeyWrapProtocolOutput

import keyprovider_pb2_grpc 
import grpc


def main(): 
 
  print("starting")
  server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
  keyprovider_pb2_grpc.add_KeyProviderServiceServicer_to_server(KeyProviderService(), server)

  server.add_insecure_port("localhost:44444")
  server.start()

  server.wait_for_termination()


class KeyProviderService(keyprovider_pb2_grpc.KeyProviderServiceServicer):
  def __init__(self):
    print("starting service")

  def WrapKey(self, request, context):
    print("wrap key")
    print(request)

    return keyProviderKeyWrapProtocolOutput(KeyProviderKeyWrapProtocolOutput = b"RESPONSE")


if __name__ == "__main__":
  main()
