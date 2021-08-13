# SEV Guest Owner Proxy / Key Broker Service Prototype

Verifying the launch of an SEV VM, and conditionally provisioning a secret is a high-touch operation. This tool is designed to run in a trusted environment and provide verification and secret injection services.

This prototype currently serves AMD SEV(-ES) only.

The GOP should be configured with a dictionary of secrets that it can serve, and a list of keysets that group these keys and specify the requirements for their release. Each keyset has a list of approved firmware digests. The keys will only be released if the provided measurement checks out for one of the firmware digests.

This repo includes a simple test client. One real client for the Guest Owner Proxy is the Kata Runtime, which should connect to the GOP to retrieve a launch bundle and inject a secret. 
