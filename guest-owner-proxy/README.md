# SEV Guest Owner Proxy / Key Broker Service Prototype

Verifying the launch of an SEV VM, and conditionally provisioning a secret is a high-touch operation. This tool is designed to run in a trusted environment and provide verification and secret injection services.

This prototype currently serves AMD SEV(-ES) only.

The GOP should be configured with a dictionary of secrets that it can serve, and a list of keysets that group these keys and specify the requirements for their release. Each keyset has a list of approved firmware digests. The keys will only be released if the provided measurement checks out for one of the firmware digests.

This repo includes a simple test client. One real client for the Guest Owner Proxy is the Kata Runtime, which should connect to the GOP to retrieve a launch bundle and inject a secret. 

The GOP needs more than just a measurement (from the client) to validate a guest. If the guest owner uploaded a measurement to the GOP, then the GOP could simply compare an incoming measurement against the uploaded measurements. Here, however, the guest owner uploads a fimware digest not a launch measurement. The reason for this is that a firmware digest directly corresponds to the firmware, initrd, kernel, and kernel params, that a guest owner supplies. The guest owner should always be able to calculate the firmware digest exactly and one firmware digest will correspond roughly to one VM image. The measurement, on the other hand, includes a number of node-specific parameters, such as the firmware build. While these parameters should be validated by the guest owner, the guest owner doesn't necessarily know all possible parameters when first deploying the image. Thus, we have the user specify a set of allowed parameters, such as a minimum firmware version. The client on the CSP then provides the plaintext for these parameters to the GOP along with the measurement. The GOP compares the parameters to the allowed parameters and then calculates the expected measurement accordingly.

Note also that the GOP must be stateful. To generate a secret, the GOP must retain the TIK and TEK that it provided via the launch bundle.
