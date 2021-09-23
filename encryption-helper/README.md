# Encryption Helper

 The encryption helper is a keyprovider that the guest owner can use with ocicrypt to encrypt images. While the Attestation Agent helps to decyrpt images inside of an enclave, the guest owner needs to use a corresponding tool to encrypt the images before uploading them to the cloud. This is that tool.

## Usage 

First, install skopeo. On Ubuntu 20.10 you can install skopeo with apt. Otherwise, you'll need to build from source. See skopeo [installation guide](https://github.com/containers/skopeo/blob/main/install.md).

Next, create a configuration file for ocicrypt. You can call it whatever you want.

```json
{
  "key-providers": {
    "eh": {
      "grpc": "localhost:44444"
    } 
  }  
} 
```

Here we tell ocicrypt about the `eh` keyprovider.

Now tell ocicrypt about the config file by setting an environment variable.

```shell
export OCICRYPT_KEYPROVIDER_CONFIG=/path/to/ocicrypt.conf
```

Now you can encrypt an image like so

```shell
skopeo copy --encryption-key provider:ek oci:alpine oci:encrypted
``` 

Notice that we specify the ek provider that is defined in the config above.
