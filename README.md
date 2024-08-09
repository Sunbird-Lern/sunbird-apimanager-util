# sunbird-apimanager-util
Wrapper for Kong admin & a general signing service to generate jwt tokens.

This wrapper exposes APIs which can be used to register kong consumers and credentials. It also exposes a signing service that can generate JWT tokens (RS256). This service should not be exposed to the internet directly and should be behind an api gateway.


## Steps to run this code
1. Create 1 or more key pairs using the following steps. The private keys are used by the api-manager-util to generate the tokens and the equivalent public keys can be injected into services that need offline validation of the tokens.

```
    //device is the prefix and 0 is the key number. The second key would be device1 and so on. The meaning of this would be clear while updating the application.properties.
    openssl genrsa -des3 -out device0.pem 2048
    openssl rsa -in device0.pem -out device0.key
    openssl rsa -in device0.pem -outform PEM -pubout -out device0.pub  //if you want to retrieve the public key
    openssl pkcs8 -topk8 -inform PEM -in device0.pem -out device0 -nocrypt
```
2. Update the application.properties with the following properties
The am.admin.api.device prefixed variables are used to load the private keys to sign the mobile_device tokens. The am.admin.api.access prefixed variables are used by the signing service. 
```
am.admin.api.device.basepath - The folder where you have created the above keys. Please note that the path should end with a /
am.admin.api.device.keycount - should be updated to the number of keys you generated. The code assumes that the keys are ordered from 0 - n. 
am.admin.api.device.keyprefix - In the key generation i am using the prefix of *device* for the keys.

You could use the same keys device0, device1 etc for the signing service, but the recommendation is to use different keys.
am.admin.api.access.basepath
am.admin.api.access.keycount
am.admin.api.access.keyprefix
```
3. Run the AdminUtilApplication class

Note: There is also a stack.yml if you want to run the service as a docker container. In this case, the keys are mounted as secrets and the stack.yml can be configured with the paths.
