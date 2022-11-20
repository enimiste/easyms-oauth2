**Generate jks file :**

```sh
keytool -genkeypair -alias jwt -keyalg RSA -dname "CN=jwt, L=Paris, S=Paris, C=FR" -keypass Easyms2020 -keystore jwt.jks -storepass Easyms2020
```

**Extract the public key (only the public key , without the certificate) into file jwt.pub :** 

```sh
keytool -list -rfc -alias jwt -keypass Easyms2020 -keystore jwt.jks -storepass Easyms2020 | openssl x509 -inform pem -pubkey -noout > jwt.pub
```

**Put the content of the jwt.pub file in each MS :**

        key-value: |
          -----BEGIN PUBLIC KEY-----
          MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0OIcJ+scLFXw23UtBfhI
          v3jqJ5qIivlZdL3T1gP3qZKaNicPvIVk1ozBJUan1hhUQE1gTI3PGi+Uhjb7zvvP
          GQnPR/nn3SzqtDGus99p5TVpMxNEQuPlMNVTQMcOOeWY2XoPTFFcWHgJJi0M1Fuc
          2KdbodvuT/h5FtRKQeTitAW1O0eZn9WUmYw9BD2N9Ijry3xaoA/rMvNDMWUBYlMH
          sicV/pUxK+t6EnMbUK1N7SHaXzZqEANLwP1ujuXdtJasYBg/Dk+2IIF7IV6MUKFh
          96xO+blmodP8GN+UtRicIHrQkFGuBh/slROluMPZSse0ISYmhJXPTRMNwmffEt/f
          FwIDAQAB
          -----END PUBLIC KEY-----

**And copy the jwt.jks file to your Oauth2 project**
