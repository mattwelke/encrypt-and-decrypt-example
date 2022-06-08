# encrypt-and-decrypt-example

Testing out encrypting and decrypting data. Encryption code copied from https://www.baeldung.com/java-aes-encryption-decryption. Integrated into Micronaut application from Micronaut Launch generated June 7, 2022.

Goal is to have an application that can encrypt data for it to be transmitted to another application, with the other application receiving it and decrypting it back to its original form.

It is not a requirement that the application receiving it be able to receive it long in the future. It is understandable that the secrets used for encrypting and decrypting data would need to be rotated over time, so the idea is that a secret rotation will result in very little of the transmitted data being undecryptable, and that's okay.

The same input to the encrypt step must always produce the same output from the decrypt step, given the same secrets configured.

## encrypting

```bash
curl --request POST \
  --url http://localhost:8080/encrypt \
  --header 'Content-Type: text/plain' \
  --data abc123
```

## decrypting

Request body is the result of encrypting and Base64-encoding the string "abc123".

```base
curl --request POST \
  --url http://localhost:8080/decrypt \
  --header 'Content-Type: text/plain' \
  --data 'IObNzU1ocw8PCAy382jN+Q=='
```

## issues

Expected to get the same output from `/encrypt` given the same input each time, but this only happens per process. Each time the app starts up, we get new output for a given input. Why?

Is it because the Baeldung example is meant for use cases where you won't be storing the encrypted data, needing to decrypt it in another process in the future?

If so, how do we configure encryption and decryption to enable our use case?