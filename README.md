# **EZ Ratified Isolates**

This repository contains trusted (Ratified) Isolates published by Encrypted Zone. Registered
Publishers can also publish their own Ratified Isolates.

Ratified Isolates are built using the EZ Isolates SDK.

For a deeper look into ratified isolates, we recommend reading the
[EZ Node readme.](https://github.com/private-compute-infra-toolkit/encrypted-zone-node/blob/main/README.md)

## **Crypto Oracle**

Crypto Oracle is a Ratified Isolate that can manage cryptographic keys & signatures. This enables
management of sensitive keys in a trusted Isolate. It can optionally be added as an interceptor
before Opaque Isolates to handle encryption. For example: An incoming encrypted payload at PUBLIC
DataScope can be sent to Crypto Oracle for decryption, after which it is transmuted to USER or
MULTI-USER DataScope before it is sent to an Opaque Isolate. The same process happens in reverse
where USER scoped data from Opaque Isolate is sent to Crypto Oracle, which is transmuted to PUBLIC
DataScope payload after Crypto Oracle encrypts the data, before sending it back via the Public API,
providing a transparent data flow that all USER data leaving the Opaque isolate is always encrypted.

Crypto Oracle uses [Tink](https://project-oak.github.io/tink-rust/rust/tink_core/index.html)
underneath to manage sensitive keys.

## **TLS Session Manager**

TLS Session Manager is a Ratified Isolate that terminates end-to-end TLS sessions from client
devices directly to the Encrypted Zone Node and forwards decrypted bidirectional gRPC streams to
downstream target Isolates, encrypting responses before returning them to the client. It can obtain
its frontend TLS certificate from Setup Isolate.

## **Setup Isolate**

Setup Isolate is a Ratified Isolate used to perform the required steps to set up EZ Node. The steps
include bootstrapping EZ Node's Identity and validating Isolate package endorsements.

## License

Apache 2.0 - See [LICENSE](LICENSE) for more information.
