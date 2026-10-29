# Changelog

All notable changes to this project will be documented in this file. See [commit-and-tag-version](https://github.com/absolute-version/commit-and-tag-version) for commit guidelines.

## 0.20.1 (2026-10-29)

_No user-facing changes to open-sourced Ratified Isolates in this release._

## 0.19.0 (2026-10-15)


### TLS Session Manager

* **tsm:** forward ControlPlaneMetadata to backend session

## 0.18.0 (2026-10-06)


### Features

* **setup_isolate:** Support multiple PES keys
* **setup_isolate:** Validate package filename in the artifact claim


### Bug Fixes

* **setup_isolate:** Validate the artifact claim instead of workload

## 0.17.0 (2026-09-17)


### TLS Session Manager

* **tsm:** omit root CA certificate from frontend TLS chain

## 0.15.0 (2026-08-24)


### Crypto Oracle

* **oracle:** add coverage configuration to bazelrc
* **oracle:** align LLVM toolchain with other isolates


### Setup Isolate

* **setup:** add coverage configuration to bazelrc


### TLS Session Manager

* **tsm:** add coverage configuration to bazelrc
* **tsm:** propagate inner stream errors to client

## 0.11.0 (2026-07-08)


### TLS Session Manager

* **tsm:** Add dependency on setup_isolate
* **tsm:** Add integration test for avs key source
* **tsm:** Add key-source flag and implementation
* **tsm:** Add missing buf formatting ignore
* **tsm:** dynamic gRPC method invocation
* **tsm:** Fix FIFO / AVS cert fetch race cond
* **tsm:** Test retries rather than fixed sleep


### Features

* **setup_isolate:** Add fields in ez_mtls
* **setup_isolate:** Add isolate binary
* **setup_isolate:** Add operator role
* **setup_isolate:** Add PES root certificates
* **setup_isolate:** Implement fetch frontend TLS
* **setup_isolate:** Implement fetch mTLS
* **setup_isolate:** OCI packaging
* **setup_isolate:** Remove rust bin _bin suffix
* **setup_isolate:** Remove unused mtls fields
* **setup_isolate:** Rename isolate package
* **setup_isolate:** Use correct AVS name

## 0.10.0 (2026-06-16)


### TLS Session Manager

* **tsm:** Add downstream RPC invoker, integration test, and backend API


### Features

* **setup_isolate:** add Setup Isolate proto definition
* **setup_isolate:** add SetupService
* **setup_isolate:** configure basic Bazel workspace

## 0.9.0 (2026-06-02)


### TLS Session Manager

* **tsm:** declare service using SDK
* **tsm:** Implement TLS handshake portion

## 0.7.0 (2026-05-11)


### Crypto Oracle

* **oracle:** Add buf_lint_test for oracle
* **oracle:** Update oracle proto package and path


### Features

* **crypto_oracle:** Add grpc_connector to crypto_oracle
* **crypto_oracle:** Add trace configuration to crypto_oracle
* **crypto_oracle:** Add traces to crypto_oracle
* **crypto_oracle:** Add tracing instrumentation to crypto_oracle

## 0.5.0 (2026-03-04)


### Crypto Oracle

* **oracle:** start oracle with public DataScope
