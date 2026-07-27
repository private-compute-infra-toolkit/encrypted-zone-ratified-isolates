# Changelog

All notable changes to this project will be documented in this file. See [commit-and-tag-version](https://github.com/absolute-version/commit-and-tag-version) for commit guidelines.

## 0.13.0 (2026-07-27)


### Dependencies

* **deps:** add pcit/api repository as submodule
* **deps:** Upgrade Project Oak for RSA PES certificate support


### Features

* add ValidateIsolateEndorsement RPC to SetupService
* implement PES endorsement verification API
* implement ValidateIsolateEndorsement RPC in setup_service
* **quota_uta:** add core rate limiter logic
* **quota_uta:** Add missing bazel configuration files
* **quota_uta:** add proto definitions and rules
* **quota_uta:** add server entry point and macro
* **quota_uta:** add service handlers
* validate expected claims in PES confirmation


### Bug Fixes

* **nsm:** connection leaks on ungraceful disconnects or cancellations

## 0.12.0 (2026-07-15)


### Anonymous Token Service

* **ats:** Propagate OTel context in token extraction


### SDK

* **sdk:** Propagate OTel trace context synchronously in stream calls


### Traces

* **traces:** trusted aratea traffic

## 0.11.0 (2026-07-08)


### Approver

* **approver:** Enable traces in Approver isolate


### Anonymous Token Service

* **ats:** Enable traces in ATS isolate


### Dependencies

* **deps:** Bump version of tokio-retry crate to 0.3.2
* **deps:** move base image reference to SDK
* **deps:** Update DevKit to release-3.10.0
* **deps:** Update versions for consistency


### SDK

* **sdk:** configure metrics retries and make setup failures fatal
* **sdk:** handle tracing setup errors and configure retries
* **sdk:** Pass through testonly in macros
* **sdk:** support raw byte stream RPCs


### Traces

* **traces:** Add /IsolateServer.dispatch_stream span
* **traces:** Add dispatch_unary span
* **traces:** Add start_noise_session_span
* **traces:** Add traces propagation in approver
* **traces:** Enable traces in nsm and crypto_oracle
* **traces:** Propagate context InvokeEzRequest
* **traces:** Propagate correct trace context from approver


### TLS Session Manager

* **tsm:** Add dependency on setup_isolate
* **tsm:** Add integration test for avs key source
* **tsm:** Add key-source flag and implementation
* **tsm:** Add missing buf formatting ignore
* **tsm:** dynamic gRPC method invocation
* **tsm:** Fix FIFO / AVS cert fetch race cond
* **tsm:** Test retries rather than fixed sleep


### Features

* add allocation error logs to ShmSlabPool
* **pubsub_broker:** Define PubSubBroker proto
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
* Test path cleanup improvements
* Update PubSubBroker proto

## 0.10.0 (2026-06-16)


### Dependencies

* **deps:** Update DevKit to release-3.9.0


### Noise Session Manager

* **noise:** Add metrics about server stream closure


### TLS Session Manager

* **tsm:** Add downstream RPC invoker, integration test, and backend API


### Features

* **nsm:** Double check cached cert to avoid race
* **nsm:** Refresh stale cached certs
* **setup_isolate:** add Setup Isolate proto definition
* **setup_isolate:** add SetupService
* **setup_isolate:** configure basic Bazel workspace
* upgrade rust to latest stable in all RIs (1.96.0)


### Bug Fixes

* gRPC error propagation and connection leak in NoiseSessionManager
* missing ELF due to extractor absolute symlink changes
* **nsm:** Cap max cert staleness to validity

## 0.9.0 (2026-06-02)


### Dependencies

* **deps:** Update DevKit to release-3.7.0
* **deps:** Update DevKit to release-3.8.0


### Noise Session Manager

* **noise:** Add metrics API
* **noise:** Add metrics for noise
* **noise:** Switch to OTel-style metric names


### TLS Session Manager

* **tsm:** declare service using SDK
* **tsm:** Implement TLS handshake portion


### Features

* Add EzShmSlabPool wrapper to Rust SDK
* **boringssl:** Extract BoringSSL patch to a separate module
* Default env_logger to INFO level in all Ratified Isolates
* **metrics:** Configure metrics for ratified isolates
* Move env logger crate to SDK
* Port Rust ShmSlabPool impl from enforcer
* Read incoming unary InvokeEzResponses from shared memory
* Read incoming unary InvokeIsolateRequests from shared memory
* Set default UDS path for OTel metrics
* Support streaming shared memory payloads for InvokeEzBridge
* Support streaming shared memory payloads for InvokeIsolateBridge
* Use encrypted_zone.ratified_isolate. metric prefix
* Write outbound unary InvokeEzRequests to shared memory
* Write outbound unary InvokeIsolateResponses to shared memory


### Bug Fixes

* have rust analzyer script use devkit
* occasional certificate time skew failure in EZ Aratea

## 0.8.0 (2026-05-18)


### Dependencies

* **deps:** Update DevKit to release-3.6.0


### Noise Session Manager

* **noise:** Use SDK service


### SDK

* **sdk:** Clean up SDK
* **sdk:** Manual sync of SDK
* **sdk:** Sync Otel from SDK


### Traces

* **traces:** Adjust sampling rate


### Features

* **tat:** only allow Smart Trust features


### Bug Fixes

* **tat:** Hybrid payload and pip2

## 0.7.0 (2026-05-11)


### Dependencies

* **deps:** Update DevKit to release-3.1.1
* **deps:** Update DevKit to release-3.2.0
* **deps:** Update DevKit to release-3.3.0
* **deps:** Update DevKit to release-3.4.0
* **deps:** Update DevKit to release-3.5.0
* **deps:** Update SDK otel and tonic versions
* **deps:** Update SDK to 0.14.0
* **deps:** Use enforcer protos from SDK in NSM
* **deps:** Use enforcer protos from SDK in oracle


### Crypto Oracle

* **oracle:** Add buf_lint_test for oracle
* **oracle:** Update oracle proto package and path


### Noise Session Manager

* **noise:** Cert caching default disabled
* **noise:** Fix service name typo
* **noise:** Remove bridge from NSM tests
* **noise:** Remove extra result from server channel
* **noise:** Remove unneeded mapping in bridge
* **noise:** Store BKM in OnceCell
* **noise:** Use call-specific methods in invoker


### Approver

* **approver:** Add grpc_connector to approver
* **approver:** Add traces configuration to approver
* **approver:** Add traces instrumentation to approver
* **approver:** Add traces to approver


### Anonymous Token Service

* **ats:** Add buff_lint_test for ATS
* **ats:** Add grpc_connector to anonymous_token_spender
* **ats:** Add traces configuration to anynymous_token_spender
* **ats:** Add traces instrumentation to ats
* **ats:** Add traces to anynymous_token_spender


### Features

* Add use_devkit Rule for Jeskit
* Add v1 to NSM proto package name
* Copy (inline) EZ rust sdk into ratified-isolates repo
* **crypto_oracle:** Add grpc_connector to crypto_oracle
* **crypto_oracle:** Add trace configuration to crypto_oracle
* **crypto_oracle:** Add traces to crypto_oracle
* **crypto_oracle:** Add tracing instrumentation to crypto_oracle
* Enable devkit/gitlinks check during pre-commit
* Extract grpc_connector and traces to shared_lib
* ignore .agents/ dir used for Jetski Rules/Skills
* manual sync of GoB SDK
* **nsm:** Add traces to nsm
* **nsm:** Copy grpc_connector from enforcer
* **nsm:** Copy traces from enforcer
* Remove unused dependency
* **sdk:** Various fixes for repo to build on it's own
* setup tls_session_manager boilerplate
* Trusted Aratea Traffic Ratified Isolate


### Bug Fixes

* Add buf_lint_test for NSM
* airlock builds require archive_override instead of git_override
* make `span.set_parent()` error non fatal

## 0.6.0 (2026-04-02)


### Dependencies

* **deps:** Switch from tokio-retry to tokio-retry2
* **deps:** Update DevKit to release-2.12.0
* **deps:** Update DevKit to release-2.13.0
* **deps:** Update DevKit to release-2.14.0
* **deps:** Update DevKit to release-2.15.0
* **deps:** Update DevKit to release-3.0.0
* **deps:** update SDK to 0.11.0
* **deps:** Update SDK to 0.13.0
* **deps:** upgrade rules_python to 1.9.0


### Noise Session Manager

* **noise:** Add SDK as dependency
* **noise:** Add SDK service target
* **noise:** Use SDK crates when possible


### Features

* Fix rules_python compatibility issues workspace-wide
* **nsm:** Revert Switch from tokio-retry to tokio-retry2"
* standardize internal build and test scripts across modules
* Use AnonymousTokensRedemptionService stub
* Use stub for forwarding Private Aratea req


### Bug Fixes

* Fix ATS scope configs

## 0.5.0 (2026-03-04)


### Dependencies

* **deps:** Update DevKit to release-2.11.0


### Crypto Oracle

* **oracle:** start oracle with public DataScope

## 0.4.0 (2026-02-09)


### Features

* Initial release
