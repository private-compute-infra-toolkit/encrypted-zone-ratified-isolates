# Changelog

All notable changes to this project will be documented in this file. See [commit-and-tag-version](https://github.com/absolute-version/commit-and-tag-version) for commit guidelines.

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
