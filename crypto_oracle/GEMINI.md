# Gemini Context: //crypto_oracle

This directory contains a cryptographic oracle that provides key management and cryptographic
operations as a gRPC service.

## Codebase Structure

-   **`src/`**: Contains the implementation of the `OracleApi` gRPC service, including key
    generation, signing, and verification.
-   **`oracle/`**: Contains the Protocol Buffer definitions for the `OracleApi` service.
-   **`test/`**: Contains tests for the cryptographic oracle.
