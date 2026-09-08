# SENTRY-X

This is the repo for the paper named "SENTRY-X: Enclave-Assisted Anonymous yet Auditable Broadcast for Proximity Networks" in ESORICS 2026.

## Experiment Setup

It requires Intel SGX SDK. The following is the version we used for our framework.

```
SGX SDK version 2.23.100.2
SGX SDK version 2.18.100.3 for sgxssl
```

## Compliation
There are two components needed to be updated in Makefile.

```
SGX_SDK ?= PATH TO SGXSDK (e.g., /opt/intel/sgxsdk)
SgxSsl_Dir := PATH TO SGXSSL (e.g., ~/linux-sgx/external/sgxssl/Linux/pacakage/lib64)
```

Last, there is one component to be updated in the App.cpp. IP ADDRESS should be updated in the main function.


