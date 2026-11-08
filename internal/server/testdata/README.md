# Event logs

`ubuntu-no-secure-boot.eventlog` and `secure-boot.eventlog` are the files
`ubuntu_2104_shielded_vm_no_secure_boot_eventlog` and `sb_cert_eventlog` from
[go-attestation](https://github.com/google/go-attestation/tree/master/attest/testdata),
Copyright Google LLC, under the Apache License 2.0. They are measured boot logs of
real machines, which the tests read and replay into a simulated TPM.
