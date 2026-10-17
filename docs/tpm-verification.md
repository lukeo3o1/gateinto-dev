# TPM verification

Manual check of the device key on a Windows 10/11 machine with a TPM 2.0.

**Status: not yet executed.**

1. Confirm a TPM is present and ready: `Get-Tpm` in PowerShell shows
   `TpmPresent : True` and `TpmReady : True`.
2. Create the key with a test name so a real device key is not touched:

   ```powershell
   gateinto key init --name gateinto-tpm-check --no-software-fallback
   ```

   Expect `created device key "gateinto-tpm-check"`, `backend: tpm` and no
   warning.
3. Show it:

   ```powershell
   gateinto key info --name gateinto-tpm-check --spki-out tpm-check.der
   ```

   Expect `backend: tpm`, `algorithm: ECDSA P-256` and the same
   `spki-sha256` as in step 2.
4. Run step 2 again. Expect `using existing device key "gateinto-tpm-check"`
   and the same `spki-sha256`.
5. Confirm the key lives in the TPM provider:

   ```powershell
   certutil -csp "Microsoft Platform Crypto Provider" -key -user
   ```

   The list contains `gateinto-tpm-check`, and
   `certutil -csp "Microsoft Software Key Storage Provider" -key -user` does
   not.
6. Clean up:

   ```powershell
   certutil -csp "Microsoft Platform Crypto Provider" -delkey -user gateinto-tpm-check
   Remove-Item tpm-check.der
   ```

   Then `gateinto key info --name gateinto-tpm-check` fails with
   `no device key named "gateinto-tpm-check"`.

7. Check that a TPM that is present but not usable stops `key init` instead of
   creating a software key. Do this only on a test machine: disabling TPM Base
   Services also affects BitLocker, Windows Hello and other TPM users. In an
   elevated PowerShell:

   ```powershell
   $startup = (Get-Service TBS).StartType
   Set-Service TBS -StartupType Disabled
   Stop-Service TBS -Force
   gateinto key init --name gateinto-tpm-check
   Set-Service TBS -StartupType $startup
   Start-Service TBS
   ```

   Expect the command to fail with `the TPM is present but not usable right
   now: <code>; no key was created and no software key was substituted. ...`,
   and `certutil -csp "Microsoft Software Key Storage Provider" -key -user`
   must not list `gateinto-tpm-check`. Record `<code>`. If the command creates
   a software key instead, the code Windows returned is classified as "absent";
   record it and treat it as a bug.
8. Run `cargo test --test device_key_windows` on this machine. With a usable
   TPM, `keys_in_both_providers_stop_init_and_make_info_warn` creates keys with
   the same name in both providers and checks that `key init` refuses to choose
   one and `key info` warns on stderr naming both backends.

## Client authentication with a TPM key

**Status: not yet executed.** CI has no TPM, so mTLS with a TPM-backed key is
only checked by these steps. They need OpenSSL 3 and an upstream HTTPS proxy
that requires client certificates from a test CA you control.

9. Create a TPM key and export its public key:

   ```powershell
   gateinto key init --name gateinto-tpm-mtls --no-software-fallback
   gateinto key info --name gateinto-tpm-mtls --spki-out tpm-mtls.der
   ```

   Expect `backend: tpm` and `client-certificate: none`.
10. Issue a client certificate for `tpm-mtls.der` with the test CA, as in the
    README section "Getting a test client certificate", and configure the
    upstream to trust that CA for client certificates.
11. Check the file against the key:

    ```powershell
    gateinto key info --name gateinto-tpm-mtls --client-cert-file client.pem
    ```

    Expect `client-certificate-source: file client.pem` and the certificate's
    thumbprint. Repeat with a certificate issued for another key and expect an
    error saying it "does not belong to the device key".
12. Run the proxy with the file and open a tunnel:

    ```powershell
    gateinto proxy --upstream-host <host> --upstream-port <port> --ca-file <upstream-ca.pem> `
      --key-name gateinto-tpm-mtls --client-certificate required --client-cert-file client.pem
    curl.exe --proxy http://127.0.0.1:18736 https://example.com/
    ```

    Expect the log line `client certificate authentication enabled` with
    `backend=tpm`, a successful request, and the upstream logging the client
    certificate. Record whether Windows showed any PIN or consent prompt; the
    signer uses `NCRYPT_SILENT_FLAG`, so a key that needs one fails instead.
13. Import the certificate and let the proxy find it:

    ```powershell
    certutil -user -addstore My client.pem
    gateinto key info --name gateinto-tpm-mtls
    ```

    Expect `client-certificate-source: CurrentUser\My`. Run step 12 again
    without `--client-cert-file` and expect the same result.
14. Run step 12 with `--client-certificate optional` and a key name that does
    not exist. Expect one warning ending in "mTLS is not configured and
    upstream connections do not authenticate this device", and `502` from the
    proxy for requests to an upstream that requires a client certificate.
15. Clean up:

    ```powershell
    certutil -user -delstore My <thumbprint>
    certutil -csp "Microsoft Platform Crypto Provider" -delkey -user gateinto-tpm-mtls
    Remove-Item tpm-mtls.der, client.pem
    ```

Record the Windows build, TPM manufacturer and firmware version (`Get-Tpm`),
and the output of each step in `docs/compatibility.md`.
