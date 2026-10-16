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

Record the Windows build, TPM manufacturer and firmware version (`Get-Tpm`),
and the output of each step in `docs/compatibility.md`.
