# WinGet manifest templates

Templates for a future WinGet submission of the per-user x64 MSI. **No WinGet
package exists.** Nothing here has been submitted to
[winget-pkgs](https://github.com/microsoft/winget-pkgs), so `winget install`
and `winget uninstall` do not install or remove Gateinto. Install the MSI as
described in [docs/install.md](../../docs/install.md).

The files use manifest schema 1.6.0:

| File | Manifest type |
| --- | --- |
| `Gateinto.yaml` | `version` |
| `Gateinto.installer.yaml` | `installer`: `InstallerType: wix`, `Scope: user`, `x64` |
| `Gateinto.locale.en-US.yaml` | `defaultLocale` |

## Placeholders

| Placeholder | Value at release time |
| --- | --- |
| `<Publisher>` | The publisher segment of the package identifier, and the `Publisher` shown to users. The identifier is `<Publisher>.Gateinto`; no identifier is reserved, so it is chosen only when the package is first submitted. |
| `<Version>` | The release version without the `v`, for example `0.1.0` for tag `v0.1.0`. It must equal the MSI's `ProductVersion`, which `packaging/wix/build.ps1` takes from `Cargo.toml`. |
| `<Owner>`, `<Repository>` | The GitHub repository that hosts the release. |
| `<InstallerSha256>` | The SHA-256 of the released `gateinto-v<Version>-x86_64-pc-windows-msvc.msi`, from its `.sha256` file. Check it against the downloaded file. |
| `<ProductCode>` | The MSI's `ProductCode`. It is **different for every build**: `gateinto.wxs` sets no `ProductCode`, so WiX generates a new one each time. Read it from the released MSI, never from a local build. |

The `UpgradeCode` (`{2C50F196-F9CD-4535-A997-0687BEB31CDE}`) is fixed in
`packaging/wix/gateinto.wxs` and stays the same across versions.

## Filling the templates for a release

1. Download the release MSI and its `.sha256`, and check the hash:

   ```powershell
   $msi = 'gateinto-v0.1.0-x86_64-pc-windows-msvc.msi'
   (Get-FileHash -Algorithm SHA256 $msi).Hash
   Get-Content "$msi.sha256"
   ```

2. Read the `ProductCode` and `ProductVersion` from the MSI:

   ```powershell
   $installer = New-Object -ComObject WindowsInstaller.Installer
   $database = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @((Resolve-Path $msi).Path, 0))
   foreach ($name in 'ProductCode', 'ProductVersion') {
     $view = $database.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $database, @("SELECT Value FROM Property WHERE Property = '$name'"))
     $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
     $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
     "${name}: $($record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, 1))"
   }
   ```

3. Copy the three files to `manifests/<p>/<Publisher>/Gateinto/<Version>/` in a
   fork of winget-pkgs, rename them to `<Publisher>.Gateinto.yaml`,
   `<Publisher>.Gateinto.installer.yaml` and
   `<Publisher>.Gateinto.locale.en-US.yaml`, and replace every placeholder.
4. Run `winget validate --manifest <folder>` and test the install with
   `winget install --manifest <folder>` in a Windows Sandbox or VM, then
   uninstall it and check that the device key is kept, as the MSI lifecycle
   in [.github/scripts/msi-lifecycle.ps1](../../.github/scripts/msi-lifecycle.ps1)
   does.
5. Only after the pull request to winget-pkgs is merged and the package is
   installable may the docs say that `winget install` works.

## Verification status

The YAML parses, and with sample values in place of the placeholders the
three files validate against the published 1.6.0 JSON schemas from
[winget-cli](https://github.com/microsoft/winget-cli/tree/master/schemas/JSON/manifests/v1.6.0).
`winget validate` was not run: `winget` was not available where the templates
were written. No install through WinGet has been tried.
