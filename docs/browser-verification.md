# Browser verification

Manual steps to check browser sessions and `basic_tofu` local proxy
authentication with Chrome and Edge on Windows 10/11. None of these steps has
been executed yet; until they are, the browser behavior described in the
README (the `407` prompt, credential caching, and what happens after a new
session) is expected, not verified. Record the results in
[verification.md](verification.md) and [compatibility.md](compatibility.md).

The steps use `gateinto session browser`, which starts one browser session on
an ephemeral loopback port. There is no `gateinto://` URI handler and no
browser launch yet, so the browser is started by hand with `--proxy-server`.

## Prerequisites

- Windows 10/11 x64 with current Chrome and Edge.
- A working configuration file and upstream, as in the
  [quickstart](quickstart.md): `gateinto check-upstream --config <file>` must
  succeed.
- A fresh, throwaway browser profile for each browser, so the steps neither
  depend on nor change your normal profile. The commands below use
  `--user-data-dir` in `%TEMP%`.

## Steps

1. Start a browser session and leave the window open:

   ```powershell
   gateinto session browser --config gateinto.toml
   ```

   It prints `session`, `kind`, `gateway`, `listen` (for example
   `127.0.0.1:49731`) and `realm` (for example
   `Gateinto session 3f9c0a1d2b4e5f60`). Note the port and the realm.

2. Start Chrome against that port with a throwaway profile:

   ```powershell
   & "C:\Program Files\Google\Chrome\Application\chrome.exe" `
     --user-data-dir="$env:TEMP\gateinto-chrome" `
     --proxy-server="http://127.0.0.1:<port>" `
     --no-first-run https://example.com/
   ```

   Expected: Chrome shows its native proxy sign-in dialog naming
   `127.0.0.1:<port>` (Chrome may or may not show the realm). Record what the
   dialog shows.

3. Enter any user name and a password of your choice (not a real password),
   for example `me` / `a-long-random-test-phrase`, and sign in.

   Expected: `https://example.com/` loads. The session window logs
   `bound the first local proxy credential to this session` only if
   `RUST_LOG=info` is set; with the default `warn` it stays quiet.

4. Open several more HTTPS sites in new tabs, for example
   `https://www.wikipedia.org/` and `https://www.rust-lang.org/`.

   Expected: they load without another prompt (Chrome caches the credential
   for this proxy and realm). Record whether any prompt appears.

5. Close Chrome completely, then start it again with the same command as in
   step 2.

   Expected: Chrome prompts again (the cache is per browser process for a
   throwaway profile) or reuses the credential if it saved it. Record which.
   Entering the same credential must work; a different one must be refused
   with another prompt.

6. In the prompt, enter a different password than in step 3.

   Expected: the prompt appears again (the session answered `407`). After 10
   wrong attempts within 60 seconds, the session answers `429` for the rest
   of that minute and Chrome shows an error page instead of a prompt
   (`ERR_TUNNEL_CONNECTION_FAILED` or similar). Record what Chrome shows.
   With `RUST_LOG=warn` the session window logs
   `local proxy credential differs from the one bound to this session` and
   `local proxy authentication rate limited`, never the credential.

7. Stop the session with Ctrl+C, start a new one (step 1), and note the new
   port and realm. Both must differ from the old ones.

8. Close Chrome completely (Chrome ignores `--proxy-server` for a profile
   that is already running), then start it with the new port and the same
   profile directory:

   ```powershell
   & "C:\Program Files\Google\Chrome\Application\chrome.exe" `
     --user-data-dir="$env:TEMP\gateinto-chrome" `
     --proxy-server="http://127.0.0.1:<new port>" https://example.com/
   ```

   Expected: Chrome prompts again, because the port and realm are new, and
   the credential entered now binds to the new session. Record whether Chrome
   instead silently reused the old credential (it would then be the one bound
   to the new session).

9. Repeat steps 1 to 8 with Edge:

   ```powershell
   & "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" `
     --user-data-dir="$env:TEMP\gateinto-edge" `
     --proxy-server="http://127.0.0.1:<port>" `
     --no-first-run https://example.com/
   ```

10. Check that a program which does not send credentials gets `407`, while
    the session runs:

    ```powershell
    curl.exe -v -x http://127.0.0.1:<port> https://example.com/
    ```

    Expected: `HTTP/1.1 407 Proxy Authentication Required` with
    `Proxy-Authenticate: Basic realm="<realm>", charset="UTF-8"`. With
    `-U me:a-long-random-test-phrase` (the bound credential) it gets `200`.

11. Delete the throwaway profiles:

    ```powershell
    Remove-Item -Recurse -Force "$env:TEMP\gateinto-chrome", "$env:TEMP\gateinto-edge"
    ```

## What to record

For each browser and version: whether the native prompt appeared on the first
`407`, what it showed, whether later tunnels needed another prompt, what
happened after a restart with the same profile, what a wrong credential and
the rate limit looked like, and whether a new session (new port and realm)
prompted again. Note anything that differs from the expectations above.
