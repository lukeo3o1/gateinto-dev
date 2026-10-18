# Browser verification

Manual steps to check browser sessions and `basic_tofu` local proxy
authentication with Chrome and Edge on Windows 10/11. None of these steps has
been executed yet; until they are, the browser behavior described in the
README (the `407` prompt, credential caching, and what happens after a new
session) is expected, not verified. Record the results in
[verification.md](verification.md) and [compatibility.md](compatibility.md).

Steps 1 to 11 use `gateinto session browser`, which starts one browser
session on an ephemeral loopback port, and start the browser by hand with
`--proxy-server`. [Launch URI and agent](#launch-uri-and-agent) then checks
the agent starting the browser itself and a `gateinto://` link clicked in a
browser. None of those steps has been executed either.

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

   A request whose `Proxy-Authorization` uses another scheme (for example
   `Negotiate` or `NTLM`) is answered with `407` and counts as a failure
   toward the same limit. Record whether the browser sends such a scheme
   before Basic (visible in `chrome://net-export` or a capture of the
   loopback traffic), how many such requests it sends per tunnel, and
   whether that alone ever leads to `429`.

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

## Launch URI and agent

These steps let the agent start Chrome or Edge itself. They use the same
configuration file; add a start page to the gateway you use, for example:

```toml
[gateways.office]
# ...
portal_url = "https://example.com/"
```

12. Start the agent in a console so its log is visible, and leave it running:

    ```powershell
    $env:RUST_LOG = "info"
    gateinto agent --config gateinto.toml
    ```

    Expected: `agent ready` with the endpoint
    `\\.\pipe\gateinto-agent-<your SID>`. A second `gateinto agent` in another
    console must exit with `an agent is already running`.

13. In another console, launch a session for the gateway:

    ```powershell
    gateinto open --config gateinto.toml -- "gateinto://connect?profile=office"
    ```

    Expected: it prints `session`, `gateway`, `listen`, `realm`, `profile`
    (a directory under `%LOCALAPPDATA%\Gateinto\profiles`) and `browser`
    (Chrome if installed, else Edge). A new browser window opens on
    `https://example.com/` with a fresh profile (no first-run page, no
    default-browser question, none of your bookmarks or extensions) and shows
    the proxy sign-in prompt. Record the browser, version and what the window
    showed. If your normal Chrome was already open, record that it was not
    affected and that the new window belongs to a separate process
    (Task Manager).

14. Sign in with a test credential as in step 3 and browse to a few HTTPS
    sites. Expected: as in steps 3 and 4.

15. Run `gateinto session list`. Expected: the device session (if
    `[device_session] gateway` is set) and one `browser` line with the port
    from step 13.

16. Close the browser window normally (the last window of that browser
    process). Expected: the agent logs that the browser exited and the
    session closed; `gateinto session list` no longer shows it; the profile
    directory from step 13 is gone; `curl.exe -x http://127.0.0.1:<port>
    https://example.com/` cannot connect. Record how long after closing the
    window this happened, and whether Chrome or Edge kept a background
    process alive instead (then the session stays open; record it and close
    it with `gateinto session close <id>`).

17. Run step 13 twice in a row. Expected: two windows, two different
    sessions, ports, realms and profile directories, each prompting
    separately. Then run `gateinto session close <id>` for one of them.
    Expected: that browser window disappears, its profile directory is gone,
    and the other window keeps working.

18. Run step 13 six times within a minute (closing windows in between).
    Expected: the sixth fails with `too many launch requests`. With four
    windows open, a fifth launch fails with `4 browser sessions are already
    open`.

19. Stop the agent with Ctrl+C in its console (or `gateinto stop`).
    Expected: every browser window it started closes and
    `%LOCALAPPDATA%\Gateinto\profiles` is empty.

20. Close every console and run step 13 again without a running agent.
    Expected: `open` starts the agent in the background (no console window
    appears) and the browser opens as before. Stop it with `gateinto stop`.

21. Register the handler for your user and try a link from a browser:

    ```powershell
    gateinto uri register --config "$PWD\gateinto.toml"
    reg query HKCU\Software\Classes\gateinto\shell\open\command
    ```

    Expected: the command is
    `"<path>\gateinto.exe" open --config "<path>\gateinto.toml" -- "%1"`.
    Save this file as `launch.html` and open it in your normal Chrome and
    Edge:

    ```html
    <a href="gateinto://connect?profile=office">office</a>
    <a href="gateinto://connect?profile=office&amp;url=https://evil.example">bad</a>
    <a href="gateinto://connect?profile=office&amp;url=https%3A%2F%2Fevil.example%2F">offsite</a>
    <a href="gateinto://connect?profile=newco&amp;gateway=proxy.newco.example&amp;portal=https%3A%2F%2Fexample.com%2F">new</a>
    ```

    Expected: clicking `office` shows the browser's confirmation for an
    external application, then a new isolated window as in step 13.
    `gateinto.exe` is a console program, so a console window may appear
    briefly while `open` runs; record whether it does. Clicking `bad` (after
    confirming) opens no browser: `open` rejects the URI before contacting
    the agent. Record the confirmation dialogs, whether
    "always allow" is offered, and what happens on repeated clicks
    (rate limit after 5 a minute). Clicking `offsite` opens no browser: the
    agent refuses a start page outside the portal's origin. Clicking `new`
    shows the Gateinto warning dialog naming `newco`,
    `proxy.newco.example:443` and `https://example.com`, with OK and Cancel
    and Cancel selected; record that Cancel is the default, that Enter,
    Space, `Y` and `O` do not choose OK, that the dialog is on top, that
    Cancel (and closing it) stores nothing (`gateinto gateway list`) and that
    clicking `new` again while the dialog is open is refused. Do not choose OK
    unless the host is a gateway you control; then record that the gateway
    appears as `linked` in `gateinto gateway list`, that a second click does
    not ask again, and remove it with `gateinto gateway forget newco`.
    Clicking `office` launching a window shows
    that the browser passed the URI in the accepted `gateinto://connect?`
    form; also add `<a href="gateinto://connect/?profile=office">slash</a>`
    and record whether it launches too, and if a link does not launch, run
    `gateinto open` by hand with the same URI to see the error.

22. Remove the handler and stop the agent:

    ```powershell
    gateinto uri unregister
    gateinto stop
    reg query HKCU\Software\Classes\gateinto
    ```

    Expected: `reg query` reports that the key does not exist.

## What to record

For each browser and version: whether the native prompt appeared on the first
`407`, what it showed, whether later tunnels needed another prompt, what
happened after a restart with the same profile, what a wrong credential and
the rate limit looked like, whether it sent a non-Basic scheme first, and
whether a new session (new port and realm) prompted again. For the agent:
which browser was found, whether its window opened on the portal with a
fresh profile beside an already running browser, how reliably and how quickly
closing the window closed the session and deleted the profile, and how the
browsers handled the `gateinto://` link. Note anything that differs from the
expectations above.
