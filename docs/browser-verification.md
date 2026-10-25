# Browser verification

Manual steps to check browser sessions and `session_credentials` local proxy
authentication with Chrome and Edge on Windows 10/11. None of these steps has
been executed yet; until they are, the browser behavior described in the
README (the `407` sign-in dialog, credential caching, and what happens after a
session closes or a new one starts) is expected, not verified. Record the
results in [verification.md](verification.md) and
[compatibility.md](compatibility.md).

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

1. Start a browser session from an interactive desktop and leave its console
   open:

   ```powershell
   gateinto session browser --config gateinto.toml
   ```

   It prints `session`, `kind`, `gateway`, `listen` (for example
   `127.0.0.1:49731`) and `realm` (for example
   `Gateinto session 3f9c0a1d2b4e5f60`), then shows a message box titled
   `Gateinto` whose text starts with `Gateinto local proxy` and gives the
   proxy address, the user name `gateinto`, a password such as
   `t9ce-hu4w-38nr` and the warning to enter them only in the browser's proxy
   sign-in dialog. Note the port, the realm and the credentials, and record
   whether the message box was on top and whether its text could be selected
   or copied. The console must not
   show the password. Choose OK.

2. Start Chrome against that port with a throwaway profile:

   ```powershell
   & "C:\Program Files\Google\Chrome\Application\chrome.exe" `
     --user-data-dir="$env:TEMP\gateinto-chrome" `
     --proxy-server="http://127.0.0.1:<port>" `
     --no-first-run https://example.com/
   ```

   Expected: Chrome shows its native proxy sign-in dialog naming
   `127.0.0.1:<port>` (Chrome may or may not show the realm). Record what the
   dialog shows, and whether it can be told apart from a dialog drawn by a
   web page.

3. Enter the user name and password from step 1, typed by hand, and sign in.

   Expected: `https://example.com/` loads.

4. Open several more HTTPS sites in new tabs, for example
   `https://www.wikipedia.org/` and `https://www.rust-lang.org/`.

   Expected: they load without another dialog (Chrome caches the credentials
   for this proxy and realm). Record whether any dialog appears.

5. Close Chrome completely, then start it again with the same command as in
   step 2.

   Expected: Chrome asks again (the cache is per browser process for a
   throwaway profile) or reuses the credentials if it saved them. Record
   which, and whether Chrome offered to save them in its password manager.
   The issued credentials must work; any other must be refused with another
   dialog.

6. In the dialog, enter the issued user name with a different password, then
   a user name and password of your own.

   Expected: the dialog appears again each time (the session answered `407`);
   an invented credential never starts to work, however early it is sent.
   After 10 wrong attempts within 60 seconds, the session answers `429` for
   the rest of that minute, even to the issued credentials, and Chrome shows
   an error page instead of a dialog (`ERR_TUNNEL_CONNECTION_FAILED` or
   similar). Record what Chrome shows. With `RUST_LOG=warn` the session
   console logs `local proxy credentials differ from the ones issued to this
   session` and `local proxy authentication rate limited`, never the
   credentials.

   A request whose `Proxy-Authorization` uses another scheme (for example
   `Negotiate` or `NTLM`) is answered with `407` and counts as a failure
   toward the same limit. Record whether the browser sends such a scheme
   before Basic (visible in `chrome://net-export` or a capture of the
   loopback traffic), how many such requests it sends per tunnel, and
   whether that alone ever leads to `429`.

   A browser that caches a mistyped password and replays it on its parallel
   `CONNECT`s can reach the limit within seconds and lock the session for
   60 seconds. Record whether Chrome does this after one mistyped entry, how
   long it took to reach `429`, and whether it asked again once the lockout
   ended.

7. With Chrome still open, stop the session with Ctrl+C. Expected: open tabs
   that were using a tunnel lose their connections, and new pages fail
   because the port is closed. Record what Chrome shows. Start a new session
   (step 1) and note the new port, realm and credentials. The realm and
   credentials must differ from the old ones; the port may be reused.

8. Close Chrome completely (Chrome ignores `--proxy-server` for a profile
   that is already running), then start it with the new port and the same
   profile directory:

   ```powershell
   & "C:\Program Files\Google\Chrome\Application\chrome.exe" `
     --user-data-dir="$env:TEMP\gateinto-chrome" `
     --proxy-server="http://127.0.0.1:<new port>" https://example.com/
   ```

   Expected: Chrome asks again, because the port and realm are new, and only
   the new credentials work. Record whether Chrome first silently sent the
   old cached credentials (the session then answers `407` and counts a
   failure; visible in the session console with `RUST_LOG=warn`), and how
   many times.

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
    `-U <user name>:<password>` (the issued credentials) it gets `200`; with
    any other `-U` it gets `407`.

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
    (Chrome if installed, else Edge), but no user name or password, and shows
    a message box titled `Gateinto` whose text starts with
    `Gateinto session <id>` and gives the proxy address, the credentials, the
    warning and the hint `gateinto session credentials <id>`. A new browser
    window opens on
    `https://example.com/` with a fresh profile (no first-run page, no
    default-browser question, none of your bookmarks or extensions) and shows
    the proxy sign-in dialog. Record whether the message box or the browser
    window ended up in front. Record the browser, version and what the window
    showed. If your normal Chrome was already open, record that it was not
    affected and that the new window belongs to a separate process
    (Task Manager).

14. Sign in with the credentials from the message box as in step 3 and
    browse to a few HTTPS sites. Expected: as in steps 3 and 4. Then run
    `gateinto session credentials <id>`: the same message box appears again,
    and the console prints nothing. Run `gateinto status`
    and `gateinto session list`: neither shows the credentials.

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
    sessions, ports, realms, credentials and profile directories, each
    prompting separately; the credentials of one session are refused by the
    other. Then run `gateinto session close <id>` for one of them. Expected:
    that browser window disappears, its profile directory is gone,
    `gateinto session credentials <id>` answers `no session <id>`, and the
    other window keeps working.

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
    the agent. Its Gateinto error dialog must remain visible until OK is
    chosen, even if the temporary console disappears. Clicking `offsite`
    must likewise leave the returned agent error visible in one error dialog.
    A successful `office` launch must not show an error dialog. Record the
    confirmation dialogs, whether
    "always allow" is offered, and what happens on repeated clicks
    (rate limit after 5 a minute). Clicking `offsite` opens no browser: the
    agent refuses a start page outside the portal's origin. Clicking `new`
    shows the Gateinto warning dialog naming `newco`,
    `proxy.newco.example:443` and `https://example.com`, with the buttons OK
    and Cancel; record that Cancel is selected by default, that Enter,
    Space, `Y` and `O` do not choose OK, that Tab and the arrow keys move
    the focus to OK (after which Enter or Space would approve; do not press
    them then), that the dialog is on top, that
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

    Also run the invalid link from an existing PowerShell window. Expected:
    stderr contains the error, `$LASTEXITCODE` is nonzero, and no error dialog
    appears. Repeat with `2> launch-error.txt`: the file contains the error and
    no dialog appears. Check an `open` argument error in its own console with:

    ```powershell
    Start-Process -FilePath (Get-Command gateinto).Source -ArgumentList 'open'
    ```

    Expected: one persistent Gateinto dialog contains the missing URI
    argument error. Run `gateinto open --help` in a terminal: help succeeds
    without an error dialog. These desktop checks have not been executed
    locally; automated tests capture notifications without opening dialogs.

22. Remove the handler and stop the agent:

    ```powershell
    gateinto uri unregister
    gateinto stop
    reg query HKCU\Software\Classes\gateinto
    ```

    Expected: `reg query` reports that the key does not exist.

## What to record

For each browser and version: whether the native dialog appeared on the first
`407`, what it showed, whether later tunnels needed another dialog, what
happened after a restart with the same profile, whether it offered to save the
credentials, what wrong credentials and the rate limit looked like, whether it
sent a non-Basic scheme first, what happened to open tabs when the session
closed, and whether a new session (new realm and credentials) asked
again or first sent the old cached credentials. For the prompt: whether the
message box appeared, on top or behind the browser, and whether its text
could be copied. For the agent:
which browser was found, whether its window opened on the portal with a
fresh profile beside an already running browser, how reliably and how quickly
closing the window closed the session and deleted the profile, and how the
browsers handled the `gateinto://` link. Note anything that differs from the
expectations above.

## Mixed routing launch links

Not verified with real Chrome or Edge. On an isolated test deployment:

1. Launch a known profile without `route` and with `route=gateway`; verify
   both send CONNECTs through the gateway.
2. Launch the same profile with `route=mixed`. Verify a DNS target matching
   a gateway IP uses the gateway, a distinct public target connects directly,
   and missing local DNS answers use the gateway. Observe DNS and network
   captures rather than treating an error page as proof of the route.
3. Verify a failed direct TCP opening tries gateway CONNECT, while a gateway
   refusal remains an error. A target TLS error after local CONNECT success
   must not cause another route attempt.
4. Check `gateinto session list` and `gateinto status` identify only the mixed
   session with `route=mixed`. A subsequent link without a mode, the device
   session and any already-open session keep their original routes.
5. Add an unknown gateway using a mixed link. Verify the existing confirmation
   discloses direct connections and local DNS/IP exposure, and approval starts
   a mixed session. A subsequent mode-free link must use the gateway route.

## Gateway-address launch selectors

Not verified with real Chrome or Edge. Using the same isolated gateway:

1. Open `gateinto://connect?gateway=<percent-encoded-host-and-port>` without
   `profile` or `portal`. Verify a configured endpoint reuses its existing
   profile and CA/TLS settings, opens its saved portal (or `about:blank`), and
   does not create another gateway file.
2. Configure two profiles with the same endpoint but different TLS settings.
   An address-only link must report ambiguity; adding the intended profile
   selects it. A supplied mismatching address or portal must be refused.
3. Use a new endpoint with no profile or portal. Verify first-time confirmation
   shows its address, generated internal profile name and `Portal: none`.
   On approval the browser opens `about:blank`; the saved file omits
   `portal_url`. Stop and restart the agent and verify the same link reuses it.
4. Verify a `url` is refused for a gateway with no portal; neither a start page
   nor a link's portal may silently add a portal to an existing entry.
5. Repeat with `route=mixed`; verify the confirmation and session listing keep
   the mode and another launch without it retains gateway routing.
