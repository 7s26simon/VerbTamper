# VerbTamper

A Burp Suite extension for quickly testing HTTP verb/method tampering and access-control bypass — useful for finding Broken Function Level Authorization (BFLA) and related flaws where endpoints fail to enforce method-, IP-, or URL-based restrictions.

---

## What it does

Send any request to VerbTamper, change the verb or inject a bypass header, and fire it — all without leaving Burp. The request text is fully editable so you can also modify the path, headers, or body before sending. Every send is logged to a history tab and every multi-verb scan is saved alongside it, both exportable as CSV.

**Use cases:**
- Testing whether `DELETE /api/admin/posts/1` works when only `POST /api/posts/1/flag` was intended for regular users
- Checking if `PUT` or `PATCH` are accepted on read-only endpoints
- Smuggling a restricted verb through a POST-only endpoint using `X-HTTP-Method-Override`
- Probing whether the app trusts upstream headers like `X-Forwarded-For` or `X-Original-URL`
- Quickly iterating through all HTTP methods on a target endpoint during recon

---

## Features

### Core

- **Right-click context menu** — "Send to Verb Tamper" from Proxy history, Repeater, or anywhere else in Burp
- **Dedicated tab with three sub-tabs** — Scanner, Send History, Scan History
- **Live verb sync** — changing the dropdown rewrites the method in the request text in real time
- **HTTP/2 aware** — automatically detects and sends HTTP/2 requests correctly
- **Robust response handling** — reads responses via raw byte arrays with fallbacks, so HTTP/2 edge cases don't come back as empty
- **Auto Content-Length** — fixes stale Content-Length headers when you switch between body-bearing and bodyless verbs
- **Header sanitisation** — normalises CRLF, stitches wrapped JWT continuation lines, terminates the headers block correctly

### Scanner tab

- **Scan All Verbs** — fires all 7 verbs in parallel and shows a colour-coded results table (status, length, preview)
- **Bypass header dropdown** — one-click insertion of common access-control bypass headers, placed directly after the `Host:` line:
  - *Method override*: `X-HTTP-Method-Override: DELETE/PUT/PATCH`, `X-HTTP-Method`, `X-Method-Override` (also auto-switches the verb dropdown to POST)
  - *IP spoofing*: `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `X-Remote-IP`, `X-Client-IP`, `X-Host`, `X-Forwarded-Host`
  - *URL rewriting*: `X-Original-URL`, `X-Rewrite-URL`, `X-Override-URL`
- **Auth token manager** — save labelled JWTs and apply them to the current request in one click
- **Diff view** — line-by-line diff of the last two responses, red for removed, green for added
- **Back / Forward navigation** — browse your send history like Repeater
- **Send to Repeater** — reads the current dropdown and editor state every click, so you push the *intended* request (not the last one sent)
- **Copy Req / Copy Resp / Clear** — obvious buttons

### Send History tab

- Every single request sent through the Scanner is logged with timestamp, verb, host, path, status, and length
- Rows are colour-coded by status class
- Double-click an entry to reload it back into the Scanner editor
- "View Response" shows the full response body in a read-only dialog
- "Export All to CSV" dumps summary columns for pivoting in Excel
- Delete individual entries or Clear All

### Scan History tab

- Every completed "Scan All Verbs" run is saved with timestamp, host, path, loaded verb, and all 7 results
- A "Notable" column flags scans that returned a mix of 2xx and 4xx responses — the signature of a likely BFLA finding
- Double-click to replay an old scan in the same colour-coded results dialog
- "Export CSV" on the scan dialog saves one scan (Verb, Status, Length, Preview, FullResponse)
- "Export All to CSV" on the history tab flattens every scan into one spreadsheet-friendly table (Timestamp, Host, Path, OriginalVerb, VerbTried, Status, Length, Preview)

---

## Installation

### Requirements
- Burp Suite (Community or Professional) — tested on v2026.3.2
- No other dependencies

### Steps

1. Download `VerbTamper-1.4.4.jar` from [Releases](../../releases)
2. In Burp Suite, go to **Extensions → Installed → Add**
3. Set **Extension type** to `Java`
4. Select the downloaded `.jar` file
5. Click **Next** — you should see `Verb Tamper 1.4.4 loaded.` in the output
6. A **Verb Tamper** tab will appear in the main Burp window

---

## Usage

### Via context menu

1. Find a request in Proxy history, Repeater, or any Burp tool
2. Right-click → **Send to Verb Tamper**
3. The request loads into the Scanner tab
4. Select a verb from the dropdown (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD)
5. Optionally pick a bypass header from the Headers dropdown
6. Edit the path or headers if needed
7. Click **Send**

### Auth token manager

1. Click **Add** in the Auth Tokens panel on the right
2. Enter a label (e.g. "admin", "hacker") and paste the full JWT
3. Select a saved token and click **Apply** to swap it into the Authorization header

### Scan All Verbs

1. Load a request into the panel
2. Click **Scan All Verbs**
3. A results table opens showing each verb's status code, response length, and body preview
4. Rows are colour-coded: green = 2xx, yellow = 3xx, red = 4xx/5xx
5. Click **Export CSV** on the dialog to save this scan
6. The completed scan is also added to the Scan History tab for later replay or bulk export

### Diff

After sending two or more requests, click **Diff** to open a line-by-line comparison of the last two responses.

### Workflow example

```
# Original request (from Proxy history)
POST /api/posts/1/flag HTTP/2
Host: target.example.com
Authorization: Bearer <user-token>

# In Verb Tamper: change path, select DELETE, hit Send
DELETE /api/admin/posts/1 HTTP/2
Host: target.example.com
Authorization: Bearer <user-token>

# Response
HTTP/2 200 OK
{"message":"Post deleted successfully","flag":"bug{...}"}
```

### Method-override smuggling example

```
# Pick "X-HTTP-Method-Override: DELETE" from the Headers dropdown.
# The verb dropdown auto-switches to POST. Hit Send.

POST /api/admin/posts/1 HTTP/2
Host: target.example.com
X-HTTP-Method-Override: DELETE
Authorization: Bearer <user-token>
```

---

## Building from source

Requires JDK 11+ and Gradle. You'll need to supply the Montoya API by extracting it from your local Burp jar:

```bash
# Extract the Montoya API classes from your Burp installation
python3 -c "
import zipfile
with zipfile.ZipFile('/path/to/burpsuite.jar') as z:
    for f in z.namelist():
        if f.startswith('burp/api/'):
            z.extract(f, '.')
"

# Package into a jar
python3 -c "
import zipfile, os
with zipfile.ZipFile('libs/montoya-api-real.jar', 'w') as z:
    for root, dirs, files in os.walk('burp/'):
        for f in files:
            path = os.path.join(root, f)
            z.write(path)
"

# Build
gradle jar

# Output: build/libs/VerbTamper-1.4.4.jar
```

> **Why not Maven Central?** The Montoya API jar on Maven Central may not match the exact version bundled with your Burp installation, causing `NoSuchMethodError` at runtime. Extracting directly from your Burp jar guarantees compatibility.

---

## License

MIT
