# VerbTamper

A Burp Suite extension for quickly testing HTTP verb/method tampering — useful for finding Broken Function Level Authorization (BFLA) and broken access control vulnerabilities where endpoints fail to enforce method-level restrictions.

---

## What it does

Send any request to VerbTamper, select a different HTTP method from the dropdown, and fire it — all without leaving Burp. The request text is fully editable so you can also modify the path, headers, or body before sending.

**Use cases:**
- Testing whether `DELETE /api/admin/posts/1` works when only `POST /api/posts/1/flag` was intended for regular users
- Checking if `PUT` or `PATCH` are accepted on read-only endpoints
- Quickly iterating through all HTTP methods on a target endpoint during recon

---

## Features

- **Right-click context menu** — "Send to Verb Tamper" from Proxy history, Repeater, or anywhere else in Burp
- **Dedicated tab** — request loads into an editable panel; change the verb, tweak the path, hit Send
- **Live verb sync** — changing the dropdown rewrites the method in the request text in real time
- **Scan All Verbs** — fires all 7 verbs in parallel and shows a colour-coded results table (status, length, preview)
- **Diff view** — line-by-line diff of the last two responses, red for removed, green for added
- **Auth token manager** — save labelled JWTs and apply them to the current request in one click
- **Back / Forward navigation** — browse your send history like Repeater
- **Copy Req / Copy Resp** — one-click clipboard copy
- **Clear** — wipe the panel back to blank state
- **Send to Repeater** — push the modified request to Repeater for further testing
- **HTTP/2 aware** — automatically detects and sends HTTP/2 requests correctly
- **Header sanitisation** — strips newlines that can sneak into header values when pasting long JWTs

---

## Installation

### Requirements
- Burp Suite (Community or Professional) — tested on v2026.3.2
- No other dependencies

### Steps

1. Download `VerbTamper-1.2.1.jar` from [Releases](../../releases)
2. In Burp Suite, go to **Extensions → Installed → Add**
3. Set **Extension type** to `Java`
4. Select the downloaded `.jar` file
5. Click **Next** — you should see `Verb Tamper loaded.` in the output
6. A **Verb Tamper** tab will appear in the main Burp window

---

## Usage

### Via context menu

1. Find a request in Proxy history, Repeater, or any Burp tool
2. Right-click → **Send to Verb Tamper**
3. The request loads into the Verb Tamper tab
4. Select a verb from the dropdown (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD)
5. Edit the path or headers if needed
6. Click **Send**

### Auth token manager

1. Click **Add** in the Auth Tokens panel on the right
2. Enter a label (e.g. "admin", "hacker") and paste the full JWT
3. Select a saved token and click **Apply** to swap it into the Authorization header

### Scan All Verbs

1. Load a request into the panel
2. Click **Scan All Verbs**
3. A results table opens showing each verb's status code, response length, and body preview
4. Rows are colour-coded: green = 2xx, yellow = 3xx, red = 4xx/5xx

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

# Output: build/libs/VerbTamper-1.0.jar
```

> **Why not Maven Central?** The Montoya API jar on Maven Central may not match the exact version bundled with your Burp installation, causing `NoSuchMethodError` at runtime. Extracting directly from your Burp jar guarantees compatibility.

---

## License

MIT
