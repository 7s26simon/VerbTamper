VerbTamper  
A Burp Suite extension for quickly testing HTTP verb/method tampering and access-control bypass useful for finding Broken Function Level Authorization (BFLA) and related flaws where endpoints fail to enforce method-, IP-, or URL-based restrictions.

What it does  
Send any request to VerbTamper, change the verb or inject a bypass header, and fire it all without leaving Burp. The request text is fully editable so you can also modify the path, headers, or body before sending. Every send is logged to a history tab and every multi-verb scan is saved alongside it, both exportable as CSV.

Use cases:
Testing whether POST /api/posts/1/flag works when only DELETE /api/admin/posts/1 was intended for regular users  
Checking if PUT or PATCH are accepted on read-only endpoints  
Smuggling a restricted verb through a POST-only endpoint using X-HTTP-Method-Override  
Probing whether the app trusts upstream headers like X-Forwarded-For or X-Original-URL  
Quickly iterating through all HTTP methods on a target endpoint during recon

Features  
Core  
Right-click context menu - "Send to Verb Tamper" from Proxy history, Repeater, or anywhere else in Burp  
Dedicated tab with three sub-tabs - Scanner, Send History, Scan History  
Live verb sync - changing the dropdown rewrites the method in the request text in real time  
Custom verbs - pick Custom... from the dropdown to test non-standard verbs (POSTX, PROPFIND, FOOBAR, etc.); they're added to the dropdown alongside the standard seven and included in Scan All Verbs  
HTTP/2 aware - automatically detects and sends HTTP/2 requests correctly  
Robust response handling - reads responses via raw byte arrays with fallbacks, so HTTP/2 edge cases don't come back as empty  
Auto Content-Length - fixes stale Content-Length headers when you switch between body-bearing and bodyless verbs  
Header sanitisation - normalises CRLF, stitches wrapped JWT continuation lines, terminates the headers block correctly  

Scanner tab  
Scan All Verbs - fires all 7 standard verbs (plus any custom verb in the dropdown) in parallel and shows a colour-coded results table (status, length, preview)  
Bypass header dropdown - one-click insertion of common access-control bypass headers, placed directly after the Host: line:  
Method override: X-HTTP-Method-Override: DELETE/PUT/PATCH, X-HTTP-Method, X-Method-Override (also auto-switches the verb dropdown to POST)  
IP spoofing: X-Forwarded-For, X-Real-IP, X-Originating-IP, X-Remote-IP, X-Client-IP, X-Host, X-Forwarded-Host  
URL rewriting: X-Original-URL, X-Rewrite-URL, X-Override-URL  
Auth token manager - save labelled JWTs and apply them to the current request in one click  
Follow Redirect - when the response is a 3xx with a Location header, the button fires a fresh GET to that URL (preserving auth headers) and appends the new response below the original; works for relative or absolute Locations including cross-origin  
Diff view - line-by-line diff of the last two responses, red for removed, green for added  
Search bars - under each pane: type a query, hit Enter to highlight every match (yellow for all, orange for current), then ◀ / ▶ to jump between them; Esc clears  
Right-click → Copy URL - copy the full URL of the current request from either pane; the response area also offers "Copy Location URL" when a redirect target is present  
Back / Forward navigation - browse your send history like Repeater  
Send to Repeater - reads the current dropdown and editor state every click, so you push the intended request, not the last one sent  
Copy Req / Copy Resp / Clear - obvious buttons; Clear also resets the verb dropdown and removes any custom verbs  

Send History tab  
Every single request sent through the Scanner is logged with timestamp, verb, host, path, status, and length  
Rows are colour-coded by status class  
Followed redirects appear with a [redirect] tag in the verb column so you can spot them  
Double-click an entry to reload it back into the Scanner editor  
"View Response" shows the full response body in a read-only dialog  
"Export All to CSV" dumps summary columns for pivoting in Excel  
Delete individual entries or Clear All  

Scan History tab  
Every completed "Scan All Verbs" run is saved with timestamp, host, path, loaded verb, and all results  
A "Notable" column flags scans that returned a mix of 2xx and 4xx responses, the signature of a likely BFLA finding  
Double-click to replay an old scan in the same colour-coded results dialog  
"Export CSV" on the scan dialog saves one scan (Verb, Status, Length, Preview, FullResponse)  
"Export All to CSV" on the history tab flattens every scan into one spreadsheet-friendly table (Timestamp, Host, Path, OriginalVerb, VerbTried, Status, Length, Preview)  

Installation  
Requirements  
Burp Suite (Community or Professional) - tested on v2026.3.2  
No other dependencies  

Steps  
Download VerbTamper-1.8.jar from [Releases](https://claude.ai/releases)  
In Burp Suite, go to Extensions → Installed → Add  
Set Extension type to Java  
Select the downloaded .jar file  
Click Next - you should see Verb Tamper 1.8 loaded. in the output  
A Verb Tamper tab will appear in the main Burp window  

Usage  
Via context menu  
Find a request in Proxy history, Repeater, or any Burp tool  
Right-click → Send to Verb Tamper  
The request loads into the Scanner tab  
Select a verb from the dropdown (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD, or Custom... for anything else)  
Optionally pick a bypass header from the Headers dropdown  
Edit the path or headers if needed  
Click Send  

Auth token manager  
Click Add in the Auth Tokens panel on the right  
Enter a label (e.g. "admin", "hacker") and paste the full JWT  
Select a saved token and click Apply to swap it into the Authorization header  

Scan All Verbs  
Load a request into the panel  
Click Scan All Verbs  
A results table opens showing each verb's status code, response length, and body preview  
Rows are colour-coded: green = 2xx, yellow = 3xx, red = 4xx/5xx  
Click Export CSV on the dialog to save this scan  
The completed scan is also added to the Scan History tab for later replay or bulk export  

Search  
Under each pane there's a search field. Type a word and hit Enter - every match in the pane gets highlighted, and the first one at or below your caret turns orange. Use ◀ and ▶ to jump between matches; the counter shows your position (e.g. 3 / 12). Esc clears the search.  

Follow Redirect  
If the response is a 3xx with a Location header, the Follow Redirect button enables. Click it once to send a GET to that location (your headers including Authorization are preserved). The new response is appended below the original with a separator so you can see both. Click again to follow another hop if the new response is also a redirect.  

Diff  
After sending two or more requests, click Diff to open a line-by-line comparison of the last two responses.  

Workflow example  
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

Method-override smuggling example  
# Pick "X-HTTP-Method-Override: DELETE" from the Headers dropdown.  
# The verb dropdown auto-switches to POST. Hit Send.  

POST /api/admin/posts/1 HTTP/2  
Host: target.example.com  
X-HTTP-Method-Override: DELETE  
Authorization: Bearer <user-token>  

Building from source  
Requires JDK 11+ and Gradle. You'll need to supply the Montoya API by extracting it from your local Burp jar:  
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

# Output: build/libs/VerbTamper-1.8.jar  

Why not Maven Central? The Montoya API jar on Maven Central may not match the exact version bundled with your Burp installation, causing NoSuchMethodError at runtime. Extracting directly from your Burp jar guarantees compatibility.  

License  
MIT
