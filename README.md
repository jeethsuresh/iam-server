# IAM Server

TL;DR: Federated auth server with no advance notice required (no client ID/secret). Pre-pre-pre-alpha. 

## API flow

1. User creates an account on the IAM server
2. User wishes to log into an application via a platform-agnostic client (opaque network boundary)
3. User enters username in the application client; the application server sends a backend to the IAM server.
    - Application server retrieves domain found in the [email-formatted] username
    - Application server sends backend request to `<domain>/backend/register`
    - In the request body, application server contains:
        - username - full username of user
        - tokenURL - majority of the application server's backend client logic; handles token verification, and sets the backend session variables required during the login process
        - redirectURL - final URL which sets the token (localstorage, cookie, etc.) on the client
4. IAM server returns a public key in response to the application server's initial query, encoded in base64. This response also contains the username, and a session ID (UUID format to identify the specific login request, unique per user per login attempt)
5. Application server redirects to the IAM server's root endpoint, with `sessionID` and `username` parameters in the URL
6. On successful login, the IAM server sends the token to the application server backend using the tokenURL endpoint
7. Once the token has been verified and accepted by the application server, the IAM server redirects to the redirectURL provided by the application server in step 3 with the session ID asa query parameter. This allows the application server to feed the token to the application client.

## Known issues
- Session ID is a UUID, not protected at all (token theft if compromised)
    - suggested solution: generate public key clientside and send that over to the application server at the start of the login process
- Process is brittle - many network requests and failure points
- Process relies on JWT hashing with public/private keypairs; does not work for other types of tokens
- Process requires a tokenURL, redirectURL, and login URL on the application server side, and hardcoded magic URLs on the IAM server side. 
- UI/UX is pretty bad
- Currently uses a SQLite database, not portable/will wipe if the container is restarted
- Username is the only unique identifier for each user, brittle and no security against impersonation via DNS attacks
- Server doesn't guarantee valid email-formatted username
- Server has no way to handle redirects/multitenant domains, etc.
- No portability across client or server (no 301s/302s)