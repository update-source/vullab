const express = require("express");
const router = express.Router();
const { authController, profileController } = require("../../controllers/v1");
const {
  changePasswordRules,
  generateForgotPasswordTokenRules,
  handleValidation,
  loginRules,
  otpRules,
  requireAuthSession,
  requireAuthSessionIgnoreStage,
  requireAuthSessionOrCookie,
  requirePendingOtpSession,
  resolveCookieByBase64,
  resetPasswordBrokenLogicRules,
  resetSecurePasswordBrokenLogicRules,
} = require("../../middlewares");

/**
 * @swagger
 * /api/v1/auth/enum/different-responses:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Login with different error responses (Vulnerable to enumeration)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       302:
 *         description: Redirect to profile on success
 *       400:
 *         description: Invalid credentials
 */
router.post(
  "/enum/different-responses",
  loginRules,
  handleValidation,
  authController.loginEnumDifferent,
);

/**
 * @swagger
 * /api/v1/auth/enum/subtle-responses:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Login with subtle enumeration vulnerability
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       302:
 *         description: Redirect to profile on success
 */
router.post(
  "/enum/subtle-responses",
  loginRules,
  handleValidation,
  authController.loginEnumSubtle,
);

/**
 * @swagger
 * /api/v1/auth/enum/timing-responses:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Login vulnerable to timing attacks
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       302:
 *         description: Redirect to profile on success
 */
router.post(
  "/enum/timing-responses",
  loginRules,
  handleValidation,
  authController.loginEnumTiming,
);

/**
 * @swagger
 * /api/v1/auth/enum/account-lock:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Login with account lock enumeration
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       302:
 *         description: Redirect to profile on success
 */
router.post(
  "/enum/account-lock",
  loginRules,
  handleValidation,
  authController.loginEnumViaAccountLock,
);

/**
 * @swagger
 * /api/v1/auth/brute-force/broken-ip-block:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Login with broken IP blocking
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       302:
 *         description: Redirect to profile on success
 */
router.post(
  "/brute-force/broken-ip-block",
  loginRules,
  handleValidation,
  authController.loginBrokenIpBlock,
);

/**
 * @swagger
 * /api/v1/auth/brute-force/multiple-credentials-per-request:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Login accepting multiple credentials per request
 *     description: |
 *       This endpoint has a critical vulnerability that allows brute-forcing multiple passwords in a single request.
 *
 *       **Vulnerability:** The password field accepts both string and array of strings. Validation doesn't reject arrays.
 *
 *       **Normal request (1 password):**
 *       ```json
 *       {
 *         "username": "carlos",
 *         "password": "Password123!"
 *       }
 *       ```
 *
 *       **Exploit request (100 passwords in 1 request):**
 *       ```json
 *       {
 *         "username": "carlos",
 *         "password": [
 *           "password123",
 *           "admin123",
 *           "Pass@123",
 *           "Secret123!",
 *           "..."
 *         ]
 *       }
 *       ```
 *
 *       **Impact:** Bypasses rate limiting since it counts as 1 attempt, not 100. The server will try each
 *       password in the array until finding a match.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 example: "carlos"
 *               password:
 *                 oneOf:
 *                   - type: string
 *                     example: "SecurePass123!"
 *                   - type: array
 *                     items:
 *                       type: string
 *                     example: ["SecurePass123!", "admin123", "Pass@123", "Secret123!", "test1234"]
 *             required:
 *               - username
 *               - password
 *     responses:
 *       302:
 *         description: Redirect to profile on success (password matched)
 *       401:
 *         description: Invalid credentials (none of the passwords matched)
 *       429:
 *         description: Too many failed attempts from this IP
 */
router.post(
  "/brute-force/multiple-credentials-per-request",
  loginRules,
  handleValidation,
  authController.loginMultipleCredsPerRequest,
);
/**
 * @swagger
 * /api/v1/auth/brute-force/stay-logged-in-cookie:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Login with stay-logged-in cookie (Vulnerable to offline brute-force)
 *     description: |
 *       This endpoint implements a "stay logged in" feature that stores user credentials in a cookie.
 *
 *       **Vulnerability:** The cookie contains base64-encoded username + MD5 password hash.
 *       MD5 is cryptographically broken and can be brute-forced offline.
 *
 *       **How it works:**
 *       1. User logs in with `isStayLoggedIn: "on"`
 *       2. Server creates cookie: `base64(username + md5(password))`
 *       3. Cookie is sent to client with 5-minute expiry
 *
 *       **Cookie format:**
 *       ```
 *       stay-logged-in = base64(username + md5_hash)
 *       Example: dXNlcm5hbWU1ZTEwYWRjOTJiYWQ0Yjk5NmY5YzMzOGQwNWFiZGU4Ng==
 *       Decoded: username5e10adc92bad4b996f9c338d05abde86
 *                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 *                         32-char MD5 hash
 *       ```
 *
 *       **Attack scenario:**
 *       1. Attacker intercepts the cookie
 *       2. Decodes base64 to get username + MD5 hash
 *       3. Brute-forces MD5 hash offline (very fast)
 *       4. Uses cracked password to login
 *
 *       **Why it's vulnerable:**
 *       - MD5 is fast to compute (millions of hashes/second)
 *       - No salt used
 *       - Cookie is not encrypted, just base64 encoded
 *       - Can be cracked offline without server interaction
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 example: "carlos"
 *               password:
 *                 type: string
 *                 example: "SecurePass123!"
 *               stay-logged-in:
 *                 type: string
 *                 enum: ["on", "off"]
 *                 example: "on"
 *                 description: Set to "on" to receive stay-logged-in cookie
 *             required:
 *               - username
 *               - password
 *     responses:
 *       302:
 *         description: Login successful, session created
 *         headers:
 *           Set-Cookie:
 *             description: Session cookie and optionally stay-logged-in cookie
 *             schema:
 *               type: string
 *               example: "session=s%3A...; stay-logged-in=dXNlcm5hbWU1ZTEwYWRj..."
 *       401:
 *         description: Invalid credentials
 */
router.post(
  "/brute-force/stay-logged-in-cookie",
  loginRules,
  handleValidation,
  authController.loginStayLoggedInCookie,
);

/**
 * @swagger
 * /api/v1/auth/brute-force/password-change/login:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Login for password change brute-force lab (Vulnerable - session-based rate limit)
 *     description: |
 *       Login endpoint used in the "Password brute-force via password change" lab.
 *
 *       **Vulnerability: Rate limit is session-based**
 *
 *       After successful login, the session stores `currentPasswordAttempt = 0`.
 *       The change-password rate limiter tracks failed attempts **per session**, not per target username.
 *
 *       **Exploit flow (bypass rate limit):**
 *       1. Login as user A (wiener) → session A created with `currentPasswordAttempt = 0`
 *       2. Use session A to attack user B (carlos) via `/brute-force/password-change`
 *       3. After 2 failed attempts → counter reaches MAX
 *       4. **Login again as user A** → new session, counter reset to 0
 *       5. Continue brute-forcing carlos → repeat until carlos's password found
 *
 *       **Why it's vulnerable:**
 *       - The rate limit counter is tied to the attacker's session, not the victim's account
 *       - By refreshing the session (re-login), the counter resets
 *       - Attacker can brute-force indefinitely using Burp Suite macro
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       302:
 *         description: Redirect to profile, session includes currentPasswordAttempt = 0
 *       401:
 *         description: Invalid credentials
 */
router.post(
  "/brute-force/password-change/login",
  loginRules,
  handleValidation,
  authController.loginBruteViaPasswordChange,
);

/**
 * @swagger
 * /api/v1/auth/brute-force/password-change:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Change password (Vulnerable - username not verified against session + session-based rate limit)
 *     description: |
 *       Password change endpoint with two vulnerabilities used in the "Password brute-force via
 *       password change" lab.
 *
 *       **Vulnerability 1: Username not bound to session**
 *
 *       The `username` field in the request body is used directly to find the target user,
 *       without verifying it matches the authenticated user's session.
 *       An attacker logged in as user A can submit `username=carlos` to change carlos's password.
 *
 *       **Vulnerability 2: Behavioral difference leaks correct password**
 *
 *       The response differs based on whether `current-password` is correct:
 *       - Wrong current-password + `new-password-1 ≠ new-password-2` → `"Current password is incorrect"`
 *       - **Correct** current-password + `new-password-1 ≠ new-password-2` → `"New passwords do not match"` ← leaked!
 *       - Wrong current-password + `new-password-1 = new-password-2` → counter +1 (account lock path)
 *
 *       **Vulnerability 3: Rate limit is session-based (bypass)**
 *
 *       The failed attempt counter is stored in `req.session.currentPasswordAttempt`.
 *       Re-logging in as user A resets the counter, bypassing the rate limit entirely.
 *     security:
 *       - cookieAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - current-password
 *               - new-password-1
 *               - new-password-2
 *             properties:
 *               username:
 *                 type: string
 *                 example: "carlos"
 *                 description: |
 *                   Target username. **Vulnerable:** not validated against the session user.
 *                   Attacker (wiener) can set this to any user (carlos) to attack their account.
 *               current-password:
 *                 type: string
 *                 example: "§password-to-brute-force§"
 *                 description: Current password of the target user (the value to brute-force)
 *               new-password-1:
 *                 type: string
 *                 example: "abc12345"
 *                 description: New password (set to a different value than new-password-2 to exploit behavioral leak)
 *               new-password-2:
 *                 type: string
 *                 example: "xyz12345"
 *                 description: Confirm new password (keep different from new-password-1 during brute-force)
 *         examples:
 *           normal_change:
 *             summary: Legitimate password change
 *             value:
 *               username: "wiener"
 *               current-password: "peter"
 *               new-password-1: "NewPass@123"
 *               new-password-2: "NewPass@123"
 *           exploit_brute_force:
 *             summary: Attacker brute-forcing carlos (new passwords differ to avoid lock)
 *             value:
 *               username: "carlos"
 *               current-password: "attempt123"
 *               new-password-1: "abc12345"
 *               new-password-2: "xyz12345"
 *     responses:
 *       200:
 *         description: Password changed successfully (session destroyed)
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "success"
 *                 message:
 *                   type: string
 *                   example: "Password Changed"
 *       400:
 *         description: |
 *           New passwords do not match (and current password is correct).
 *           **This response indicates the brute-forced password is correct!**
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "error"
 *                 message:
 *                   type: string
 *                   example: "New passwords do not match"
 *       401:
 *         description: Current password is incorrect (current-password is wrong)
 *       429:
 *         description: Account locked (too many wrong attempts with matching new passwords)
 */
router.post(
  "/brute-force/password-change",
  requireAuthSession,
  changePasswordRules,
  handleValidation,
  authController.changePasswordBruteForce,
);

/**
 * @swagger
 * /api/v1/auth/password-reset-broken-logic:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Generate password reset token (Vulnerable - Broken Logic)
 *     description: |
 *       Generates a password reset token and sends it to the user's email.
 *
 *       **Vulnerability: Always returns HTTP 200 regardless of user existence (prevents enumeration,
 *       but combined with the broken reset step creates full account takeover)**
 *
 *       **How it works (correct order):**
 *       1. Client sends `username` and/or `email`
 *       2. Server looks up user by `username` (priority) or `email`
 *       3. If user **does NOT exist** → throw `AppError(200, "Please check your email...")` → returns 200, nothing saved to DB
 *       4. If user **exists** → generate raw token: `crypto.randomBytes(32).toString('hex')`
 *       5. Hash token: `sha256(rawToken)` → save to `user_tokens` table (linked to user)
 *       6. Email the **raw token** to the user
 *
 *       **Why always 200?** To prevent username/email enumeration — attacker cannot
 *       distinguish between "user not found" and "email sent" from the response.
 *
 *       **The real vulnerability is in the reset step** (`/reset`), where
 *       the token is never validated — so this generation step becomes irrelevant.
 *       An attacker can skip this step entirely and reset any account directly.
 *
 *       **At least one of `username` or `email` is required.**
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 minLength: 3
 *                 maxLength: 50
 *                 example: "carlos"
 *                 description: Username of the account (optional if email is provided)
 *               email:
 *                 type: string
 *                 format: email
 *                 example: "carlos@example.com"
 *                 description: Email of the account (optional if username is provided)
 *               forgot-password:
 *                 type: boolean
 *                 example: true
 *                 description: Must be true to trigger the flow
 *             required:
 *               - forgot-password
 *           examples:
 *             by_username:
 *               summary: Request by username
 *               value:
 *                 username: "carlos"
 *                 forgot-password: true
 *             by_email:
 *               summary: Request by email
 *               value:
 *                 email: "carlos@example.com"
 *                 forgot-password: true
 *     responses:
 *       200:
 *         description: |
 *           Always returns 200 regardless of whether the user exists.
 *           If the user exists, a reset token is emailed.
 *           If not, no email is sent but the response is identical.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "success"
 *                 message:
 *                   type: string
 *                   example: "Please check your email for a reset password link."
 *       400:
 *         description: Validation error (missing required fields or invalid format)
 */
router.post(
  "/password-reset-broken-logic",
  generateForgotPasswordTokenRules,
  handleValidation,
  authController.generateFogotPasswordToken,
);

/**
 * @swagger
 * /api/v1/auth/password-reset-broken-logic/reset:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Reset password with broken token validation (Vulnerable)
 *     description: |
 *       Resets the user's password. The token in the request body is **NOT validated**.
 *
 *       **Vulnerability: Token validation is completely disabled**
 *
 *       The reset token logic is intentionally commented out in the service:
 *       - The server does **not** check if the token exists in the database
 *       - The server does **not** check if the token belongs to the target user
 *       - The server does **not** check if the token has expired
 *       - `temp-forgot-password-token` only needs to be present in the body (any string value works)
 *
 *       **Exploit flow:**
 *       1. Attacker does NOT need to request a reset token first
 *       2. Send a POST request with any target `username`
 *       3. Set new password in body
 *       4. Pass any string as `temp-forgot-password-token`
 *       5. Server resets the password without any token verification → **Account takeover**
 *
 *       **Example exploit request:**
 *       ```json
 *       {
 *         "username": "victim",
 *         "new-password": "Hacked@123",
 *         "confirm-password": "Hacked@123",
 *         "temp-forgot-password-token": "anything"
 *       }
 *       ```
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - new-password
 *               - confirm-password
 *               - temp-forgot-password-token
 *             properties:
 *               username:
 *                 type: string
 *                 minLength: 3
 *                 maxLength: 50
 *                 example: "carlos"
 *                 description: Username of the account to reset
 *               new-password:
 *                 type: string
 *                 format: password
 *                 example: "NewSecure@123"
 *                 description: New password (min 8 chars, must include upper, lower, number, symbol)
 *               confirm-password:
 *                 type: string
 *                 format: password
 *                 example: "NewSecure@123"
 *                 description: Must match new-password
 *               temp-forgot-password-token:
 *                 type: string
 *                 example: "anyvalueworks"
 *                 description: |
 *                   Reset token from the email. **Vulnerable:** any non-empty string is accepted
 *                   because server-side token validation is completely disabled.
 *           examples:
 *             normal_reset:
 *               summary: Normal user (with their own token from email)
 *               value:
 *                 username: "carlos"
 *                 new-password: "NewPass@123"
 *                 confirm-password: "NewPass@123"
 *                 temp-forgot-password-token: "real-token-from-email"
 *             exploit_reset:
 *               summary: Attacker reset (no valid token needed)
 *               value:
 *                 username: "victim"
 *                 new-password: "Hacked@123"
 *                 confirm-password: "Hacked@123"
 *                 temp-forgot-password-token: "anything"
 *     responses:
 *       200:
 *         description: Password reset successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "success"
 *                 message:
 *                   type: string
 *                   example: "Password reset successfully"
 *       400:
 *         description: Validation error (passwords don't match, weak password, missing fields)
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "error"
 *                 message:
 *                   type: string
 *                   example: "Passwords do not match"
 */
router.post(
  "/password-reset-broken-logic/reset",
  resetPasswordBrokenLogicRules,
  handleValidation,
  authController.resetPasswordBrokenLogic,
);

/**
 * @swagger
 * /api/v1/auth/password-reset-poisoning:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Generate password reset link (Vulnerable - Password Reset Poisoning via X-Forwarded-Host)
 *     description: |
 *       Generates a password reset token and sends a **clickable reset link** to the user's email.
 *       The link is built using `req.hostname` — which in Express is influenced by the `X-Forwarded-Host`
 *       header when `trust proxy` is enabled.
 *
 *       **Root cause:** `v1App.set("trust proxy", true)` is configured on the server.
 *       This makes Express trust the `X-Forwarded-Host` header and use its value as `req.hostname`,
 *       allowing an attacker to control the domain in the generated reset URL.
 *
 *       **Vulnerability: Password Reset Poisoning via X-Forwarded-Host**
 *
 *       The reset link is built as:
 *       ```
 *       http://<req.hostname>/api/v1/auth/password-reset-poisoning?temp-forgot-password-token=<token>
 *       ```
 *       Since `req.hostname` reflects `X-Forwarded-Host`, the attacker can poison the link destination.
 *
 *       **Exploit flow (based on PortSwigger lab):**
 *       1. Attacker intercepts/sends a POST to this endpoint targeting the victim's username
 *       2. Adds the `X-Forwarded-Host` header pointing to their own server:
 *          ```
 *          X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
 *          ```
 *       3. Server generates a valid token, saves SHA-256 hash to DB, then emails the victim
 *          a reset link pointing to **the attacker's server**
 *       4. Victim clicks the link → attacker's server access log captures the real token as a query param
 *       5. Attacker copies the token from their server log
 *       6. Attacker calls `/password-reset-poisoning/reset` with the stolen token to set a new password
 *       7. Attacker logs in with the new password → **Full account takeover**
 *
 *       **Email received by victim (poisoned):**
 *       ```
 *       Your password reset token is:
 *       http://exploit-server.net/api/v1/auth/password-reset-poisoning?temp-forgot-password-token=abc123real
 *       ```
 *
 *       **Why it's vulnerable:**
 *       - `trust proxy: true` causes Express to trust `X-Forwarded-Host` and set `req.hostname` to its value
 *       - No allowlist of trusted domains is enforced on `req.hostname`
 *       - The generated token is cryptographically valid and usable on the real server
 *
 *       **At least one of `username` or `email` is required.**
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 minLength: 3
 *                 maxLength: 50
 *                 example: "carlos"
 *                 description: Username of the account (optional if email is provided)
 *               email:
 *                 type: string
 *                 format: email
 *                 example: "carlos@example.com"
 *                 description: Email of the account (optional if username is provided)
 *               forgot-password:
 *                 type: boolean
 *                 example: true
 *                 description: Must be true to trigger the flow
 *             required:
 *               - forgot-password
 *           examples:
 *             normal_request:
 *               summary: Normal request (no X-Forwarded-Host)
 *               value:
 *                 username: "carlos"
 *                 forgot-password: true
 *             poisoned_request:
 *               summary: Poisoned request (attacker's username + X-Forwarded-Host header)
 *               value:
 *                 username: "victim"
 *                 forgot-password: true
 *     parameters:
 *       - in: header
 *         name: X-Forwarded-Host
 *         schema:
 *           type: string
 *           example: "YOUR-EXPLOIT-SERVER-ID.exploit-server.net"
 *         description: |
 *           **⚠️ Primary exploit vector.**
 *           Because the server sets `trust proxy: true`, Express reads this header and sets
 *           `req.hostname` to its value. The server then uses `req.hostname` to build the
 *           password reset link that is emailed to the victim.
 *
 *           Set this to an attacker-controlled server to capture the victim's reset token
 *           from the server's access log when the victim clicks the link.
 *     responses:
 *       200:
 *         description: |
 *           Always returns 200 regardless of whether the user exists (prevents enumeration).
 *           If the user exists, a poisoned reset link is emailed.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "success"
 *                 message:
 *                   type: string
 *                   example: "Please check your email for a reset password link."
 *       400:
 *         description: Validation error (missing required fields or invalid format)
 */
router.post(
  "/password-reset-poisoning",
  generateForgotPasswordTokenRules,
  handleValidation,
  authController.generatePasswordResetPoisoning,
);

/**
 * @swagger
 * /api/v1/auth/password-reset-poisoning/reset:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Reset password via poisoned token (used with /password-reset-poisoning)
 *     description: |
 *       Resets the user's password using a token from the email link generated by the `/password-reset-poisoning` endpoint.
 *
 *       **This endpoint has proper token validation** (unlike the broken-logic reset). However, it is the
 *       **target step** in the password reset poisoning attack chain — once the attacker captures the
 *       valid token (via `Host` header poisoning on the generate step), they use it here to take over the account.
 *
 *       **Token validation flow (correct behaviour):**
 *       1. Server receives `temp-forgot-password-token` from the request body
 *       2. Computes `sha256(token)` and looks it up in the `user_tokens` table
 *       3. Checks token type is `password_reset` and has not expired (5-minute TTL)
 *       4. Updates the user's password and deletes the used token
 *
 *       **Note:** No `username` field is required — the user identity is resolved from the token itself.
 *
 *       **Exploit scenario (full attack chain with `/password-reset-poisoning`):**
 *       1. Attacker sends POST to `/password-reset-poisoning` with `Host: attacker.com` and victim's username
 *       2. Victim receives email: `http://attacker.com/...?temp-forgot-password-token=<real_token>`
 *       3. Victim clicks link → real token is sent to attacker's server
 *       4. Attacker sends POST to this endpoint with the captured token and their chosen new password
 *       5. Victim's password is reset → **Full account takeover**
 *
 *       **Example exploit request:**
 *       ```json
 *       {
 *         "new-password": "Hacked@123",
 *         "confirm-password": "Hacked@123",
 *         "temp-forgot-password-token": "<token_stolen_from_victim>"
 *       }
 *       ```
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - new-password
 *               - confirm-password
 *               - temp-forgot-password-token
 *             properties:
 *               new-password:
 *                 type: string
 *                 format: password
 *                 example: "NewSecure@123"
 *                 description: New password (min 8 chars, must include uppercase, lowercase, number, symbol)
 *               confirm-password:
 *                 type: string
 *                 format: password
 *                 example: "NewSecure@123"
 *                 description: Must match new-password
 *               temp-forgot-password-token:
 *                 type: string
 *                 example: "a3f1c2d4e5b6..."
 *                 description: |
 *                   The raw reset token received via the email link.
 *                   Server will SHA-256 hash this and validate against the DB.
 *                   Token expires after 5 minutes.
 *           examples:
 *             legitimate_reset:
 *               summary: Legitimate user resetting their own password
 *               value:
 *                 new-password: "MyNewPass@123"
 *                 confirm-password: "MyNewPass@123"
 *                 temp-forgot-password-token: "real-token-from-email"
 *             attacker_exploit:
 *               summary: Attacker using stolen token (from poisoned reset link)
 *               value:
 *                 new-password: "Hacked@123"
 *                 confirm-password: "Hacked@123"
 *                 temp-forgot-password-token: "token-stolen-from-victim-click"
 *     responses:
 *       200:
 *         description: Password reset successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "success"
 *                 message:
 *                   type: string
 *                   example: "Password reset successfully"
 *       400:
 *         description: Validation error (passwords don't match, weak password, or missing fields)
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "error"
 *                 message:
 *                   type: string
 *                   example: "Passwords do not match"
 *       401:
 *         description: Token is invalid or has expired
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "error"
 *                 message:
 *                   type: string
 *                   example: "Token is invalid or expired"
 */
router.post(
  "/password-reset-poisoning/reset",
  resetSecurePasswordBrokenLogicRules,
  handleValidation,
  authController.resetPasswordViaPoison,
);

/**
 * @swagger
 * /api/v1/auth/2FA/simple-bypass:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: 2FA with simple bypass vulnerability
 *     description: After this step, call /api/v1/auth/2FA/verify-otp with the OTP.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       302:
 *         description: Redirect to profile (bypassing OTP)
 */
router.post(
  "/2FA/simple-bypass",
  loginRules,
  handleValidation,
  authController.login2FASimpleBypass,
);

/**
 * @swagger
 * /api/v1/auth/2FA/simple-bypass-ver2:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: 2FA bypass version 2 (middleware vulnerability)
 *     description: After this step, call /api/v1/auth/2FA/verify-otp with the OTP.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       302:
 *         description: Redirect to profile
 */
router.post(
  "/2FA/simple-bypass-ver2",
  loginRules,
  handleValidation,
  authController.login2FASimpleBypassVer2,
);

/**
 * @swagger
 * /api/v1/auth/2FA/broken-logic:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: 2FA login with broken logic vulnerability
 *     description: |
 *       This endpoint has a flawed 2FA implementation. After successful login, the OTP is generated
 *       based on the "verify" cookie value instead of the authenticated user.
 *
 *       **Vulnerability:** Attacker can manipulate the "verify" cookie to generate OTP for another user.
 *
 *       **Exploit flow:**
 *       1. Login with your own credentials → receive verify=your_username cookie
 *       2. Change cookie to verify=victim_username (using Burp)
 *       3. Login again with your credentials → OTP is generated for victim
 *       4. Brute-force the OTP via /2FA/broken-verify-otp
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: OTP sent, sets verify cookie
 *       401:
 *         description: Invalid credentials
 */
router.post(
  "/2FA/broken-logic",
  loginRules,
  handleValidation,
  authController.login2FABrokenLogic,
);

/**
 * @swagger
 * /api/v1/auth/2FA/verify-otp:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Verify OTP code
 *     description: Call this after /api/v1/auth/2FA/simple-bypass or /api/v1/auth/2FA/simple-bypass-ver2.
 *     security:
 *       - cookieAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/OTPRequest'
 *     responses:
 *       302:
 *         description: Redirect to profile on success
 *       401:
 *         description: Invalid OTP
 */
router.post(
  "/2FA/verify-otp",
  requirePendingOtpSession,
  otpRules,
  handleValidation,
  authController.verify2FAOtp,
);

/**
 * @swagger
 * /api/v1/auth/2FA/broken-verify-otp:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Verify OTP with broken logic (uses verify cookie)
 *     description: |
 *       This endpoint verifies OTP based on the "verify" cookie instead of the session.
 *
 *       **Vulnerability:** The user identity is determined by the "verify" cookie which can be
 *       manipulated by the attacker.
 *
 *       **Usage:** Send OTP in request body. The username is read from "verify" cookie.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/OTPRequest'
 *     responses:
 *       302:
 *         description: Redirect to profile on success (logged in as victim)
 *       400:
 *         description: Invalid OTP or missing verify cookie
 */
router.post(
  "/2FA/broken-verify-otp",
  otpRules,
  handleValidation,
  authController.brokenVerify2FAOtp,
);

/**
 * @swagger
 * /api/v1/auth/logout:
 *   post:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Logout current session
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Logged out successfully
 */
router.post("/logout", authController.logout);

// ═══════════════════════════════════════════════════════════════
// PROTECTED PROFILE ENDPOINTS
// These are the resource endpoints that auth labs redirect to after login.
// ═══════════════════════════════════════════════════════════════

/**
 * @swagger
 * /api/v1/auth/profile:
 *   get:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Get user profile (requires logged_in session stage)
 *     description: |
 *       Standard session-protected profile endpoint.
 *       Used after any auth lab login to verify the user is authenticated.
 *
 *       ---
 *       **🧭 Lab Guide:** Call any auth login endpoint first, then access this.
 *
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: User profile data
 *       401:
 *         description: Unauthorized
 */
router.get("/profile", requireAuthSession, profileController.getProfile);

/**
 * @swagger
 * /api/v1/auth/2FA/profile:
 *   get:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Get profile ignoring session stage (2FA bypass vulnerable)
 *     description: |
 *       **VULNERABLE endpoint.** This profile check ignores the session `stage` field.
 *       After 2FA login sets `stage: "pending"`, this endpoint still grants access
 *       because it only checks `session.userId` without verifying `stage === "logged_in"`.
 *
 *       **Root cause:** `requireAuthSessionIgnoreStage` middleware does not check
 *       `session.stage`, so a user who has completed step 1 (password) but NOT step 2
 *       (OTP) can directly access the profile.
 *
 *       ---
 *       **🧭 Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|  
 *       | 1 | POST | `/api/v1/auth/2FA/simple-bypass` | Login (password only, OTP pending) |
 *       | 2 | GET | `/api/v1/auth/2FA/profile` ← you are here | Access profile (vuln: skips OTP check) |
 *
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: User profile data (even without completing 2FA)
 *       401:
 *         description: Unauthorized
 */
router.get(
  "/2FA/profile",
  requireAuthSessionIgnoreStage,
  profileController.getProfile,
);

/**
 * @swagger
 * /api/v1/auth/stay-logged-in/profile:
 *   get:
 *     tags: [V1 - Authentication (Vulnerable)]
 *     summary: Get profile via session or stay-logged-in cookie (vulnerable)
 *     description: |
 *       **VULNERABLE endpoint.** Accepts authentication via either session or
 *       `stay-logged-in` cookie. The cookie contains `base64(username:md5password)`,
 *       which is vulnerable to offline brute-force.
 *
 *       ---
 *       **🧭 Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|  
 *       | 1 | POST | `/api/v1/auth/stay-logged-in/brute-force` | Login with remember-me |
 *       | 2 | GET | `/api/v1/auth/stay-logged-in/profile` ← you are here | Use cookie (vuln: base64+md5) |
 *
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: cookie
 *         name: stay-logged-in
 *         schema:
 *           type: string
 *         description: Base64 encoded string containing username + MD5 password hash
 *     responses:
 *       200:
 *         description: User profile data retrieved successfully
 *       401:
 *         description: Unauthorized
 */
router.get(
  "/stay-logged-in/profile",
  requireAuthSessionOrCookie,
  resolveCookieByBase64,
  profileController.getProfile,
);

module.exports = router;
