const express = require("express");
const router = express.Router();
const { authController } = require("../../controllers/v2");
const {
  changePasswordBruteForceRules,
  generateForgotPasswordTokenRules,
  handleValidation,
  loginRules,
  otpRules,
  registerRules,
  requireAuthSession,
  requirePendingOtpSession,
  requireTrustedHost,
  resetSecurePasswordBrokenLogicRules,
} = require("../../middlewares");

/**
 * @swagger
 * /api/v2/auth/register:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Register a new user
 *     description: |
 *       Register a new user account. Since SMTP is not configured, you can set
 *       `isEmailVerified: true` to bypass email verification for testing.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RegisterRequest'
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Validation error
 */
router.post(
  "/register",
  registerRules,
  handleValidation,
  authController.register,
);

/**
 * @swagger
 * /api/v2/auth/enum/different-responses:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Secure login (fixed enumeration)
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
  "/enum/different-responses",
  loginRules,
  handleValidation,
  authController.loginEnumDifferentFix,
);

/**
 * @swagger
 * /api/v2/auth/enum/subtle-responses:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Secure login (fixed subtle enumeration)
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
  authController.loginEnumSubtleFix,
);

/**
 * @swagger
 * /api/v2/auth/enum/timing-responses:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Secure login (fixed timing attack)
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
  authController.loginEnumTimingFix,
);

/**
 * @swagger
 * /api/v2/auth/enum/account-lock:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Secure login with proper account locking
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
  authController.loginSecureAccountLock,
);

/**
 * @swagger
 * /api/v2/auth/brute-force/broken-ip-block:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Secure login with proper IP blocking
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
  authController.loginSecureIpBlock,
);

/**
 * @swagger
 * /api/v2/auth/brute-force/multiple-credentials-per-request:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Secure login (reject multiple credentials)
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
  "/brute-force/multiple-credentials-per-request",
  loginRules,
  handleValidation,
  authController.loginSecureMultipleCredsPerRequest,
);

/**
 * @swagger
 * /api/v2/auth/brute-force/stay-logged-in-cookie:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Login with secure stay-logged-in cookie (selector:validator pattern)
 *     description: |
 *       Secure implementation of the "remember me" feature using the `selector:validator` pattern.
 *
 *       **How it works:**
 *       1. User logs in with `stay-logged-in: "on"`
 *       2. Server generates a random `selector` (16 hex) and `validator` (64 hex)
 *       3. Only `SHA-256(validator)` is stored in DB — plain validator is never persisted
 *       4. Cookie is set as `selector:validator` with 30-day expiry
 *
 *       **Cookie format:**
 *       ```
 *       stay-logged-in = selector:validator
 *       Example: a1b2c3d4e5f6a7b8:c9d0e1f2...
 *       ```
 *
 *       After login, use `GET /api/v2/profile/cookie` with the issued cookie.
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
 *                 description: Set to "on" to receive a secure remember-me cookie
 *             required:
 *               - username
 *               - password
 *     responses:
 *       302:
 *         description: Login successful, redirected to /api/v2/profile/cookie
 *         headers:
 *           Set-Cookie:
 *             description: Session cookie and optionally stay-logged-in cookie
 *             schema:
 *               type: string
 *               example: "stay-logged-in=a1b2c3d4e5f6a7b8:c9d0e1f2...; HttpOnly; SameSite=Lax"
 *       401:
 *         description: Invalid credentials
 */
router.post(
  "/brute-force/stay-logged-in-cookie",
  loginRules,
  handleValidation,
  authController.loginSecureStayLoggedInCookie,
);

/**
 * @swagger
 * /api/v2/auth/brute-force/password-change/login:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Login for password change brute-force lab (Secure)
 *     description: |
 *       Secure login endpoint for the "Password brute-force via password change" lab.
 *
 *       **Security fix compared to V1:**
 *       - No `currentPasswordAttempt` counter stored in session
 *       - Rate limiting for change-password is enforced **per userId** in the service layer
 *         (using Redis), not per session — re-logging in does NOT reset the counter
 *
 *       After login, use `POST /api/v2/auth/brute-force/password-change` to change password.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       302:
 *         description: Redirect to profile on success
 *       401:
 *         description: Invalid credentials
 */
router.post(
  "/brute-force/password-change/login",
  loginRules,
  handleValidation,
  authController.loginSecureBruteViaPasswordChange,
);

/**
 * @swagger
 * /api/v2/auth/brute-force/password-change:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Change password (Secure - username bound to session + userId-based rate limit)
 *     description: |
 *       Secure password change endpoint that fixes all vulnerabilities present in the V1 version.
 *
 *       **Security fix 1: Username bound to session**
 *
 *       The target user is resolved from `req.authUserId` (set by `requireAuthSession`),
 *       not from the request body. The `username` field is completely removed.
 *       An attacker cannot change another user's password by submitting a different username.
 *
 *       **Security fix 2: No behavioral difference**
 *
 *       Both wrong current-password cases return the same error regardless of
 *       whether new passwords match. The `changePasswordBruteForce` validation middleware
 *       enforces `new-password-1 === new-password-2` before reaching the service,
 *       eliminating the behavioral leak used for brute-forcing.
 *
 *       **Security fix 3: Rate limit per userId (not per session)**
 *
 *       Failed attempts are tracked via Redis key `change-pw-attempts:{userId}`.
 *       Re-logging in creates a new session but the userId stays the same,
 *       so the counter is NOT reset — the session-based bypass is completely mitigated.
 *     security:
 *       - cookieAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - current-password
 *               - new-password-1
 *               - new-password-2
 *             properties:
 *               current-password:
 *                 type: string
 *                 example: "OldPass@123"
 *                 description: Current password of the authenticated user
 *               new-password-1:
 *                 type: string
 *                 example: "NewPass@456"
 *                 description: New password (min 8 chars, uppercase, lowercase, number, symbol)
 *               new-password-2:
 *                 type: string
 *                 example: "NewPass@456"
 *                 description: Must match new-password-1
 *     responses:
 *       200:
 *         description: Password changed successfully
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
 *                   example: "Password changed successfully"
 *       401:
 *         description: Current password is incorrect or unauthorized
 *       429:
 *         description: Too many failed attempts (rate limit per userId, not per session)
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
 *                   example: "Too many failed attempts. Try again later."
 */
router.post(
  "/brute-force/password-change",
  requireAuthSession,
  changePasswordBruteForceRules,
  handleValidation,
  authController.changeSecurePasswordBruteForce,
);

/**
 * @swagger
 * /api/v2/auth/password-reset-broken-logic:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Generate password reset token (Secure)
 *     description: |
 *       Generates a password reset token and sends it to the user's email.
 *       This is the **secure version** — same flow as V1 but the reset step properly validates the token.
 *
 *       **How it works:**
 *       1. Client sends `username` and/or `email`
 *       2. Server looks up user by `username` (priority) or `email`
 *       3. If user **does NOT exist** → returns 200 (no email sent) — prevents enumeration
 *       4. If user **exists** → generate raw token: `crypto.randomBytes(32).toString('hex')`
 *       5. Hash token: `sha256(rawToken)` → save to `user_tokens` table with 5-minute expiry
 *       6. Email the **raw token** to the user
 *
 *       **Security note:** Always returns 200 regardless of user existence
 *       to prevent username/email enumeration.
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
 *           If the user exists, a reset token is emailed (valid for 5 minutes).
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
 * /api/v2/auth/password-reset-broken-logic/reset:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Reset password with proper token validation (Secure)
 *     description: |
 *       Resets the user's password. Unlike V1, this endpoint **fully validates** the token.
 *
 *       **Security fixes compared to V1:**
 *       - ✅ Token is looked up in the database and must exist
 *       - ✅ Token expiry is strictly checked (5-minute window)
 *       - ✅ Token is deleted after use (one-time use)
 *       - ✅ Password is hashed only after token is confirmed valid (no wasted CPU)
 *       - ✅ User identity comes from the token itself (not from user-supplied `username`)
 *
 *       **How it works:**
 *       1. Hash submitted token: `sha256(token)` → lookup in `user_tokens` table
 *       2. If token not found → `401 Token is invalid or expired`
 *       3. If token expired → destroy token → `401 Token is invalid or expired`
 *       4. Hash new password with bcrypt
 *       5. Update user password via `token.userId` (not from request body)
 *       6. Destroy token (prevent reuse)
 *
 *       **Usage flow:**
 *       1. Call `POST /api/v2/auth/password-reset-broken-logic` to receive token via email
 *       2. Submit the token from email in this endpoint's body
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
 *                 description: New password (min 8 chars, must include upper, lower, number, symbol)
 *               confirm-password:
 *                 type: string
 *                 format: password
 *                 example: "NewSecure@123"
 *                 description: Must match new-password
 *               temp-forgot-password-token:
 *                 type: string
 *                 example: "a3f9c2b1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"
 *                 description: |
 *                   The raw token received in the password reset email.
 *                   **Secure:** Server validates this token against the database before allowing reset.
 *           examples:
 *             valid_reset:
 *               summary: Reset with valid token from email
 *               value:
 *                 new-password: "NewSecure@123"
 *                 confirm-password: "NewSecure@123"
 *                 temp-forgot-password-token: "a3f9c2b1d4e5f6a7b8c9d0e1f2a3b4c5..."
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
 *       401:
 *         description: Token is invalid or expired
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
 *       400:
 *         description: Validation error (passwords don't match, weak password, missing fields)
 */
router.post(
  "/password-reset-broken-logic/reset",
  resetSecurePasswordBrokenLogicRules,
  handleValidation,
  authController.resetSecurePasswordBrokenLogic,
);

/**
 * @swagger
 * /api/v2/auth/password-reset-poisoning:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Generate password reset link (Secure - Host Header Injection prevented)
 *     description: |
 *       Generates a password reset token and sends a **clickable reset link** to the user's email.
 *       This is the **secure version** that mitigates Password Reset Poisoning by validating
 *       the request's `Host` header against a server-side allowlist via the `requireTrustedHost`
 *       middleware **before** the reset link is generated.
 *
 *       **Security fix: `requireTrustedHost` middleware**
 *
 *       The middleware reads `req.hostname` and checks it against `ALLOWED_HOSTS`
 *       (configured via `process.env.ALLOWED_HOSTS`, defaults to `"localhost"`).
 *       If the hostname is not in the allowlist, the request is **rejected with HTTP 400**
 *       before any token is generated or any email is sent.
 *
 *       **Contrast with V1 (vulnerable):**
 *       - V1 sets `trust proxy: true` → Express blindly trusts `X-Forwarded-Host`
 *         → attacker can inject any domain into `req.hostname`
 *       - V2 does **not** trust the reverse proxy header AND validates hostname against
 *         an allowlist → poisoning the `Host` / `X-Forwarded-Host` header is blocked
 *
 *       **Why the attack fails on V2:**
 *       1. Attacker sends `X-Forwarded-Host: attacker.com`
 *       2. `requireTrustedHost` checks `req.hostname` against `ALLOWED_HOSTS`
 *       3. `"attacker.com"` is not in the allowlist → **400 Invalid or untrusted host**
 *       4. No token is generated, no email is sent → attack is blocked
 *
 *       **Reset link format (when hostname is trusted):**
 *       ```
 *       http://<trusted-hostname>/api/v2/auth/password-reset-poisoning?temp-forgot-password-token=<token>
 *       ```
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
 *               summary: Normal request (trusted host)
 *               value:
 *                 username: "carlos"
 *                 forgot-password: true
 *             poisoned_attempt:
 *               summary: Would-be poisoned request — blocked by requireTrustedHost
 *               value:
 *                 username: "victim"
 *                 forgot-password: true
 *     parameters:
 *       - in: header
 *         name: X-Forwarded-Host
 *         schema:
 *           type: string
 *           example: "attacker.exploit-server.net"
 *         description: |
 *           **⛔ Attack vector blocked in V2.**
 *           Even if this header is sent, `requireTrustedHost` will reject the request
 *           because `"attacker.exploit-server.net"` is not in the `ALLOWED_HOSTS` list.
 *           The server returns **400 Invalid or untrusted host** before any token is created.
 *     responses:
 *       200:
 *         description: |
 *           Always returns 200 regardless of whether the user exists (prevents enumeration).
 *           If the user exists and the host is trusted, a reset link is sent via email (valid 5 minutes).
 *           If the user does not exist, no email is sent but the response is identical.
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
 *         description: |
 *           Validation error (missing required fields / invalid format)
 *           **or** host is not in the trusted allowlist (`requireTrustedHost` rejected the request).
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
 *                   example: "Invalid or untrusted host"
 */
router.post(
  "/password-reset-poisoning",
  requireTrustedHost,
  generateForgotPasswordTokenRules,
  handleValidation,
  authController.generateSecurePasswordResetPoisoning,
);

/**
 * @swagger
 * /api/v2/auth/password-reset-poisoning/reset:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Reset password via token from poisoning-resistant link (Secure)
 *     description: |
 *       Resets the user's password using a token received from the reset link generated by
 *       `/api/v2/auth/password-reset-poisoning`.
 *
 *       **This endpoint has full token validation** — the attack chain is broken at the
 *       *generation* step (by `requireTrustedHost`), but even if an attacker somehow
 *       obtains a token, this reset step still validates it correctly.
 *
 *       **Token validation flow:**
 *       1. Compute `sha256(submitted token)` → look up in `user_tokens` table
 *       2. If not found → `401 Token is invalid or expired`
 *       3. If `expiresAt <= now` → destroy token → `401 Token is invalid or expired`
 *       4. Hash new password with bcrypt
 *       5. Update user password via `token.userId` (identity comes from DB, not request body)
 *       6. Destroy token (one-time use — prevents reuse)
 *
 *       **Security properties:**
 *       - ✅ Token is cryptographically random (`crypto.randomBytes(32)`)
 *       - ✅ Only SHA-256 hash is stored in DB — raw token is never persisted
 *       - ✅ Token expires after 5 minutes
 *       - ✅ Token is deleted after use (one-time use)
 *       - ✅ User identity is resolved from the token, **not** from user-supplied input
 *
 *       **Usage flow:**
 *       1. Call `POST /api/v2/auth/password-reset-poisoning` to receive token link via email
 *       2. Extract the `temp-forgot-password-token` from the link
 *       3. Submit it in this endpoint's body along with the new password
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
 *                 description: New password (min 8 chars, must include upper, lower, number, symbol)
 *               confirm-password:
 *                 type: string
 *                 format: password
 *                 example: "NewSecure@123"
 *                 description: Must match new-password
 *               temp-forgot-password-token:
 *                 type: string
 *                 example: "a3f9c2b1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"
 *                 description: |
 *                   The raw token from the reset link received via email.
 *                   Server SHA-256 hashes this and validates against the DB.
 *                   Token is valid for 5 minutes and can only be used once.
 *           examples:
 *             valid_reset:
 *               summary: Legitimate user — reset with valid token from email link
 *               value:
 *                 new-password: "NewSecure@123"
 *                 confirm-password: "NewSecure@123"
 *                 temp-forgot-password-token: "a3f9c2b1d4e5f6a7b8c9d0e1f2a3b4c5..."
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
  authController.resetSecurePasswordViaPoison,
);

/**
 * @swagger
 * /api/v2/auth/2FA/simple-bypass:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Secure 2FA login (no bypass)
 *     description: After this step, call /api/v2/auth/2FA/verify-otp with the OTP.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: OTP sent to email
 */
router.post(
  "/2FA/simple-bypass",
  loginRules,
  handleValidation,
  authController.loginSecure2FASimpleBypass,
);

/**
 * @swagger
 * /api/v2/auth/2FA/broken-logic:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Secure 2FA login (fixed broken logic)
 *     description: |
 *       This is the secure version of the broken-logic endpoint. OTP is properly tied to the
 *       authenticated session, not a manipulable cookie.
 *
 *       **Security fixes:**
 *       1. OTP is generated based on session userId, not cookie
 *       2. Session regeneration prevents session fixation
 *       3. OTP attempts are tracked and limited
 *
 *       After this step, call /api/v2/auth/2FA/broken-verify-otp with the OTP.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: OTP sent to email
 *       401:
 *         description: Invalid credentials
 */
router.post(
  "/2FA/broken-logic",
  loginRules,
  handleValidation,
  authController.loginSecure2FABrokenLogic,
);

/**
 * @swagger
 * /api/v2/auth/2FA/verify-otp:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Verify OTP code (secure)
 *     description: Call this after /api/v2/auth/2FA/simple-bypass to complete login.
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
 */
router.post(
  "/2FA/verify-otp",
  requirePendingOtpSession,
  otpRules,
  handleValidation,
  authController.verifySecure2FAOtp,
);

/**
 * @swagger
 * /api/v2/auth/2FA/broken-verify-otp:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Verify OTP with secure implementation (fixed broken logic)
 *     description: |
 *       This is the secure version of the broken-verify-otp endpoint. The user identity
 *       is properly determined from the session, not from a manipulable cookie.
 *
 *       **Security fixes:**
 *       1. User identity taken from session userId, not cookie
 *       2. OTP attempts are tracked and limited (max 3 attempts)
 *       3. Session regeneration after successful verification
 *       4. Proper session cleanup on max attempts exceeded
 *
 *       **Usage:** Send OTP in request body with valid session.
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
 *       400:
 *         description: Invalid OTP
 *       403:
 *         description: Maximum OTP attempts exceeded
 */
router.post(
  "/2FA/broken-verify-otp",
  requirePendingOtpSession,
  otpRules,
  handleValidation,
  authController.brokenSecureVerify2FAOtp,
);

/**
 * @swagger
 * /api/v2/auth/logout:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Logout (secure session cleanup)
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Logged out successfully
 */
router.post("/logout", authController.logout);

module.exports = router;
