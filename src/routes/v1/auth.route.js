const express = require("express");
const router = express.Router();
const { authController } = require("../../controllers/v1");
const {
  otpRules,
  loginRules,
  registerRules,
  handleValidation,
  generateForgotPasswordTokenRules,
  resetPasswordBrokenLogicRules,
  requirePendingOtpSession,
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

module.exports = router;
