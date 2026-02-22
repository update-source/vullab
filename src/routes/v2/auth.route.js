const express = require("express");
const router = express.Router();
const { authController } = require("../../controllers/v2");
const {
  otpRules,
  loginRules,
  registerRules,
  handleValidation,
  requirePendingOtpSession,
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
 *                 example: "Password123!"
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
