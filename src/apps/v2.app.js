const express = require("express");

const authRouteV2 = require("../routes/v2/auth.route");
const jwtRouteV2 = require("../routes/v2/jwt.route");
const profileRouteV2 = require("../routes/v2/profile.route");

const v2App = express();

/**
 * SECURE: trust proxy is NOT set (default = false)
 *
 * This sub-app does NOT trust X-Forwarded-For / X-Real-IP headers.
 * req.ip always reflects the real IP of the TCP connection,
 * regardless of any headers the client sends.
 *
 * Result: IP-based protections (rate limiting, IP blocking) cannot
 * be bypassed by header manipulation.
 */

v2App.use("/auth", authRouteV2);
v2App.use("/jwt", jwtRouteV2);
v2App.use("/profile", profileRouteV2);

module.exports = v2App;
