const express = require("express");

const authRouteV1 = require("../routes/v1/auth.route");
const jwtRouteV1 = require("../routes/v1/jwt.route");
const profileRouteV1 = require("../routes/v1/profile.route");
const wellKnownRouteV1 = require("../routes/v1/well-known.route");
const xmlRouteV1 = require("../routes/v1/xml.route");

const v1App = express();

/**
 * VULNERABILITY: trust proxy = true
 *
 * This sub-app blindly trusts the X-Forwarded-For / X-Real-IP headers
 * injected by a reverse proxy (Nginx, Caddy, load balancer, etc.).
 *
 * Real-world impact: Any IP-based protection (rate limiting, IP blocking)
 * can be bypassed by simply setting:
 *   X-Forwarded-For: 1.2.3.4
 *
 * The secure version (v2) does NOT set this option.
 */
v1App.set("trust proxy", true);

v1App.use("/auth", authRouteV1);
v1App.use("/jwt", jwtRouteV1);
v1App.use("/profile", profileRouteV1);
v1App.use("/xxe", xmlRouteV1);
v1App.use("/.well-known", wellKnownRouteV1);

module.exports = v1App;
