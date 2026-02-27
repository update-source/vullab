const express = require("express");
const router = express.Router();
const authRouteV1 = require("./v1/auth.route");
const jwtRouteV1 = require("./v1/jwt.route");
const profileRouteV1 = require("./v1/profile.route");
const profileRouteV2 = require("./v2/profile.route");
const authRouteV2 = require("./v2/auth.route");

router.use("/auth", authRouteV2);
router.use("/v1/auth", authRouteV1);
router.use("/v1/jwt", jwtRouteV1);
router.use("/v1/profile", profileRouteV1);
router.use("/v2/profile", profileRouteV2);
router.use("/v2/auth", authRouteV2);

module.exports = router;
