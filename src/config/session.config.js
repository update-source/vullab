require("dotenv").config({
  path: require("path").resolve(__dirname, "../../.env"),
});
const { redisStore } = require("./redis.config");
const session = require("express-session");

module.exports = session({
  secret: process.env.SESSION_SECRET || "dev-secret",
  resave: false,
  saveUninitialized: false,
  store: redisStore,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 24h
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  },
  name: "session",
});
