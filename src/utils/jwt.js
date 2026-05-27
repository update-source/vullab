const {
  JWT_KID,
  JWT_PRIVATE_KEY,
  JWT_PUBLIC_KEY,
  JWT_SECRET,
  WEAK_JWT_SECRET,
  accessTokenOptions,
  refreshTokenOptions,
} = require("../config/jwt.config");

const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");
const jwkToPem = require("jwk-to-pem");

/*
Note:
In all v2 jwt patches I used env variables (hardcoded public key / secret).
This is very safe but does not reflect enough for real-world cases.
For example, in microservices or multi-tenant systems with multiple issuers
(e.g., Google, Auth0), a single hardcoded key cannot cover all scenarios —
the proper approach is dynamic JWKS resolution combined with an allowlist
of trusted domains/URLs within the same service, not separate deployments.

For the JKU injection fix specifically, the standard mitigation is to maintain
a trusted URL allowlist and only fetch JWKS from those pre-approved origins.
This is technically feasible even in a local environment.

However, what is genuinely difficult to demonstrate locally is the *attacker side*:
hosting an external JWKS server requires an externally reachable network,
which is not available in a purely local setup. That is the actual limitation
of this project for demonstrating the full JKU injection attack chain.
*/

const generateAccessToken = (payload) => {
  return jwt.sign(payload, JWT_SECRET, accessTokenOptions);
};

const generateAccessTokenWithWeakSecret = (payload) => {
  return jwt.sign(payload, WEAK_JWT_SECRET, accessTokenOptions);
};

const generateAccessTokenWithRS256Alg = (payload) => {
  const options = { ...accessTokenOptions, algorithm: "RS256", keyid: JWT_KID };
  return jwt.sign(payload, JWT_PRIVATE_KEY, options);
};

const generateRefreshToken = (payload) => {
  return jwt.sign(payload, JWT_SECRET, refreshTokenOptions);
};

const verifyAccessTokenViaHS256Alg = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET, {
      issuer: accessTokenOptions.issuer,
      audience: accessTokenOptions.audience,
      algorithms: [accessTokenOptions.algorithm],
    });
  } catch (error) {
    return null;
  }
};
//https://curity.io/resources/learn/jwt-best-practices/
const verifyAccessTokenViaRS256Alg = (token) => {
  try {
    return jwt.verify(token, JWT_PUBLIC_KEY, {
      issuer: accessTokenOptions.issuer,
      audience: accessTokenOptions.audience,
      algorithms: ["RS256"],
      keyid: accessTokenOptions.keyid,
    });
  } catch (error) {
    return null;
  }
};

const verifyRefreshToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET, {
      issuer: refreshTokenOptions.issuer,
      audience: refreshTokenOptions.audience,
      algorithms: [refreshTokenOptions.algorithm],
    });
  } catch (error) {
    return null;
  }
};

const verifyUnsignedAccessToken = (token) => {
  try {
    const decodedHeader = jwt.decode(token, { complete: true })?.header;
    /*
    The reason I wrote secret set to undefined 
    is because when secret is set and alg is none, 
    jsonwebtoken will thow an error, 
    so in order for the vulnerability to succeed, 
    you must intentionally set the secret to undefined.
    */
    const secret = decodedHeader?.alg === "none" ? undefined : JWT_SECRET;
    return jwt.verify(token, secret, {
      issuer: refreshTokenOptions.issuer,
      audience: refreshTokenOptions.audience,
      algorithms: [refreshTokenOptions.algorithm, "none"],
    });
  } catch (error) {
    return null;
  }
};
const verifyAccessTokenWithWeakSecret = (token) => {
  try {
    return jwt.verify(token, WEAK_JWT_SECRET, {
      issuer: accessTokenOptions.issuer,
      audience: accessTokenOptions.audience,
      algorithms: [accessTokenOptions.algorithm],
    });
  } catch (error) {
    return null;
  }
};

const verifyAccessTokenViaJwk = (token) => {
  try {
    const decodedHeader = jwt.decode(token, { complete: true })?.header;
    if (decodedHeader?.jwk) {
      const pem = jwkToPem(decodedHeader.jwk);
      return jwt.verify(token, pem, {
        issuer: accessTokenOptions.issuer,
        audience: accessTokenOptions.audience,
        algorithms: ["RS256"],
        keyid: accessTokenOptions.keyid,
      });
    }
    // If user does not send jwk, the public key will be used
    return jwt.verify(token, JWT_PUBLIC_KEY, {
      issuer: accessTokenOptions.issuer,
      audience: accessTokenOptions.audience,
      algorithms: ["RS256"],
      keyid: accessTokenOptions.keyid,
    });
  } catch (error) {
    return null;
  }
};

const fetchJwkByKid = async (url, kid) => {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Fail to fetch ${url}`);
  }
  const data = await response.json();
  if (!data || !Array.isArray(data.keys)) {
    throw new Error("Invalid jwks format");
  }
  return data.keys.find((key) => key.kid === kid);
};

const verifyAccessTokenViaJku = async (token) => {
  try {
    //To fit the scenario, instead of using JWT_PUBLIC_KEY directly, we will call api to get jwks
    const decodedHeader = jwt.decode(token, { complete: true })?.header;
    const port = process.env.PORT || 3500;
    const jwksUrl =
      decodedHeader?.jku ??
      `http://localhost:${port}/api/v1/.well-known/jwks.json`;

    if (!decodedHeader.kid) {
      throw new Error("Require kid field in header to fetch Jwks");
    }
    const jwk = await fetchJwkByKid(jwksUrl, decodedHeader.kid);
    if (!jwk) {
      return null;
    }
    const pem = jwkToPem(jwk);
    return jwt.verify(token, pem, {
      issuer: accessTokenOptions.issuer,
      audience: accessTokenOptions.audience,
      algorithms: ["RS256"],
      keyid: "vullab-rs256-key-1",
    });
  } catch (error) {
    return null;
  }
};

const verifyAccessTokenViaKid = (token) => {
  try {
    const decodedHeader = jwt.decode(token, { complete: true })?.header;
    if (decodedHeader?.kid) {
      try {
        const pem = fs.readFileSync(path.join(__dirname, decodedHeader.kid), {
          // path traversal
          encoding: "utf-8",
        });
        return jwt.verify(token, pem, {
          issuer: accessTokenOptions.issuer,
          audience: accessTokenOptions.audience,
          algorithms: [accessTokenOptions.algorithm],
        });
      } catch (error) {
        return null;
      }
    }
    return jwt.verify(token, JWT_SECRET, {
      issuer: accessTokenOptions.issuer,
      audience: accessTokenOptions.audience,
      algorithms: [accessTokenOptions.algorithm],
    });
  } catch (error) {
    return null;
  }
};

const verifyAccessTokenViaAlg = async (token) => {
  try {
    const decodedHeader = jwt.decode(token, { complete: true })?.header;
    /*
    Bc i using jsonwebtoken in version >= 9, 
    they have added a protection mechanism that 
    you cannot use public key to verify jwt for alg which is HS256
    */
    if (decodedHeader?.alg === "RS256" || decodedHeader?.alg === "HS256") {
      if (!decodedHeader.kid) return null;
      const port = process.env.PORT || 3500;
      const jwksUrl = `http://localhost:${port}/api/v1/.well-known/jwks.json`;
      const jwk = await fetchJwkByKid(jwksUrl, decodedHeader.kid);
      if (!jwk) {
        return null;
      }
      const pem = jwkToPem(jwk);
      // Custom
      if (decodedHeader.alg === "HS256") {
        const [header, payload, signature] = token.split(".");
        const dataToSign = `${header}.${payload}`;

        /*
        Use raw DER bytes as the HMAC key.
        Strip PEM headers/footer and base64-decode to get the raw binary key.
        This matches Burp Suite JWT Editor "Copy Public Key as Symmetric Key".
        */
        const pemBody = pem
          .replace("-----BEGIN PUBLIC KEY-----", "")
          .replace("-----END PUBLIC KEY-----", "")
          .replace(/\s+/g, "");
        const keyBytes = Buffer.from(pemBody, "base64");

        const expectedSignature = crypto
          .createHmac("sha256", keyBytes)
          .update(dataToSign)
          .digest("base64url");

        if (signature === expectedSignature) {
          return jwt.decode(token);
        }
        return null;
      }
      return jwt.verify(token, pem, {
        issuer: accessTokenOptions.issuer,
        audience: accessTokenOptions.audience,
        algorithms: ["RS256"],
        keyid: "vullab-rs256-key-1",
      });
    }
  } catch (error) {
    return null;
  }
};

const generateJwkFromPem = (pem) => {
  return crypto.createPublicKey(pem).export({ format: "jwk" });
};

const decodeToken = (token) => {
  return jwt.decode(token); // jwt.decode never throws, returns null on invalid input
};

module.exports = {
  decodeToken,
  verifyAccessTokenViaHS256Alg,
  verifyAccessTokenViaJku,
  verifyRefreshToken,
  verifyAccessTokenViaKid,
  verifyAccessTokenViaJwk,
  verifyUnsignedAccessToken,
  verifyAccessTokenViaRS256Alg,
  verifyAccessTokenViaAlg,
  verifyAccessTokenWithWeakSecret,
  generateJwkFromPem,
  generateAccessToken,
  generateRefreshToken,
  generateAccessTokenWithRS256Alg,
  generateAccessTokenWithWeakSecret,
};
