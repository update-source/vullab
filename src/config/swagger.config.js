const swaggerJsdoc = require("swagger-jsdoc");

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Vulnerable Authentication API",
      version: "1.0.0",
      description: "API documentation for authentication vulnerabilities lab",
      contact: {
        name: "VulLab",
      },
    },
    servers: [
      {
        url: "http://localhost:3500",
        description: "Development server",
      },
    ],
    components: {
      schemas: {
        LoginRequest: {
          type: "object",
          required: ["username", "password"],
          properties: {
            username: {
              type: "string",
              minLength: 3,
              maxLength: 50,
              example: "carlos",
            },
            password: {
              type: "string",
              format: "password",
              minLength: 8,
              example: "SecurePass123!",
            },
          },
        },
        OTPRequest: {
          type: "object",
          required: ["otp"],
          properties: {
            otp: {
              type: "string",
              pattern: "^[0-9]{6}$",
              example: "123456",
            },
          },
        },
        RegisterRequest: {
          type: "object",
          required: ["username", "email", "password"],
          properties: {
            username: {
              type: "string",
              minLength: 3,
              maxLength: 30,
              pattern: "^[a-zA-Z0-9_-]+$",
              example: "carlos",
            },
            email: {
              type: "string",
              format: "email",
              example: "carlos@example.com",
            },
            password: {
              type: "string",
              format: "password",
              minLength: 8,
              example: "SecurePass123!",
              description:
                "Must contain at least 8 characters with uppercase, lowercase, number and symbol",
            },
            isEmailVerified: {
              type: "boolean",
              default: false,
              example: true,
              description:
                "Set to true to bypass email verification (for testing without SMTP)",
            },
          },
        },
        ErrorResponse: {
          type: "object",
          properties: {
            success: {
              type: "boolean",
              example: false,
            },
            message: {
              type: "string",
              example: "Error message",
            },
          },
        },
        SuccessResponse: {
          type: "object",
          properties: {
            success: {
              type: "boolean",
              example: true,
            },
            message: {
              type: "string",
              example: "Operation successful",
            },
            data: {
              type: "object",
            },
          },
        },
      },
      securitySchemes: {
        cookieAuth: {
          type: "apiKey",
          in: "cookie",
          name: "session",
        },
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
          description:
            "Paste the JWT token obtained from the login endpoint (without 'Bearer ' prefix)",
        },
      },
    },
    tags: [
      {
        name: "V1 - Authentication (Vulnerable)",
        description: "Vulnerable authentication endpoints for testing",
      },
      {
        name: "V1 - JWT (Vulnerable)",
        description: "Vulnerable JWT endpoints for testing",
      },
      {
        name: "V2 - Authentication (Secure)",
        description: "Secure authentication endpoints with fixes",
      },
      {
        name: "V2 - JWT (Secure)",
        description: "Secure JWT endpoints with proper signature verification",
      },
      {
        name: "V1 - Profile (Vulnerable)",
        description: "User profile endpoints",
      },
      {
        name: "V2 - Profile (Secure)",
        description: "Secure profile endpoints with proper authentication",
      },
      {
        name: "V2 - Well-Known",
        description:
          "RFC 5785 well-known endpoints — exposes the server's RS256 public key as a JWKS for JWT verification labs",
      },
    ],
  },
  apis: ["./src/routes/**/*.js"], // Path to the API routes
};

const specs = swaggerJsdoc(options);

module.exports = specs;
