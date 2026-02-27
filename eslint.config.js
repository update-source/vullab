const js = require("@eslint/js");
const prettier = require("eslint-config-prettier");
const simpleImportSort = require("eslint-plugin-simple-import-sort");
const sortDestructureKeys = require("eslint-plugin-sort-destructure-keys");

module.exports = [
  js.configs.recommended,
  prettier,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "commonjs",
      globals: {
        process: "readonly",
        __dirname: "readonly",
        __filename: "readonly",
        require: "readonly",
        module: "writable",
        exports: "writable",
        console: "readonly",
        Buffer: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
      },
    },
    plugins: {
      "simple-import-sort": simpleImportSort,
      "sort-destructure-keys": sortDestructureKeys,
    },
    rules: {
      // Import sorting: Node builtins → third-party → internal (../)
      "simple-import-sort/imports": [
        "warn",
        {
          groups: [
            // Node.js built-ins (crypto, path, fs, etc.)
            [
              "^(assert|buffer|child_process|cluster|console|constants|crypto|dgram|dns|domain|events|fs|http|https|module|net|os|path|perf_hooks|process|punycode|querystring|readline|repl|stream|string_decoder|sys|timers|tls|tty|url|util|v8|vm|wasi|worker_threads|zlib)(/.*)?$",
            ],
            // Third-party packages
            ["^[^.]"],
            // Internal: relative imports
            ["^\\."],
          ],
        },
      ],
      "simple-import-sort/exports": "warn",
      "sort-destructure-keys/sort-destructure-keys": "warn",

      // Code quality
      "no-unused-vars": [
        "warn",
        { varsIgnorePattern: "^_", argsIgnorePattern: "^_" },
      ],
      "no-console": "off",
      "no-undef": "error",

      // Best practices
      eqeqeq: ["error", "always"],
      "no-var": "error",
      "prefer-const": "warn",
    },
  },
  {
    ignores: ["node_modules/**", "dist/**", "build/**"],
  },
];
