import { dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

import globals from "globals";
import tsParser from "@typescript-eslint/parser";
import tsPlugin from "@typescript-eslint/eslint-plugin";

export default [
  {
    ignores: ["dist/", "node_modules/"],
    files: ["src/**/*.ts", "index.ts"],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
      },
      parser: tsParser,
      parserOptions: {
        tsconfigRootDir: __dirname,
        ecmaVersion: "latest",
        sourceType: "module",
        project: "./tsconfig.json",
      },
    },
    plugins: {
      "@typescript-eslint": tsPlugin,
    },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          ignoreRestSiblings: true,
        },
      ],
      camelcase: ["error", { properties: "always" }],
      indent: ["error", 4, { SwitchCase: 1 }],
      quotes: ["error", "single", { avoidEscape: true }],
      "no-console": "warn",
      "consistent-return": "error",
      "no-var": "error",
      "prefer-const": "error",
      "no-multiple-empty-lines": ["error", { max: 1, maxEOF: 0 }],
      eqeqeq: ["error", "always"],
      "object-curly-spacing": ["error", "always"],
      "linebreak-style": ["error", "unix"],
      "prefer-promise-reject-errors": ["error", { allowEmptyReject: true }],
      "func-names": ["error", "as-needed"],
      "max-len": ["error", { code: 200 }],
      "no-useless-constructor": "error",
      "no-empty-function": "error",
      "no-eval": "error",
      "callback-return": "error",
    },
  },
];
