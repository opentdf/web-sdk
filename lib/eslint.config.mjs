import typescriptEslint from "@typescript-eslint/eslint-plugin";
import globals from "globals";
import tsParser from "@typescript-eslint/parser";
import path from "node:path";
import { fileURLToPath } from "node:url";
import js from "@eslint/js";
import { FlatCompat } from "@eslint/eslintrc";
import pluginChaiFriendly from "eslint-plugin-chai-friendly";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const compat = new FlatCompat({
    baseDirectory: __dirname,
    recommendedConfig: js.configs.recommended,
    allConfig: js.configs.all
});

export default [
    ...compat.extends("plugin:@typescript-eslint/recommended", "plugin:prettier/recommended"),
    {
        plugins: {
            "chai-friendly": pluginChaiFriendly,
            "@typescript-eslint": typescriptEslint,
        },

        languageOptions: {
            globals: {
                ...globals.browser,
            },

            parser: tsParser,
            ecmaVersion: 12,
            sourceType: "module",

            parserOptions: {
                project: ["**/tsconfig.json"],
            },
        },

        rules: {
            // See https://www.npmjs.com/package/eslint-plugin-chai-friendly
            "@typescript-eslint/no-unused-expressions": "off", // disable original rule
            "chai-friendly/no-unused-expressions": "error"
        },
    },
    {
        files: ["**/*.spec.ts"],

        rules: {
            "@typescript-eslint/ban-ts-comment": "off",
        },
    },
];