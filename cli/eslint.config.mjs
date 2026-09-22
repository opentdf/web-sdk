import js from '@eslint/js';
import { defineConfig } from 'eslint/config';
import chaiFriendly from 'eslint-plugin-chai-friendly';
import prettierRecommended from 'eslint-plugin-prettier/recommended';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default defineConfig(
  {
    ignores: ['dist/**'],
  },
  js.configs.recommended,
  tseslint.configs.recommendedTypeChecked,
  {
    files: ['src/**/*.ts', 'tests/**/*.ts'],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: globals.node,
    },
  },
  {
    files: ['tests/**/*.ts'],
    plugins: {
      'chai-friendly': chaiFriendly,
    },
    languageOptions: {
      globals: globals.mocha,
    },
    rules: {
      // Chai assertions intentionally use expression statements such as `.to.be.true`.
      '@typescript-eslint/no-unused-expressions': 'off',
      'chai-friendly/no-unused-expressions': 'error',
    },
  },
  prettierRecommended
);
