# UTM PKI Security Node Library - Developer Guide

This guide is for developers working on the UTM PKI Security Node Library codebase.

## Development Setup

### 1. Root Project Setup
```bash
# Clone the repository
git clone https://github.com/tiiuae/utm-sec-lib.git
cd utm-sec-lib

# Install root project dependencies (for husky)
npm install

# Husky will be automatically installed and configured
# Pre-commit hook will run ESLint on utm-seclib-node files
```

### 2. Library Setup
```bash
# Navigate to the library directory
cd utm-seclib-node

# Install dependencies
npm install
```

## Available Scripts

In the `utm-seclib-node` directory, you can run:

- `npm run build` - Compiles TypeScript code to JavaScript in `dist` directory
- `npm run clean` - Removes the `dist` directory
- `npm run lint` - Runs ESLint on all TypeScript files
- `npm run lint:fix` - Runs ESLint and automatically fixes issues where possible
- `npm run prepare` - Automatically runs build before publishing

## Publishing Process

1. Configure GitHub Package Registry:
   ```bash
   # Update .npmrc with your GitHub Personal Access Token (PAT)
   # Your PAT needs write:packages permission
   
   # Current .npmrc
   @tiiuae:registry=https://npm.pkg.github.com/
   //npm.pkg.github.com/:_authToken=YOUR_GITHUB_PAT
   save-exact=true
   engine-strict=true
   ```

2. Update version in package.json:
   ```bash
   # Manually update version in package.json
   # or use npm version commands
   npm version patch  # for bug fixes (1.5.0 -> 1.5.1)
   npm version minor  # for new features (1.5.0 -> 1.6.0)
   npm version major  # for breaking changes (1.5.0 -> 2.0.0)
   ```

3. Build and publish:
   ```bash
   # Clean and build
   npm run clean
   npm run build

   # Run linting check
   npm run lint

   # Publish to GitHub Package Registry
   npm publish
   ```

## Git Hooks

- **pre-commit**: Automatically runs ESLint on TypeScript files before each commit
  - Checks files in `utm-seclib-node/src/**/*.ts` and `utm-seclib-node/index.ts`
  - Must pass for commit to succeed
# utm-sec-lib
