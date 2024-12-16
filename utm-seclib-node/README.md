# UTM PKI Security Node Library

A Node.js library for implementing PKI (Public Key Infrastructure) security features in UTM (Unmanned Traffic Management) systems. This library provides utilities for handling IETF HTTP message signatures, content digests, and PKI operations.

## Table of Contents

- [Installation](#installation)
- [Features](#features)
- [Usage](#usage)
  - [Authentication Setup](#authentication-setup)
  - [Basic Usage](#basic-usage)
  - [API Reference](#api-reference)
- [Examples](#examples)
  - [Client Implementation](#client-implementation)
  - [Server Implementation](#server-implementation)
- [Requirements](#requirements)

## Installation

1. Create a `.npmrc` file in your project's root directory with the following content:
```
@tiiuae:registry=https://npm.pkg.github.com/
//npm.pkg.github.com/:_authToken=YOUR_GITHUB_PAT
```

2. Install the package:
```bash
npm install @tiiuae/utm_seclib_node
```

## Features

- IETF HTTP Message Signatures
- Content Digest Creation and Verification
- PKI Operations (Signing, Verification)
- Secure Request/Response Handling
- Built-in Logging System

## Usage

### Authentication Setup

1. Create a GitHub Personal Access Token (PAT) with `read:packages` permission
2. Replace `YOUR_GITHUB_PAT` in your `.npmrc` with your actual PAT

### Basic Usage

```javascript
const utmSecLib = require('@tiiuae/utm_seclib_node');

// Initialize logger
const logs = utmSecLib.logger();

// Create IETF Parameters
const params = utmSecLib.CreateIETFRequestParams(
    'POST',
    'http://example.com/api',
    JSON.stringify({ data: 'example' }),
    'your-bearer-token'
);

// Create IETF Request
const ietfRequest = utmSecLib.CreateIETFRequest(
    params,
    privateKeyPem,
    certPath,
    keyId,
    algorithm
);
```

### API Reference

#### Core Functions

- **CreateIETFRequestParams(method, url, body, bearerToken)**
  - Creates parameters for IETF HTTP request
  - Returns: `IETFRequestParams`

- **CreateIETFRequest(params, privateKey, certPath, keyId, algorithm)**
  - Creates a signed IETF HTTP request
  - Returns: `IETFRequestResult`

- **VerifySignature(publicKeyPem, signature, signatureBase)**
  - Verifies HTTP message signatures
  - Returns: `boolean`

- **VerifyContentDigest(body, contentDigestHeader)**
  - Verifies content digest
  - Returns: `boolean`

- **Logger()**
  - Creates a configured logger instance
  - Returns: `Logger`

#### Types

```typescript
interface IETFRequestParams {
    method: string;
    url: string;
    body: string;
    bearerToken?: string;
}

interface IETFRequestResult {
    contentDigest: string;
    sigInput: string;
    certBase64: string;
    signature: string;
    authHeader: string;
}
```

## Examples

### Client Implementation

```javascript
const utmSecLib = require('@tiiuae/utm_seclib_node');

async function main() {
    const data = { userName: "example", password: "password" };
    const params = utmSecLib.CreateIETFRequestParams('POST', serverUrl, JSON.stringify(data), 'token');
    
    const ietfRequest = utmSecLib.CreateIETFRequest(
        params,
        clientPrivateKeyPem,
        clientCertPath,
        pkiKeyId,
        pkiAlgorithm
    );

    // Use the request headers
    const headers = {
        'Accept': 'application/json',
        'X-Certificate-Bundle': ietfRequest.certBase64,
        'Content-Type': 'application/json',
        'Signature': ietfRequest.signature,
        'Content-Digest': ietfRequest.contentDigest,
        'Signature-Input': ietfRequest.sigInput
    };
}
```

### Server Implementation

```javascript
const utmSecLib = require('@tiiuae/utm_seclib_node');

app.post('/api/authenticate', async (req, res) => {
    const { clientPublicKeyPem, requestSignature, requestSignBase } = 
        utmSecLib.ExtractPropertiesFromRequest(req);

    const isSignatureValid = utmSecLib.VerifySignature(
        clientPublicKeyPem,
        requestSignature.split(':')[1],
        requestSignBase
    );

    if (isSignatureValid) {
        // Process the authenticated request
    }
});
```

## Requirements

- Node.js >= 18.17.0
- GitHub account with package read access
- Valid PKI certificates and keys
