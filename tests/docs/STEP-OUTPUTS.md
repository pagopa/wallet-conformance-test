# Step Outputs Reference Guide

This guide describes the **output structure of each base class step** in both Issuance and Presentation flows.
Use this reference when building custom tests or extending step implementations to understand what data 
you can extract and assert on from each step's response.

---

## Table of Contents

- [Issuance Flow Steps](#issuance-flow-steps)
  - [FetchMetadataDefaultStep](#fetchmetadatadefaultstep)
  - [PushedAuthorizationRequestDefaultStep](#pushedauthorizationrequestdefaultstep)
  - [AuthorizeDefaultStep](#authorizedefaultstep)
  - [TokenRequestDefaultStep](#tokenrequestdefaultstep)
  - [NonceRequestDefaultStep](#noncerequestdefaultstep)
  - [CredentialRequestDefaultStep](#credentialrequestdefaultstep)
- [Presentation Flow Steps](#presentation-flow-steps)
  - [FetchMetadataVpDefaultStep](#fetchmetadatavpdefaultstep)
  - [AuthorizationRequestDefaultStep](#authorizationrequestdefaultstep)
  - [RedirectUriDefaultStep](#redirecturidefaultstep)
- [Shared Types](#shared-types)
  - [KeyPair](#keypair-srctypeskey-pairts)
  - [AttestationResponse](#attestationresponse-srctypesattestation-responsets)
  - [CredentialWithKey](#credentialwithkey-srctypescredentialts)
  - [ItWalletCredentialVerifierMetadata](#itwalletcredentialverifiermetadata-pagopaiio-wallet-oid-federation)
- [Common Response Pattern](#common-response-pattern)

---

# Issuance Flow Steps

## FetchMetadataDefaultStep

**Purpose**: Fetches issuer metadata from the well-known endpoint (OpenID4VCI or OpenID Federation).

**Input** (`FetchMetadataOptions`):
```typescript
{
  baseUrl: string;  // Issuer Base URL
}
```

**Output** (`FetchMetadataStepResponse`):
```typescript
{
  success: boolean;
  error?: Error;
  durationMs?: number;
  response?: {
    discoveredVia?: "federation" | "oid4vci";  // Discovery method used
    entityStatementClaims?: {                   // Parsed claims from entity statement JWT (shape varies by issuer)
      iss?: string;                             //   Issuer identifier
      sub?: string;                             //   Subject (same as iss for self-signed)
      credential_issuer?: string;               //   Credential Issuer URL
      authorization_servers?: string[];         //   Authorization server URLs
      credential_configurations_supported?: Record<string, unknown>;  // Supported credential types
      jwks?: { keys: unknown[] };               //   Issuer public keys
      [key: string]: unknown;                   //   Any additional issuer-specific claims
    };
    status: number;                             // HTTP status code (typically 200)
  }
}
```

**Example Response**:
```json
{
  "success": true,
  "durationMs": 245,
  "response": {
    "discoveredVia": "oid4vci",
    "status": 200,
    "entityStatementClaims": {
      "iss": "https://issuer.example.com",
      "sub": "https://issuer.example.com",
      "credential_issuer": "https://issuer.example.com",
      "authorization_servers": ["https://issuer.example.com"],
      "jwks": { ... }
    }
  }
}
```

**Common Assertions**:
- `response.success === true`
- `response.response?.status === 200`
- `response.response?.entityStatementClaims` contains expected issuer metadata
- `response.response?.discoveredVia` matches expected discovery method

---

## PushedAuthorizationRequestDefaultStep

**Purpose**: Sends a Pushed Authorization Request (PAR) to the issuer's PAR endpoint to obtain 
a request URI.

**Input** (`PushedAuthorizationRequestStepOptions`):
```typescript
{
  baseUrl: string;                    // Issuer Base URL
  clientId: string;                   // OAuth2 Client ID (wallet kid)
  credentialConfigurationIds: string[];  // Credential types to request
  pushedAuthorizationRequestEndpoint: string;  // PAR endpoint URL
  walletAttestation: {                // Wallet authentication (AttestationResponse without "created")
    attestation: string;              //   Compact JWT of the Wallet Attestation
    providerKey: KeyPair;             //   Wallet Provider key pair (EC P-256, JWK format)
    unitKey: KeyPair;                 //   Wallet Unit key pair (EC P-256, JWK format) — used to sign PAR
  };
  popAttestation: string;             // DPoP JWT for client authentication
  codeVerifier?: string;              // PKCE code verifier (optional — auto-generated if omitted)
  createParOverrides?: Partial<{      // Override specific PAR fields (CreatePushedAuthorizationRequestOptions)
    audience: string;                 //   Credential Issuer identifier (aud claim in JAR)
    authorization_details?: Array<{   //   Credential authorization details
      type: "openid_credential";
      credential_configuration_id: string;
    }>;
    clientId: string;                 //   OAuth2 client_id (thumbprint of wallet unit key)
    redirectUri: string;              //   Redirect URI for the authorization response
    responseMode: string;             //   Response mode (e.g. "query")
    scope?: string;                   //   OAuth2 scope
    state?: string;                   //   State parameter (auto-generated if omitted)
    jti?: string;                     //   JWT ID (auto-generated if omitted)
    pkceCodeVerifier?: string;        //   PKCE code verifier (auto-generated if omitted)
    callbacks: {                      //   Crypto callbacks (generateRandom, hash, signJwt)
      generateRandom: Function;
      hash: Function;
      signJwt: Function;
    };
    // … additional fields documented in @pagopa/io-wallet-oauth2
  }>;
}
```

**Output** (`PushedAuthorizationRequestResponse`):
```typescript
{
  success: boolean;
  error?: Error;
  durationMs?: number;
  response?: {
    request_uri: string;    // Request URI to use in the authorization redirect
    expires_in: number;     // Seconds until the request_uri expires (e.g. 600)
    codeVerifier: string;   // PKCE code verifier (auto-generated or from input) — pass to AuthorizeStep / TokenRequestStep
  }
}
```

**Example Response**:
```json
{
  "success": true,
  "durationMs": 312,
  "response": {
    "request_uri": "urn:example:issuer:request_object:1234567890",
    "expires_in": 600,
    "codeVerifier": "E9Mrozoa2owszxWeEMsudkMjXXVfqaexRKjcWB0nJc"
  }
}
```

**Common Assertions**:
- `response.success === true`
- `response.response?.request_uri` is a valid string (not empty)
- `response.response?.expires_in` is a positive number
- `response.response?.codeVerifier` is present and non-empty

**Note**: Use `createParOverrides` to test negative cases (e.g., wrong credential type, malformed parameters).

---

## AuthorizeDefaultStep

**Purpose**: Performs the authorization step in the issuance flow. It fetches the request object
JWT from the issuer's authorization endpoint, parses it (including the DCQL credential query),
builds a VP token from the wallet's credentials, creates the encrypted JARM authorization response,
and returns the authorization code.

> **Note**: This step internally constructs and sends the authorization response to the issuer's
> `response_uri` (JARM-encrypted). The `authorizeResponse.code` in the output is the authorization
> code the issuer echoes back after validating the VP presentation.

**Input** (`AuthorizeStepOptions`):
```typescript
{
  authorizationEndpoint: string;    // Issuer authorization endpoint
  baseUrl: string;                  // Issuer Base URL
  clientId: string;                 // OAuth2 Client ID (wallet kid)
  credentials: Array<{             // Issued credentials available for VP token (CredentialWithKey[])
    credential: string;            //   Raw compact credential (SD-JWT or mDOC)
    dpopJwk: {                     //   DPoP public key bound to this credential (JWK)
      kid: string;
      kty: "EC" | "RSA";
      // … standard JWK fields (crv, x, y, d, n, e, …)
    };
    id: string;                    //   Credential identifier (matches DCQL query key, e.g. "PID_1")
    typ: "dc+sd-jwt" | "mso_mdoc";
  }>;
  requestUri?: string;             // Request URI from PAR step
  rpMetadata: {                    // Relying Party metadata (ItWalletCredentialVerifierMetadata)
    application_type: "web";
    authorization_encrypted_response_alg: string;  // e.g. "ECDH-ES"
    authorization_encrypted_response_enc: string;  // e.g. "A256GCM"
    authorization_signed_response_alg: string;     // e.g. "ES256"
    client_id: string;             //   RP identifier URL
    client_name: string;
    jwks: { keys: object[] };      //   RP public keys
    request_uris: string[];
    response_uris: string[];
    vp_formats: Record<string, {   //   Supported VP formats and algorithms
      alg?: string[];
      "sd-jwt_alg_values"?: string[];
    }>;
    // … additional fields from @pagopa/io-wallet-oid-federation
  };
  walletAttestation: {             // Wallet authentication (AttestationResponse without "created")
    attestation: string;           //   Compact JWT of the Wallet Attestation
    providerKey: KeyPair;          //   Wallet Provider key pair (EC P-256, JWK format)
    unitKey: KeyPair;              //   Wallet Unit key pair (EC P-256, JWK format)
  };
}
```

**Output** (`AuthorizeStepResponse`):
```typescript
{
  success: boolean;
  error?: Error;
  durationMs?: number;
  response?: {
    // AuthorizationResponse — the redirect-based code response from the issuer
    authorizeResponse?: {
      code: string;   // OAuth2 authorization code to exchange for a token
      iss: string;    // Issuer identifier (echoed from the request)
      state: string;  // State parameter (must match what was sent in PAR)
    };
    iss: string;               // Issuer Base URL (from step options)
    requestObject?: {          // Parsed request object claims (Openid4vpAuthorizationRequestPayload)
      client_id: string;
      nonce: string;
      response_mode: "direct_post.jwt";
      response_type: "vp_token";
      response_uri: string;   // Where to POST the authorization response
      state: string;
      dcql_query: Record<string, unknown>;  // DCQL credential query
      scope?: string;
      iss?: string;           // Standard JWT iss claim
      exp?: number;           // JWT expiration (Unix seconds)
      iat?: number;
      // … additional JWT claims
    };
    requestObjectJwt: string;  // Raw request object JWT string
  }
}
```

**Example Response** (Issuance):
```json
{
  "success": true,
  "durationMs": 450,
  "response": {
    "iss": "https://issuer.example.com",
    "requestObjectJwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
    "requestObject": {
      "client_id": "wallet-client-id",
      "response_type": "code",
      "redirect_uri": "https://client.example.org/cb",
      "scope": "openid",
      "state": "random-state",
      "code_challenge": "E9Mrozoa2owszxWeEMsudkMjXXVfqaexRKjcWB0nJc",
      "code_challenge_method": "S256"
    },
    "authorizeResponse": {
      "code": "authorization-code-12345",
      "iss": "https://issuer.example.com",
      "state": "random-state"
    }
  }
}
```

**Common Assertions**:
- `response.success === true`
- `response.response?.authorizeResponse?.code` is present
- `response.response?.iss` matches expected issuer
- `response.response?.requestObject.client_id` is valid

---

## TokenRequestDefaultStep

**Purpose**: Requests an access token from the issuer's token endpoint using the authorization code.

**Input** (`TokenRequestStepOptions`):
```typescript
{
  accessTokenEndpoint: string;       // Token endpoint URL
  accessTokenRequest: {              // Token request body (AccessTokenRequest from @openid4vc/oauth2)
    grant_type:                      //   OAuth2 grant type
      | "authorization_code"
      | "urn:ietf:params:oauth:grant-type:pre-authorized_code"
      | "refresh_token"
      | string;
    code?: string;                   //   Authorization code (for authorization_code grant)
    redirect_uri?: string;           //   Must match the redirect_uri from the PAR request
    code_verifier?: string;          //   PKCE verifier (required when code_challenge was sent)
    "pre-authorized_code"?: string;  //   Pre-authorized code (for pre-auth grant)
    refresh_token?: string;          //   Refresh token (for refresh_token grant)
    tx_code?: string;                //   Transaction code (pre-auth flows)
  };
  popAttestation: string;            // DPoP JWT for client authentication
  walletAttestation: {               // Wallet authentication (AttestationResponse without "created")
    attestation: string;             //   Compact JWT of the Wallet Attestation
    providerKey: KeyPair;            //   Wallet Provider key pair (EC P-256, JWK format)
    unitKey: KeyPair;                //   Wallet Unit key pair (EC P-256, JWK format)
  };
}
```

**Output** (`TokenRequestResponse`):
```typescript
{
  success: boolean;
  error?: Error;
  durationMs?: number;
  response?: {
    // AccessTokenResponse fields
    access_token: string;                   // The access token JWT
    token_type: "Bearer" | "DPoP";          // Token type
    expires_in?: number;                    // Token lifetime in seconds
    refresh_token?: string;                 // Optional refresh token
    authorization_details?: Array<{         // Credential-specific authorization details
      type: "openid_credential";
      credential_configuration_id?: string;
      credential_identifiers?: string[];
    }>;
    // Step-added field
    dPoPKey: {                              // Ephemeral DPoP key pair — MUST be passed to CredentialRequestStep
      publicKey:  { kid: string; kty: "EC" | "RSA"; /* crv, x, y, … */ };
      privateKey: { kid: string; kty: "EC" | "RSA"; /* crv, x, y, d, … */ };
    };
  }
}
```

**Example Response**:
```json
{
  "success": true,
  "durationMs": 187,
  "response": {
    "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9...",
    "token_type": "DPoP",
    "expires_in": 3600,
    "authorization_details": [
      {
        "type": "openid_credential",
        "credential_configuration_id": "dc_sd_jwt_PersonIdentificationData",
        "credential_identifiers": ["PID_1"]
      }
    ],
    "dPoPKey": {
      "publicKey": { "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "kid": "..." },
      "privateKey": { "kty": "EC", "crv": "P-256", "d": "...", "x": "...", "y": "..." }
    }
  }
}
```

**Common Assertions**:
- `response.success === true`
- `response.response?.access_token` is a non-empty string
- `response.response?.token_type` is `"Bearer"` or `"DPoP"`
- `response.response?.dPoPKey` is present (pass it to `CredentialRequestStepOptions.dPoPKey`)

---

## NonceRequestDefaultStep

**Purpose**: Requests a fresh nonce from the issuer's nonce endpoint (used for credential requests).

**Input** (`NonceRequestStepOptions`):
```typescript
{
  nonceEndpoint: string;  // Nonce endpoint URL
}
```

**Output** (`NonceRequestResponse`):
```typescript
{
  success: boolean;
  error?: Error;
  durationMs?: number;
  response?: {
    attempts: number;                              // Number of HTTP attempts before success
    cacheControl: null | string;                   // Cache-Control header value
    contentType: null | string;                    // Content-Type header value
    nonce: {                                       // The nonce payload from the issuer (NonceResponsePayload)
      nonce: string;                               //   Opaque nonce value — pass to CredentialRequestStep
      nonce_expires_in?: number;                   //   Nonce lifetime in seconds (e.g. 86400)
      [key: string]: unknown;                      //   Additional issuer-specific fields
    };
  }
}
```

**Example Response**:
```json
{
  "success": true,
  "durationMs": 134,
  "response": {
    "attempts": 1,
    "cacheControl": "no-store, max-age=0",
    "contentType": "application/json",
    "nonce": {
      "nonce": "fUHyO2Dw3L-4-t88bF4b5Q",
      "nonce_expires_in": 86400
    }
  }
}
```

**Common Assertions**:
- `response.success === true`
- `response.response?.nonce.nonce` is a non-empty string
- `response.response?.contentType` contains "application/json"
- `response.response?.cacheControl` reflects no-cache policy

---

## CredentialRequestDefaultStep

**Purpose**: Requests the actual credential(s) from the issuer's credential endpoint.

**Input** (`CredentialRequestStepOptions`):
```typescript
{
  accessToken: string;                  // Access token from token step
  baseUrl: string;                      // Issuer Base URL
  clientId: string;                     // OAuth2 Client ID
  credentialIdentifier: string;         // Credential configuration ID (e.g. "dc_sd_jwt_PersonIdentificationData")
  credentialRequestEndpoint: string;    // Credential endpoint URL
  dPoPKey: {                            // Ephemeral DPoP key from TokenRequestStep — MUST be the same key (KeyPair)
    publicKey:  { kid: string; kty: "EC" | "RSA"; /* crv, x, y, … */ };
    privateKey: { kid: string; kty: "EC" | "RSA"; /* crv, x, y, d, … */ };
  };
  nonce: string;                        // Nonce value from NonceRequestStep (response.nonce.nonce)
  walletAttestation: {                  // Wallet authentication (AttestationResponse without "created")
    attestation: string;                //   Compact JWT of the Wallet Attestation
    providerKey: KeyPair;               //   Wallet Provider key pair (EC P-256, JWK format)
    unitKey: KeyPair;                   //   Wallet Unit key pair (EC P-256, JWK format)
  };
  createCredentialRequestOverrides?: Partial<{  // Override specific credential request fields (BaseCredentialRequestOptions)
    clientId: string;                   //   OAuth2 client_id
    credential_identifier: string;      //   Credential identifier
    issuerIdentifier: string;           //   Issuer base URL
    nonce: string;                      //   Nonce value
    // … additional version-specific fields (proof, format, etc.)
  }>;
  dPoPOverride?: string;                // Override DPoP JWT (for negative/error testing)
}
```

**Output** (`CredentialRequestResponse`):
```typescript
{
  success: boolean;
  error?: Error;
  durationMs?: number;
  response?: {
    // ImmediateCredentialResponse fields
    credentials: [                         // Non-empty array (at least one element guaranteed)
      { credential: string },              // credential: the issued token (SD-JWT, mDOC, …)
      ...{ credential: string }[]
    ];
    notification_id?: string;             // Optional notification ID for deferred status
    // Step-added field
    credentialKeyPair: {                   // Key pair generated for this credential's proof (KeyPair)
      publicKey:  { kid: string; kty: "EC" | "RSA"; /* crv, x, y, … */ };
      privateKey: { kid: string; kty: "EC" | "RSA"; /* crv, x, y, d, … */ };
    };
  }
}
```

**Example Response** (SD-JWT):
```json
{
  "success": true,
  "durationMs": 256,
  "response": {
    "credentials": [
      {
        "credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCIsImtpZCI6ImtleTox..."
      }
    ],
    "credentialKeyPair": {
      "publicKey": { "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "kid": "..." },
      "privateKey": { "kty": "EC", "crv": "P-256", "d": "...", "x": "...", "y": "..." }
    }
  }
}
```

**Common Assertions**:
- `response.success === true`
- `response.response?.credentials` is a non-empty array
- `response.response?.credentials[0].credential` is a non-empty string (JWT or mDOC)
- `response.response?.credentialKeyPair` contains public and private key components

**Note**: Use `createCredentialRequestOverrides` to test negative cases (e.g., wrong proofType, invalid nonce).

---

# Presentation Flow Steps

## Quick Reference

| What you want to assert | Full path |
|-------------------------|-----------|
| Flow succeeded | `result.authorizationRequestResult.success` |
| Request nonce | `result.authorizationRequestResult.response?.requestObject.nonce` |
| Request state | `result.authorizationRequestResult.response?.requestObject.state` |
| Response mode | `result.authorizationRequestResult.response?.requestObject.response_mode` |
| JWT header type | `result.authorizationRequestResult.response?.authorizationRequestHeader.typ` |
| Trust chain (V1.0) | `result.authorizationRequestResult.response?.authorizationRequestHeader.trust_chain` |
| JARM JWE | `result.authorizationRequestResult.response?.authorizationResponse.jarm.responseJwe` |
| VP token map | `result.authorizationRequestResult.response?.authorizationResponse.authorizationResponsePayload.vp_token` |
| Verifier redirect URI | `result.redirectUriResult.response?.redirectUri` |
| Response code | `result.redirectUriResult.response?.responseCode` |
| RP entity claims | `result.fetchMetadataResult.response?.entityStatementClaims` |
| HTTP status | `result.fetchMetadataResult.response?.status` |

---

## FetchMetadataVpDefaultStep

**Purpose**: Fetches Relying Party (Verifier) metadata from the `.well-known/openid-federation` endpoint.

**Input** (`FetchMetadataVpOptions`):
```typescript
{
  baseUrl: string;  // Verifier Base URL
}
```

**Output** (`FetchMetadataVpStepResponse`):
```typescript
{
  success: boolean;
  error?: Error;
  durationMs?: number;
  response?: {
    status: number;                  // HTTP status code (typically 200)
    entityStatementClaims?: {        // Parsed claims from entity statement JWT (shape varies by RP)
      iss?: string;                  //   RP identifier
      sub?: string;                  //   Subject (same as iss for self-signed)
      metadata?: {
        openid_credential_verifier?: {  // RP's OpenID4VP verifier metadata
          client_id?: string;
          redirect_uris?: string[];
          response_types_supported?: string[];
          vp_formats_supported?: Record<string, unknown>;
          [key: string]: unknown;
        };
        [key: string]: unknown;
      };
      jwks?: { keys: unknown[] };    //   RP public keys
      [key: string]: unknown;        //   Any additional claims
    };
    headers?: Headers;               // Response headers (Fetch API Headers object — use .get() to read)
  }
}
```

**Example Response**:
```json
{
  "success": true,
  "durationMs": 198,
  "response": {
    "status": 200,
    "entityStatementClaims": {
      "iss": "https://verifier.example.com",
      "sub": "https://verifier.example.com",
      "metadata": {
        "openid_credential_verifier": {
          "contacts": ["info@verifier.example.com"],
          "grant_types": ["authorization_code"],
          "redirect_uris": ["https://verifier.example.com/callback"]
        }
      },
      "jwks": { ... }
    },
    "headers": { ... }
  }
}
```

**Common Assertions**:
- `response.success === true`
- `response.response?.status === 200`
- `response.response?.entityStatementClaims` contains expected verifier metadata
- `response.response?.entityStatementClaims.metadata.openid_credential_verifier` is present
- `headers` is a Fetch API `Headers` object — use `.get()` to read values:
  ```typescript
  // Correct
  fetchMetadataResult.response?.headers?.get("content-type");
  // Wrong — always returns undefined
  fetchMetadataResult.response?.headers?.["content-type"];
  ```

---

## AuthorizationRequestDefaultStep

**Purpose**: Fetches the authorization request from the verifier, parses it, builds the VP token 
from available credentials, and creates the authorization response.

**Input** (`AuthorizationRequestOptions`):
```typescript
{
  credentials: Array<{             // Credentials to use for VP token (CredentialWithKey[])
    credential: string;            //   Raw compact credential (SD-JWT or mDOC)
    dpopJwk: {                     //   DPoP public key bound to this credential (JWK)
      kid: string;
      kty: "EC" | "RSA";
      // … standard JWK fields
    };
    id: string;                    //   Credential identifier (matches DCQL query key, e.g. "PID_1")
    typ: "dc+sd-jwt" | "mso_mdoc";
  }>;
  verifierMetadata: {              // Verifier metadata (ItWalletCredentialVerifierMetadata)
    application_type: "web";
    authorization_encrypted_response_alg: string;  // e.g. "ECDH-ES"
    authorization_encrypted_response_enc: string;  // e.g. "A256GCM"
    authorization_signed_response_alg: string;     // e.g. "ES256"
    client_id: string;             //   RP identifier URL
    client_name: string;
    jwks: { keys: object[] };      //   RP public keys (used to encrypt JARM response)
    request_uris: string[];
    response_uris: string[];
    vp_formats: Record<string, {   //   Supported VP formats and algorithms
      alg?: string[];
      "sd-jwt_alg_values"?: string[];
    }>;
    // … additional fields from @pagopa/io-wallet-oid-federation
  };
  walletAttestation: {             // Full wallet authentication (AttestationResponse)
    attestation: string;           //   Compact JWT of the Wallet Attestation
    created: boolean;              //   Whether the attestation was freshly created (true) or cached (false)
    providerKey: KeyPair;          //   Wallet Provider key pair (EC P-256, JWK format)
    unitKey: KeyPair;              //   Wallet Unit key pair (EC P-256, JWK format)
  };
}
```

**Output** (`AuthorizationRequestStepResponse`):
```typescript
{
  success: boolean;
  error?: Error;
  durationMs?: number;
  response?: {
    // ParsedQrCode — decoded from the authorization request URL
    parsedQrCode: {
      clientId: string;                    // client_id from the authorization URL
      requestUri?: string;                 // request_uri from the authorization URL
      requestUriMethod?: "get" | "post";   // HTTP method used to fetch the request object
    };

    // Openid4vpAuthorizationRequestHeader — JWT header of the request object (version-dependent)
    // V1.0
    authorizationRequestHeader: {
      alg: string;
      kid: string;
      typ: "oauth-authz-req+jwt";
      trust_chain: [string, ...string[]]; // required, at least one element
    };
    // V1.3
    authorizationRequestHeader: {
      alg: string;
      kid: string;
      typ: "oauth-authz-req+jwt";
      trust_chain?: [string, ...string[]]; // optional
      x5c: string[];                       // required
    };

    // Openid4vpAuthorizationRequestPayload — decoded request object claims
    requestObject: {
      client_id: string;
      nonce: string;
      response_mode: "direct_post.jwt"; // literal — use toBe("direct_post.jwt") in assertions
      response_type: "vp_token";        // literal — use toBe("vp_token") in assertions
      response_uri: string;             // Where to POST the authorization response
      state: string;                    // required (always present per schema)
      exp: number;                      // JWT expiration timestamp (Unix seconds) — asserted in RPR094
      iss?: string;                     // Issuer identifier (standard JWT claim)
      dcql_query?: object;              // DCQL credential request query
      // … other OpenID4VP request object claims
    };

    responseUri: string;         // Convenience copy of requestObject.response_uri

    // CreateAuthorizationResponseResult — the encrypted JARM response to send back
    authorizationResponse: {
      authorizationResponsePayload: {
        state: string;
        vp_token: Record<string, string | string[]>; // keyed by credential ID from DCQL query (e.g. { "PID_1": "eyJ..." })
      };
      // jarm is always present — the step throws "JARM response is missing" if absent
      jarm: {
        encryptionJwk: object;   // JWK used to encrypt the response
        responseJwe: string;     // Compact JWE to POST to responseUri
      };
    };
  }
}
```

**Example Response**:
```json
{
  "success": true,
  "durationMs": 523,
  "response": {
    "parsedQrCode": {
      "clientId": "https://verifier.example.com",
      "requestUri": "https://verifier.example.com/request/abc123",
      "requestUriMethod": "get"
    },
    "authorizationRequestHeader": {
      "alg": "ES256",
      "typ": "oauth-authz-req+jwt",
      "kid": "verifier_key_1",
      "trust_chain": ["eyJ..."]
    },
    "requestObject": {
      "client_id": "https://verifier.example.com",
      "response_type": "vp_token",
      "response_mode": "direct_post.jwt",
      "nonce": "n-0S6_WzA2Mj",
      "state": "xyz",
      "response_uri": "https://verifier.example.com/response",
      "dcql_query": {}
    },
    "responseUri": "https://verifier.example.com/response",
    "authorizationResponse": {
      "authorizationResponsePayload": {
        "vp_token": { "PID_1": "eyJ..." },
        "state": "xyz"
      },
      "jarm": {
        "encryptionJwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "kid": "..." },
        "responseJwe": "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSJ9..."
      }
    }
  }
}
```

**Common Assertions**:
- `response.success === true`
- `response.response?.authorizationResponse.jarm.responseJwe` is present (`jarm` is always present — no `?.` needed)
- `response.response?.requestObject.nonce` is non-empty
- `response.response?.responseUri` matches expected verifier response endpoint

---

## RedirectUriDefaultStep

**Purpose**: Sends the authorization response to the verifier's response URI and extracts the final 
redirect URI with response code.

**Input** (`RedirectUriOptions`):
```typescript
{
  authorizationResponse: {         // Authorization response built in the previous step (CreateAuthorizationResponseResult)
    authorizationResponsePayload: {
      state: string;               //   Echoes the state from the request object
      vp_token: Record<string, string | string[]>;  // VP token map (credential ID → compact token)
    };
    jarm: {
      encryptionJwk: object;       //   JWK used to encrypt the JARM response
      responseJwe: string;         //   Compact JWE to POST to responseUri
    };
  };
  responseUri: string;             // Response URI endpoint (= authorizationRequestResult.response.responseUri)
}
```

**Output** (`RedirectUriStepResponse`):
```typescript
{
  success: boolean;
  error?: Error;
  durationMs?: number;
  // The two fields are always co-present: if redirectUri is defined, responseCode is also defined, and vice versa.
  response?:
    | { redirectUri: undefined; responseCode: undefined }  // presentation declined
    | { redirectUri: URL;       responseCode: string    }; // presentation accepted
}
```

**Example Response** (Success):
```json
{
  "success": true,
  "durationMs": 287,
  "response": {
    "redirectUri": "https://client.example.org/cb?response_code=eye3rcvAeq0aL&state=xyz",
    "responseCode": "eye3rcvAeq0aL"
  }
}
```

**Example Response** (Declined):
```json
{
  "success": true,
  "durationMs": 156,
  "response": {
    "redirectUri": undefined,
    "responseCode": undefined
  }
}
```

**Common Assertions**:
- `response.success === true`
- If presentation was accepted:
  - `response.response?.redirectUri` is a valid URL
  - `response.response?.responseCode` is a non-empty string
- If presentation was declined:
  - `response.response?.redirectUri === undefined`
  - `response.response?.responseCode === undefined`

---

# Shared Types

These types appear across multiple steps. They are defined in `src/types/` (internal) or in
`@pagopa/io-wallet-oauth2` / `@pagopa/io-wallet-oid-federation` (external packages).

## `KeyPair` (`src/types/key-pair.ts`)

An EC (or RSA) key pair in JWK format with a mandatory `kid` field.

```typescript
interface KeyPair {
  publicKey:  KeyPairJwk;  // { kid, kty, crv?, x?, y?, n?, e?, alg?, use?, … }
  privateKey: KeyPairJwk;  // same shape plus private components (d, p, q, …)
}

// KeyPairJwk = standard JWK (from @pagopa/io-wallet-oauth2 Jwk) & { kid: string } & { kty: "EC" | "RSA" }
```

In the conformance tests the keys always use curve **P-256** (`"crv": "P-256"`, `"kty": "EC"`).

## `AttestationResponse` (`src/types/attestation-response.ts`)

```typescript
interface AttestationResponse {
  attestation: string;   // Compact JWT (Wallet Attestation signed by the Wallet Provider)
  created: boolean;      // true = freshly issued; false = returned from cache
  providerKey: KeyPair;  // Wallet Provider key pair (signs the attestation)
  unitKey: KeyPair;      // Wallet Unit key pair (used by the wallet to sign PAR / credential proof)
}
```

Most step inputs accept `Omit<AttestationResponse, "created">`, i.e. every field except `created`.
The `AuthorizationRequestDefaultStep` (presentation) uses the full `AttestationResponse`.

## `CredentialWithKey` (`src/types/credential.ts`)

```typescript
interface CredentialWithKey {
  credential: string;              // Raw compact credential (SD-JWT VC or mDOC)
  dpopJwk: {                       // DPoP public key bound to this credential (KeyPairJwk)
    kid: string;
    kty: "EC" | "RSA";
    // … standard JWK fields (crv, x, y, …)
  };
  id: string;                      // Credential identifier (matches the DCQL query key, e.g. "PID_1")
  typ: "dc+sd-jwt" | "mso_mdoc";  // Credential format
}
```

This type is produced by the issuance orchestrator and consumed by the presentation orchestrator.

## `ItWalletCredentialVerifierMetadata` (`@pagopa/io-wallet-oid-federation`)

The parsed metadata of the Relying Party (Verifier) extracted from its Entity Configuration.
Key fields:

```typescript
{
  application_type: "web";
  authorization_encrypted_response_alg: string;  // JWE alg, e.g. "ECDH-ES"
  authorization_encrypted_response_enc: string;  // JWE enc, e.g. "A256GCM"
  authorization_signed_response_alg: string;     // JWS alg for signed response, e.g. "ES256"
  client_id: string;                             // RP identifier URL
  client_name: string;
  jwks: { keys: object[] };                      // RP JWK Set (used to encrypt the JARM response)
  request_uris: string[];
  response_uris: string[];
  vp_formats: Record<string, {
    alg?: string[];
    "sd-jwt_alg_values"?: string[];
  }>;
  // Additional optional fields per the IT-Wallet RP metadata spec
}
```

---

# Common Response Pattern

All step responses follow this base pattern:

```typescript
type StepResponse = {
  success: boolean;              // Whether the step execution succeeded
  error?: Error;                 // Error object if success === false
  durationMs?: number;           // Execution time in milliseconds
  response?: T;                  // Step-specific response object (T = concrete step type)
};
```

## Usage in Tests

When running orchestrators, you access step outputs via the orchestrator results:

```typescript
// Issuance flow
const {
  fetchMetadataResponse,
  pushedAuthorizationRequestResponse,   // note: full name, not pushedAuthorizationResponse
  authorizeResponse,
  tokenResponse,
  nonceResponse,
  credentialResponse
} = await orchestrator.issuance();

// Check individual step success
if (!tokenResponse.success) {
  expect(tokenResponse.error?.message).toBeDefined();
}

// Extract response data
const { access_token, dPoPKey } = tokenResponse.response || {};

// Presentation flow — field names use the "Result" suffix
const {
  fetchMetadataResult,
  authorizationRequestResult,
  redirectUriResult,
} = await orchestrator.presentation();
```

## Error Handling

When a step fails (`success === false`):
- The `error` field contains the thrown Error object
- The `response` field may be undefined or partially populated
- Subsequent steps might fail due to missing dependencies
- Tests should check `response.success` before asserting on `response.response`

## Step Overrides

To override step behavior in tests, extend the base class and override the `run()` method:

```typescript
import { TokenRequestDefaultStep } from "@/step/issuance";

export class CustomTokenStep extends TokenRequestDefaultStep {
  override async run(options: TokenRequestStepOptions) {
    // Modify options, call super, or implement custom logic
    const result = await super.run(options);
    
    // Post-process the response
    if (result.response) {
      result.response.access_token = "malformed-token";  // For negative tests
    }
    return result;
  }
}
```

---

## Further Reading

- [ISSUANCE-TESTING-GUIDE.md](./ISSUANCE-TESTING-GUIDE.md) — Step-by-step guide for writing issuance tests
- [TEST-CONFIGURATION-GUIDE.md](./TEST-CONFIGURATION-GUIDE.md) — Configuration reference
- `src/orchestrator/` — Orchestrator implementations
- `src/step/` — All step implementations
