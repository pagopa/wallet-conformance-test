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
    entityStatementClaims?: any;                // Parsed claims from entity statement JWT
    status: number;                              // HTTP status code (typically 200)
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
  baseUrl: string;                                    // Issuer Base URL
  clientId: string;                                   // OAuth2 Client ID (wallet kid)
  credentialConfigurationIds: string[];               // Credential types to request
  pushedAuthorizationRequestEndpoint: string;         // PAR endpoint URL
  walletAttestation: Omit<AttestationResponse, "created">;  // Wallet authentication
  popAttestation: string;                             // DPoP JWT for client authentication
  codeVerifier?: string;                              // PKCE code verifier (optional)
  createParOverrides?: Partial<CreatePushedAuthorizationRequestOptions>;  // Override specific PAR fields
}
```

**Output** (`PushedAuthorizationRequestResponse`):
```typescript
{
  success: boolean;
  error?: Error;
  durationMs?: number;
  response?: PushedAuthorizationResponse & {
    request_uri: string;                    // Request URI returned by issuer
    expires_in?: number;                    // Request URI expiration time in seconds
    codeVerifier: string;                   // PKCE code verifier used
    // ... other OpenID4VCI PAR response fields
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

**Purpose**: Performs the authorization redirect to the issuer's authorization endpoint and returns
the authorization code.

**Input** (`AuthorizeStepOptions`):
```typescript
{
  authorizationEndpoint: string;           // Issuer authorization endpoint
  baseUrl: string;                         // Issuer Base URL
  clientId: string;                        // OAuth2 Client ID (wallet kid)
  credentials: CredentialWithKey[];        // Issued credentials to use in VP token
  requestUri?: string;                     // Request URI from PAR step
  rpMetadata: ItWalletCredentialVerifierMetadata;  // RP metadata
  walletAttestation: Omit<AttestationResponse, "created">;  // Wallet authentication
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
    iss: string;                                              // Issuer Base URL (from step options)
    requestObject?: Openid4vpAuthorizationRequestPayload;     // Parsed request object claims
    requestObjectJwt: string;                                 // Raw request object JWT string
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
  accessTokenEndpoint: string;                  // Token endpoint URL
  accessTokenRequest: AccessTokenRequest;       // Token request body (with auth code, etc.)
  popAttestation: string;                       // DPoP JWT for client authentication
  walletAttestation: Omit<AttestationResponse, "created">;  // Wallet authentication
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
    dPoPKey: KeyPair;                       // Ephemeral DPoP key pair — MUST be passed to CredentialRequestStep
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
    nonce: NonceResponsePayload;                   // The nonce payload from the issuer
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
  accessToken: string;                                        // Access token from token step
  baseUrl: string;                                            // Issuer Base URL
  clientId: string;                                           // OAuth2 Client ID
  credentialIdentifier: string;                               // Credential configuration ID
  credentialRequestEndpoint: string;                          // Credential endpoint URL
  dPoPKey: KeyPair;                                           // Ephemeral DPoP key from TokenRequestStep — MUST be the same key
  nonce: string;                                              // Nonce from nonce request
  walletAttestation: Omit<AttestationResponse, "created">;    // Wallet authentication
  createCredentialRequestOverrides?: Partial<BaseCredentialRequestOptions>;  // Override specific fields
  dPoPOverride?: string;                                      // Override DPoP JWT (for error testing)
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
    credentialKeyPair: KeyPair;            // Key pair generated for this credential's proof
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
    status: number;                 // HTTP status code (typically 200)
    entityStatementClaims?: any;    // Parsed claims from entity statement JWT
    headers?: Headers;              // Response headers
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
  credentials: CredentialWithKey[];                               // Credentials to use for VP token
  verifierMetadata: ItWalletCredentialVerifierMetadata;          // Verifier metadata
  walletAttestation: AttestationResponse;                        // Wallet authentication
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
  authorizationResponse: CreateAuthorizationResponseResult;  // Authorization response from previous step
  responseUri: string;                                       // Response URI endpoint
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
