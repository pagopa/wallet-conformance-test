# Test Execution Reference

### Issuance Flow Tests

The issuance flow validates credential issuance conformance according to [Credential Issuer Test Matrix](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-credential-issuer.html).

#### Federation Metadata Tests

- **CI_001**: Calls the `.well-known/openid-federation` endpoint of the Credential Issuer and verifies that the request succeeds and the response body contains parseable Entity Configuration claims (`entityStatementClaims`). Confirms that the federation endpoint is reachable and returns valid data.

- **CI_002**: Verifies that the `.well-known/openid-federation` endpoint returns a response with `Content-Type: application/entity-statement+jwt`. Validated indirectly: the step succeeds only if the JWT is parsed correctly, which requires the server to serve the correct MIME type.

- **CI_003**: Verifies that the Entity Configuration JWT is signed and was discovered through the OpenID Federation path. Checks that the HTTP response status is 200 and that the metadata was obtained via federation (not a fallback), confirming the issuer participates in the trust chain.

- **CI_006**: Parses the Entity Configuration JWT payload and validates the presence and correct type of all six mandatory top-level claims: `iss` (issuer URL), `sub` (subject URL), `iat` (issued-at Unix timestamp), `exp` (expiration Unix timestamp), `jwks` (JSON Web Key Set), and `metadata` (federation metadata object). Uses Zod schema validation.

- **CI_008**: Inspects the `metadata` object inside the Entity Configuration and verifies that it contains three required sub-objects: `federation_entity` (OpenID Federation entity metadata), `oauth_authorization_server` (OAuth 2.0 authorization server metadata including token and PAR endpoints), and `openid_credential_issuer` (credential-specific metadata including credential endpoint and supported types). Fails if any section is absent.

- **CI_009**: Inspects the `metadata` object inside the Entity Configuration and verifies that the `openid_credential_verifier` key is present. This sub-object is required when the Credential Issuer acts as a verifier during user authentication (i.e., when it requests a PID presentation from the Wallet Instance via OpenID4VP). Fails if the key is absent.

#### PAR Request Object Validation Tests

These are negative tests: each sends a deliberately malformed PAR request and verifies that the Credential Issuer rejects it. The shared setup runs the flow up to the PAR step to collect the wallet attestation, authorization server URL, and PAR endpoint needed to craft custom requests.

- **CI_015**: Sends a PAR Request Object JWT signed with a freshly generated key that does not match the key declared in the Wallet Attestation's `cnf.jwk`. Verifies that the issuer rejects the request, confirming that it validates the JWT signature against the key from the attestation rather than accepting any signature.

- **CI_015a**: Sends a PAR Request Object with `alg=ES256` in the JWT header but actually signed with the ES384 algorithm. Verifies that the issuer uses the `alg` header to select the verification algorithm (as required by RFC 9126/9101), rather than inferring the algorithm from the key. If the issuer ignored the header, it might accept the JWT; the test confirms it does not.

- **CI_015b**: Creates a synthetic Wallet Attestation signed by a freshly generated key that was never registered in the Trust Chain. Sends a PAR request with this fake attestation. Verifies that the issuer resolves the attestation's public key from the Trust Chain and rejects an attestation whose key is unknown.

- **CI_015c**: Sends a PAR Request Object where the `kid` header is set to `"wrong-kid-that-does-not-match"` even though the JWT is signed with the correct wallet key. Verifies that the issuer checks the `kid` header value against the key reference in the Wallet Attestation and rejects a mismatched identifier.

- **CI_015d**: Signs a valid PAR Request Object, then decodes the payload, modifies the `aud` claim to `"https://tampered.example.com"`, re-encodes it, and reassembles the token (original signature is now invalid for the modified payload). Verifies that the issuer detects payload tampering through cryptographic signature verification.

- **CI_019**: Sends a PAR Request Object signed with HMAC-SHA256 (`HS256`), a symmetric algorithm. Verifies that the issuer enforces the requirement for asymmetric algorithms only and rejects the request.

- **CI_020**: Sends a PAR request where the `client_id` field in the HTTP POST body is set to `"mallory_client_id_that_does_not_match"` while the JWT payload's `client_id` claim contains the real value. Verifies that the issuer enforces consistency between the POST body parameter and the JWT claim (RFC 9126 §2) and rejects the mismatched request.

- **CI_021**: Sends a PAR Request Object where the `iss` JWT claim is set to `"https://attacker.example.com"` while the actual wallet's `client_id` is different. Verifies that the issuer enforces the requirement that the `iss` claim must exactly equal `client_id`.

- **CI_022**: Sends a PAR Request Object where the `aud` claim is set to `"https://wrong.example.com"` instead of the issuer's own identifier URL. Verifies that the issuer validates the `aud` claim against its own identifier and rejects requests addressed to a different audience.

- **CI_023**: Builds a valid PAR request and injects an additional `request_uri` parameter into the HTTP POST body using a custom fetch interceptor, producing a request that contains both `request` and `request_uri`. Verifies that the issuer enforces RFC 9126 §2.1, which prohibits mixing these two parameters in the same PAR call.

- **CI_024**: Sends a PAR request with the `redirect_uri` parameter absent (set to `undefined`). Verifies that the issuer enforces the presence of this mandatory parameter and returns an error when it is missing.

- **CI_025**: Freezes the system clock 10 minutes in the past before generating the PAR Request Object, causing the JWT's `exp` claim to be already in the past at request time. Verifies that the issuer validates token expiration and rejects an expired Request Object.

- **CI_026**: Advances the system clock 10 minutes into the future before generating the PAR Request Object, producing a JWT with an `iat` claim 10 minutes ahead of the server's current time. Verifies that the issuer rejects tokens with a future `iat` that exceeds the permitted clock-skew tolerance.

- **CI_026a**: Rewinds the system clock 6 minutes before generating the PAR Request Object, producing a JWT with an `iat` that is 6 minutes in the past. Verifies that the issuer rejects stale tokens whose `iat` is beyond the 5-minute clock-skew window.

- **CI_027**: Creates a PAR Request Object with a fixed `jti` value and sends it twice. The first request must succeed (the server caches the `jti`). The second request with the identical `jti` must be rejected. Verifies that the issuer tracks previously seen `jti` values to prevent replay attacks.

- **CI_028a**: Builds a Proof-of-Possession (PoP) JWT signed with a fresh random key instead of the wallet unit key declared in the Wallet Attestation's `cnf.jwk`. Sends a PAR request with this tampered PoP. Verifies that the issuer validates the PoP signature against the `cnf.jwk` embedded in the attestation and rejects a PoP signed by an unregistered key.

- **CI_028b**: Builds a PoP JWT where the `aud` claim is set to `"https://attacker.example.com"` instead of the issuer's own URL. Verifies that the issuer checks the PoP `aud` claim and rejects a PoP addressed to the wrong audience.

- **CI_028c**: Builds a PoP JWT with `iat` 11 minutes in the past and `exp` 10 minutes in the past, making it already expired at request time. Verifies that the issuer validates the PoP expiration time and rejects an expired PoP.

#### Pushed Authorization Request (PAR) Response Tests

These are positive checks run against the response of a successful PAR request.

- **CI_040**: Reads the `expires_in` field in the successful PAR response and asserts that its value is at most 60 seconds. This enforces the requirement that the `request_uri` has a short validity window to limit replay exposure.

- **CI_041**: Reads the `request_uri` value from the PAR response, extracts the random token portion (the segment after the last `:` in the URN), and estimates its bit length (6 bits per character for base64, 4 bits for hex). Asserts that the estimated bit length is at least 128 bits, which is the minimum for cryptographic randomness.

- **CI_042**: Reads the full `request_uri` string from the PAR response and asserts that its total length does not exceed 512 ASCII characters, keeping it embeddable in a QR code or URL parameter.

- **CI_043**: Verifies that the PAR step completed without an error (no `error` field in the response). Confirms that the issuer accepted the well-formed request and returned HTTP 201 with a valid response body.

- **CI_044a**: Reads the `request_uri` field from the PAR response and asserts that it is a defined, non-empty string. This is the one-time URI the wallet will reference in the subsequent authorization request.

- **CI_044b**: Reads the `expires_in` field from the PAR response and asserts that it is a positive number. This value tells the wallet how many seconds the `request_uri` remains valid before it must start a new PAR.

#### Authorization Request Validation Tests

- **CI_047**: Verifies one-time use and time-based expiration of a `request_uri`. First attempts to reuse a `request_uri` that was already consumed in the shared setup step — the issuer must reject it. Then performs a new PAR, waits for the `request_uri` to expire (using the `expires_in` value), and attempts to use the expired URI — the issuer must also reject it.

- **CI_048**: Tests optional duplicate-request tolerance. Performs a new PAR to get a fresh `request_uri`, then sends two authorization requests with the same URI 2 seconds apart (concurrently via `Promise.all`). Asserts that both calls return the same result (both succeed or both fail). This verifies whether the issuer implements a grace period for near-simultaneous duplicate requests.

- **CI_049**: Verifies PAR–authorization correlation. Checks that the PAR response contained a `request_uri` matching the URN pattern `urn:ietf:params:oauth:request_uri:…`, and that the subsequent authorization step succeeded and returned an authorization `code`. If the issuer had not correctly associated the PAR session with the authorization request, the authorization would have failed.

- **CI_050**: Sends an authorization request without a `request_uri` parameter (empty string). Verifies that the issuer rejects the request, enforcing the PAR-only flow where authorization requests must reference a previously submitted PAR via `request_uri`.

#### Authorization Tests

- **CI_054**: Verifies that the Credential Issuer completed user authentication via PID presentation. The test checks that the authorization step returned an authorization `code`, which is only issued after the issuer successfully validated the PID credential presented by the Wallet Instance via OpenID4VP.

- **CI_055**: Verifies that the issuer triggered the OpenID4VP protocol to request PID presentation from the Wallet. The test checks that the authorization step returned an authorization `code`, which can only be obtained after the wallet completed the OpenID4VP presentation exchange initiated by the issuer.

- **CI_056**: Verifies that the issuer sent the OpenID4VP presentation Request Object JWT to the Wallet Instance. The test checks that `requestObjectJwt` is defined in the authorization step response, confirming that the issuer delivered a signed request for the wallet to parse and respond to.

- **CI_058a**: Reads the `code` field from the authorization callback response and asserts that it is a defined non-empty string. This short-lived authorization code is subsequently exchanged for tokens at the token endpoint.

- **CI_058b**: Reads the `state` parameter from both the authorization callback response and from the original authorization request object. Asserts that the two values are exactly equal, confirming that the issuer echoed back the `state` without modification (CSRF protection per OAuth 2.0 §10.12).

- **CI_058c**: Reads the `iss` parameter from the authorization callback response and compares it to the issuer identifier obtained during the authorization step. Asserts they are equal, confirming the response is bound to the correct issuer (RFC 9207 — Authorization Server Issuer Identification).

#### Token Endpoint Validation Tests

These are negative tests that verify the token endpoint enforces all required validations.

- **CI_060**: Sends a token request with an authorization `code` set to `"unknown-code-123"` — a value that was never issued by the server. Verifies that the issuer rejects the request with `invalid_grant`, confirming it validates the authorization code against its own records.

- **CI_061**: Runs a fresh authorization flow to obtain a valid `code`. Sends two token requests using the same `code` (3 seconds apart). The first request must succeed. The second request must fail. Verifies that authorization codes are single-use only.

- **CI_061a**: Sends a token request with the correct `code` but with a mismatched `code_verifier` (`"wrong-verifier-123"` instead of the PKCE verifier generated during PAR). Verifies that the issuer enforces PKCE by checking the `code_verifier` against the stored `code_challenge` and rejects mismatches.

- **CI_062**: Sends a token request with the correct `code` and `code_verifier` but with a different `redirect_uri` (`"https://wrong.redirect.uri"`). Verifies that the issuer performs byte-for-byte matching of the `redirect_uri` against the value registered during PAR.

- **CI_063**: Creates a DPoP proof JWT for the token endpoint with `method: "GET"` instead of `"POST"`, producing an `htm` claim of `"GET"`. Sends this invalid DPoP proof with an otherwise valid token request. Verifies that the issuer validates the DPoP proof's `htm` claim and rejects the request.

#### Token Request Tests

- **CI_064**: Decodes the Access Token JWT from the token endpoint response and checks two timestamp claims: `exp` must be greater than the current Unix time (token is not yet expired), and `iat` must be less than the current Unix time (token was issued in the past). Confirms the Access Token is valid and immediately usable.

- **CI_066**: Checks that `token_type` equals `"DPoP"`. Computes the JWK thumbprint of the DPoP public key stored in the token response. For every token returned (Access Token, and Refresh Token if present), decodes the JWT and asserts that the `cnf.jkt` claim matches the computed thumbprint. Confirms each token is cryptographically bound to the DPoP key.

- **CI_094**: Same DPoP binding verification as CI_066, applied specifically to the tokens generated after all validation checks pass. Confirms that both the Access Token and any Refresh Token carry a `cnf.jkt` claim equal to the JWK thumbprint of the DPoP key.

- **CI_095**: Asserts that the `access_token` field is defined and non-empty in the token endpoint response. Confirms that the issuer delivered at least the Access Token to the Wallet Instance after a successful token exchange.

- **CI_101**: Verifies that every token in the token response (Access Token and optional Refresh Token) carries a `cnf.jkt` claim equal to the JWK thumbprint of the same DPoP public key. Confirms that all tokens are bound to the same single key rather than different keys.

#### Nonce Request Tests

- **CI_068**: Calls the nonce endpoint after a successful token exchange and asserts that the response contains a `c_nonce` field that is a defined, non-empty string. The `c_nonce` is the server-issued challenge the Wallet Instance must embed in its credential proof JWT.

- **CI_069**: Validates two properties of the `c_nonce` value: (1) its length must be at least 32 characters, and (2) its Shannon entropy (computed over the character-frequency distribution of the string) must exceed 5 bits. Low entropy would indicate a predictable value that an attacker could guess before it is used.

#### Credential Request Tests

- **CI_071**: Sends a credential request whose JWT proof is missing the `nonce` claim. Verifies that the issuer detects the missing mandatory claim and rejects the request, rather than proceeding with an unauthenticated proof.

- **CI_072**: Constructs a batch credential request where the same proof JWT (with the same JWK) is duplicated in the `proofs.jwt` array. Verifies that the issuer rejects duplicate proof keys in a batch request. This test is skipped if the issuer does not advertise `batch_credential_issuance` in its metadata or if the wallet is configured for spec version 1.0.

- **CI_073**: Sends a credential request whose JWT proof has `typ: "JWT"` in the header instead of the required `"openid4vci-proof+jwt"`. Verifies that the issuer validates the `typ` header and rejects proofs declared with the wrong type.

- **CI_074**: Sends a credential request whose JWT proof is signed with HMAC-SHA256 (`HS256`), a symmetric algorithm. Verifies that the issuer enforces the requirement for asymmetric proof algorithms and rejects symmetric signatures.

- **CI_075**: Sends a credential request whose JWT proof is signed with a fresh random key while the `jwk` header still declares a different public key. The signature cannot verify against the declared JWK. Verifies that the issuer performs cryptographic verification of the proof signature.

- **CI_076**: Sends a credential request whose JWT proof `jwk` header contains the private key `d` parameter (EC private scalar). Verifies that the issuer detects the presence of private key material in a public-key field and rejects the request.

- **CI_077**: Sends a credential request with a proof whose `nonce` claim is set to `"this-nonce-was-never-issued-by-the-server"` — a value the server never generated. Verifies that the issuer checks the nonce against its own issued challenges and rejects unrecognized values.

- **CI_078a**: Advances the system clock 10 minutes into the future before building the credential proof JWT, producing an `iat` claim 10 minutes ahead of the server's current time. Verifies that the issuer rejects proofs with a future `iat` beyond the clock-skew tolerance.

- **CI_078b**: Rewinds the system clock 6 minutes before building the credential proof JWT, producing an `iat` claim 6 minutes in the past (beyond the assumed 5-minute tolerance window). Verifies that the issuer rejects stale proofs.

- **CI_079**: Runs a successful credential request and inspects the issued credential's JWT payload for a `status` claim. For spec version 1.3, verifies that `status.status_list` is present with an integer `idx` and a string `uri`. For spec version 1.0, verifies that `status.status_assertion` is present with a `credential_hash_alg` string. Confirms the credential references a valid revocation/status mechanism.

- **CI_084**: Runs a successful credential request and verifies that the issued SD-JWT VC credential is cryptographically bound to the wallet's key. Extracts the `cnf` claim from the credential's JWT payload, computes the JWK thumbprint of the `cnf.jwk`, and asserts it equals the thumbprint of the wallet's credential key pair. Confirms the credential cannot be used by anyone other than the holder of the matching private key.

- **CI_084a**: Sends a credential request with `credential_configuration_id` set to `"unknown_credential_type_that_does_not_exist_in_issuer_metadata"`. Verifies that the issuer validates the credential type against its metadata and rejects requests for unknown types.

- **CI_118**: For each credential in the response, attempts to parse it first as an SD-JWT VC and, if that fails, as an mdoc-CBOR document. The test passes if at least one credential is successfully parsed as either format, confirming the issuer returns credentials in one of the two formats mandated by the specification.

#### Credential Request DPoP Tests

- **CI_082a**: Sends a credential request with no `DPoP` header at all. Verifies that the issuer requires a DPoP proof for credential endpoint access and rejects requests that omit it entirely.

- **CI_082b**: Sends a credential request with a DPoP proof whose `htm` claim is set to `"GET"` instead of the required `"POST"`. Verifies that the issuer validates the HTTP method claim against the actual request method (RFC 9449 §4.3 check 2).

- **CI_082c**: Sends a credential request with a DPoP proof whose `ath` (access token hash) claim is computed from a different (wrong) access token. Verifies that the issuer revalidates the `ath` claim against the actual access token used in the request (RFC 9449 §4.3 check 8).

- **CI_082d**: Sends a credential request with a DPoP proof that is missing the `ath` claim entirely (simulating reuse of a token-endpoint DPoP proof at the credential endpoint). Verifies that the issuer requires the `ath` claim at the credential endpoint, where token binding is mandatory (RFC 9449 §4.3).

- **CI_082e**: Sends a credential request with a DPoP proof whose `typ` header is set to `"JWT"` instead of the required `"dpop+jwt"`. Verifies that the issuer validates the type header of the DPoP proof (RFC 9449 §4.3 check 4).

- **CI_082f**: Sends a credential request with a DPoP proof that declares `alg: "none"`. Verifies that the issuer rejects unsigned DPoP proofs and enforces the requirement for a proper asymmetric algorithm (RFC 9449 §4.3 check 5).

- **CI_082g**: Sends a credential request with a DPoP proof signed by key A but with key B declared in the `jwk` header, so the signature does not verify against the declared key. Verifies that the issuer cryptographically verifies the DPoP proof signature against the key in the `jwk` header (RFC 9449 §4.3 check 6).

- **CI_082h**: Sends a credential request with a DPoP proof whose `jwk` header contains the private key `d` parameter alongside the public key coordinates. Verifies that the issuer rejects DPoP proofs that expose private key material in the header (RFC 9449 §4.3 check 7).

- **CI_082i**: Sends a credential request with a DPoP proof whose `htu` (HTTP target URI) claim points to a different endpoint than the actual credential endpoint URL. Verifies that the issuer validates `htu` against the current request URI (RFC 9449 §4.3 check 9).

- **CI_082j**: Sends a credential request with a DPoP proof whose `iat` is set 5 minutes in the past, placing it outside the server's freshness window. Verifies that the issuer enforces the DPoP proof freshness requirement and rejects stale proofs (RFC 9449 §4.3 check 11).

- **CI_083**: Sends a credential request where the DPoP proof is signed by a different key than the one bound to the access token (the `cnf.jkt` in the token does not match the DPoP proof's `jwk` thumbprint). Verifies that the issuer checks the DPoP key consistency between the access token binding and the current DPoP proof.

---

### Presentation Flow Tests

The presentation flow validates credential presentation conformance according to [Credential Verifier Test Matrix](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-presentation.html).

#### QR Code and Authorization Request Tests

- **RPR003**: After a complete presentation flow, checks that the `client_id` in the QR code URL matches the `sub` claim of the Relying Party's Entity Configuration, and that the `request_uri` in the QR code is a valid HTTPS URL. Confirms the QR code is anchored to the RP's federated identity rather than an arbitrary URL.

- **RPR004**: Reads the `client_id` from the parsed QR code and asserts it matches the pattern `https://…`. Verifies that the RP uses an HTTPS URL as its `client_id`, as required for federation-based trust (the `client_id` serves as the RP's entity identifier).

- **RPR009**: Checks `request_object_endpoint_methods` in the RP's `openid_credential_verifier` metadata. If the field is present, verifies that `"GET"` is included as a supported method. If the field is absent, the default (GET) applies. Also verifies that the authorization request step succeeded, confirming the wallet fetched the Request Object via GET.

- **RPR012**: Reads `state` and `nonce` from the parsed Request Object JWT and verifies that both are defined, non-empty strings matching the pattern `[a-zA-Z0-9_-]+` (URL-safe characters). These parameters are mandatory to bind the authorization session and protect against replay and cross-site request forgery.

- **RPR013**: Reads the `alg` field from the authorization Request Object JWT header and asserts it is one of the recognized asymmetric signing algorithms: `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, or `PS512`. Verifies the RP signs its requests with a standards-compliant algorithm.

- **RPR014**: Reads the `kid` field from the authorization Request Object JWT header and asserts it is a defined, non-empty string. The `kid` allows the wallet to locate the correct verification key in the RP's JWKS.

- **RPR015**: Reads the authorization Request Object JWT header and verifies that at least one of two trust signals is present: `trust_chain` (a non-empty array of JWTs representing the OpenID Federation trust chain) or `x5c` (a non-empty certificate chain array). Confirms the RP embeds its trust credential in the Request Object for the wallet to validate.

- **RPR019**: Verifies that the redirect URI step succeeded and returned a `redirectUri` that is a valid HTTPS URL, and that `responseCode` is defined in the response. Confirms that after the wallet submitted the VP token, the RP responded with a valid redirect containing a `response_code`.

#### JARM Response Tests

- **RPR016**: Reads the `responseJwe` field from the authorization response's JARM object and verifies it is a valid compact JWE serialization — exactly five dot-separated parts, each a non-empty base64url-encoded segment. Confirms the RP encrypts the authorization response using the JARM (JWT Secured Authorization Response Mode) standard.

- **RPR017**: Reads the `encryptionJwk` from the JARM object and verifies it is a valid EC public key with the required parameters: `kty: "EC"`, `crv` (curve name), `x` (x coordinate), and `y` (y coordinate). Confirms the RP selected an EC key for JARM encryption.

#### DCQL Query Tests

- **RPR078**: Reads the `dcql_query` field from the Request Object JWT payload and verifies that it is a non-null object containing a `credentials` array with at least one element. Confirms the RP uses the DCQL (Digital Credential Query Language) format, as required by the specification.

- **RPR079**: Iterates over all credential entries in `dcql_query.credentials`. For each entry identified as a Wallet Attestation (i.e., `meta.vct_values` contains `"urn:eu.europa.ec.eudi:wallet_attestation:1"`), asserts that the `claims` field is **absent**. The Wallet Attestation is requested for its presence only, not for specific attributes; including a `claims` filter would be a protocol violation.

- **RPR080**: Iterates over all credential entries in `dcql_query.credentials` that have a `meta` object. Verifies that each such entry includes a `meta.vct_values` field that is a non-empty array of strings. The `vct_values` field specifies the allowed credential types and is mandatory for type-constrained requests.

- **RPR081**: Iterates over all credential entries in `dcql_query.credentials` and asserts that each entry has a non-empty `id` field of type string. The `id` is used to correlate the credential query with the credential in the authorization response's `vp_token`.

#### Metadata and Configuration Tests

- **RPR082**: Reads `openid_credential_verifier.response_types_supported` from the RP's Entity Configuration and asserts that the array contains `"vp_token"`. Confirms the RP declares its support for the VP Token response type, which is required for the OpenID4VP cross-device flow.

- **RPR083**: Verifies two things end-to-end: (1) the `response_uri` in the Request Object JWT is a valid HTTPS URL, and (2) the redirect URI step, which POSTs the VP token to that `response_uri`, succeeded and returned a valid redirect URL. Confirms that the RP correctly exposes and handles the `response_uri` endpoint.

- **RPR095**: Verifies that the FetchMetadata step completed successfully and that the HTTP response status was 200. Confirms that the RP's `.well-known/openid-federation` endpoint is reachable and returns a well-formed response.

- **RPR096**: Reads the `iss` and `sub` claims from the RP's Entity Configuration and asserts that both are defined strings and that they are equal to each other. In a self-signed Entity Configuration (the entity's own statement), `iss` and `sub` must be identical — both equal to the entity's identifier URL.

#### JWT and Parameter Validation Tests

- **RPR085**: Reads the `state` parameter from the Request Object JWT and the `state` value from the authorization response payload. Asserts they are equal. Verifies that the RP (or the wallet, acting as relay) echoes back the same `state` value in the response, which is required for session binding.

- **RPR086**: Reads the authorization response payload sent by the wallet to the RP's `response_uri` and asserts that the `vp_token` field is defined and non-null. Confirms the wallet included the Verifiable Presentation token in its response.

- **RPR087**: Reads the `vp_token` from the authorization response payload and asserts it is either a non-empty string or an object with at least one key. Confirms the VP token has a valid, non-trivial format — the type depends on the credential format (SD-JWT VC yields a string, mdoc may yield an object).

- **RPR089**: Reads the `typ` header from the authorization Request Object JWT and asserts it equals `"oauth-authz-req+jwt"`. This is the JWT type mandated by RFC 9101 (JAR) and the OpenID4VP profile for authorization request JWTs.

- **RPR090**: Reads `response_mode` from the Request Object JWT payload and asserts it equals `"direct_post.jwt"`. This mode requires the wallet to POST the VP token, encrypted as a JARM JWT, directly to the `response_uri` endpoint.

- **RPR091**: Reads `response_type` from the Request Object JWT payload and asserts it equals `"vp_token"`. This is the only response type permitted in the OpenID4VP cross-device flow used by the IT Wallet ecosystem.

- **RPR092**: Reads `response_uri` from the Request Object JWT and verifies it is a valid HTTPS URL. Then confirms the redirect URI step (which submits the VP token to that endpoint) succeeded. Together these verify the end-to-end routing of the authorization response to the correct RP endpoint.

- **RPR093**: Reads the `nonce` from the Request Object JWT and asserts that its length is at least 32 characters. A nonce shorter than 32 characters may not provide sufficient entropy against guessing; a longer value ensures cryptographic unpredictability.

- **RPR094**: Reads the `exp` claim from the Request Object JWT, computes the current Unix timestamp, and asserts `exp > current_time`. Confirms the Request Object was issued with a future expiration and has not already expired by the time the wallet processes it.

- **RPR097**: Reads the `requestUriMethod` field from the parsed QR code. If present, asserts it is either `"get"` or `"post"`. If absent, the default (GET) is used and the test passes. Verifies the RP specifies only valid HTTP methods for fetching the Request Object.
