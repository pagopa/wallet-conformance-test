# Test Execution Reference

### Issuance Flow Tests

The issuance flow validates credential issuance conformance according to [Credential Issuer Test Matrix](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-credential-issuer.html).

#### Federation Metadata Tests

- **CI_001**: Federation Entity publishes its own Entity Configuration in the .well-known/openid-federation endpoint
- **CI_002**: Entity Configuration response media type check (must be `application/entity-statement+jwt`)
- **CI_003**: The Entity Configuration is cryptographically signed (JWT signature validation)
- **CI_006**: Entity Configurations have in common these parameters: `iss`, `sub`, `iat`, `exp`, `jwks`, `metadata`
- **CI_008**: Credential Issuer metadata includes `federation_entity`, `oauth_authorization_server`, and `openid_credential_issuer` sections
- **CI_009**: Inclusion of `openid_credential_verifier` metadata in User Authentication via Wallet

#### Pushed Authorization Request (PAR) Tests

- **CI_040**: `request_uri` validity time is set to less than one minute
- **CI_041**: Generated `request_uri` includes a cryptographic random value of at least 128 bits
- **CI_042**: Complete `request_uri` doesn't exceed 512 ASCII characters
- **CI_043**: When verification is successful, Credential Issuer returns HTTP 201 status code
- **CI_044a**: HTTP response includes `request_uri` parameter containing the generated one-time authorization URI
- **CI_044b**: HTTP response includes `expires_in` parameter specifying the validity duration in seconds

#### Authorization Tests

- **CI_049**: Credential Issuer successfully identifies and correlates each authorization request as a direct result of a previously submitted PAR
- **CI_054**: (Q)EAA Provider successfully performs User authentication by requesting and validating a valid PID from the Wallet Instance
- **CI_055**: (Q)EAA Provider uses OpenID4VP protocol to request PID presentation from the Wallet Instance
- **CI_056**: (Q)EAA Provider successfully provides the presentation request to the Wallet
- **CI_058a**: Authorization code response includes the `code` parameter
- **CI_058b**: Authorization code response includes the `state` parameter matching the original request
- **CI_058c**: Authorization code response includes the `iss` parameter identifying the issuer

#### Token Request Tests

- **CI_064**: Credential Issuer provides the Wallet Instance with a valid Access Token upon successful authorization
- **CI_066**: Both Access Token and Refresh Token (when issued) are cryptographically bound to the DPoP key
- **CI_094**: When all validation checks succeed, Credential Issuer generates new Access Token and new Refresh Token, both bound to the DPoP key
- **CI_095**: Both the Access Token and the Refresh Token are sent back to the Wallet Instance
- **CI_101**: Access Tokens and Refresh Tokens are bound to the same DPoP key

#### Nonce Request Tests

- **CI_068**: Credential Issuer provides a `c_nonce` value to the Wallet Instance
- **CI_069**: The `c_nonce` parameter is provided as a string value with sufficient unpredictability to prevent guessing attacks (≥32 characters with sufficient entropy)

#### Credential Request Tests

- **CI_071**: Issuer rejects a credential request whose JWT proof is missing a required claim (`nonce`)
- **CI_072**: Issuer rejects a batch credential request with duplicate proof keys (skipped when issuer does not advertise `batch_credential_issuance` or wallet config is v1.0)
- **CI_073**: Issuer rejects a credential request with an incorrect proof `typ` header (e.g. `JWT` instead of `openid4vci-proof+jwt`)
- **CI_074**: Issuer rejects a credential request whose JWT proof is signed with a symmetric algorithm (HS256)
- **CI_075**: Issuer rejects a credential request whose JWT proof signature does not verify against the declared JWK
- **CI_076**: Issuer rejects a credential request whose JWT proof JWK header contains private key material (`d` parameter)
- **CI_077**: Issuer rejects a credential request whose proof `nonce` was not issued by the server
- **CI_078a**: Issuer rejects a credential proof whose `iat` is more than the clock-skew tolerance into the future
- **CI_078b**: Issuer rejects a credential proof whose `iat` is more than 5 minutes in the past
- **CI_079**: Issued credential references a valid status list entry initialized as valid (`status_list` in v1.3; `status_assertion` in v1.0)
- **CI_084**: When all validation checks succeed, Credential Issuer creates a new Credential cryptographically bound to the validated key material and provides it to the Wallet Instance
- **CI_084a**: Issuer rejects a credential request for an unknown `credential_configuration_id`
- **CI_118**: (Q)EAA are Issued to a Wallet Instance in SD-JWT VC or mdoc-CBOR data format

#### Credential Request DPoP Tests

- **CI_082a**: Issuer rejects a credential request with no DPoP proof header
- **CI_082b**: Issuer rejects a credential request whose DPoP `htm` claim is not `POST`
- **CI_082c**: Issuer rejects a credential request whose DPoP `ath` claim does not match the access token hash
- **CI_082d**: Issuer rejects a credential request whose DPoP proof lacks the `ath` claim
- **CI_082e**: Issuer rejects a credential request whose DPoP `typ` header is not `dpop+jwt` (RFC 9449 §4.3 check 4)
- **CI_082f**: Issuer rejects a credential request whose DPoP uses `alg=none` (RFC 9449 §4.3 check 5)
- **CI_082g**: Issuer rejects a credential request whose DPoP signature does not verify against the declared `jwk` header key (RFC 9449 §4.3 check 6)
- **CI_082h**: Issuer rejects a credential request whose DPoP `jwk` header contains private key material (RFC 9449 §4.3 check 7)
- **CI_082i**: Issuer rejects a credential request whose DPoP `htu` does not match the credential endpoint URI (RFC 9449 §4.3 check 9)
- **CI_082j**: Issuer rejects a credential request whose DPoP `iat` is outside the acceptable freshness window (RFC 9449 §4.3 check 11)
- **CI_083**: Issuer rejects a credential request where the DPoP key differs from the expected proof binding key

---

### Presentation Flow Tests

The presentation flow validates credential presentation conformance according to [Credential Verifier Test Matrix](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/test-plans-presentation.html).

#### QR Code and Authorization Request Tests

- **RPR003**: Relying Party issues the QR-Code containing a URL using the base URL provided within its metadata
- **RPR009**: Relying Party accepts defaults to GET method for request objects
- **RPR012**: Relying Party receives and validates response with `state` and `nonce` values
- **RPR019**: User is redirected correctly, the endpoint works

#### DCQL Query Tests

- **RPR078**: Wallet Attestation request correctly uses standard DCQL query format
- **RPR079**: `claims` parameter is not included in DCQL query for Wallet Attestation
- **RPR080**: `vct_values` parameter is correctly required in DCQL query

#### Metadata and Configuration Tests

- **RPR082**: `response_types_supported` is correctly set to `vp_token` in verifier metadata
- **RPR083**: Relying Party correctly provides and handles `redirect_uri` and `response_uri`

#### JWT and Parameter Validation Tests

- **RPR089**: JWT `typ` parameter is correctly set to `oauth-authz-req+jwt`
- **RPR090**: `response_mode` parameter is correctly set to `direct_post.jwt`
- **RPR091**: `response_type` parameter is correctly set to `vp_token`
- **RPR092**: Relying Party sends Authorization Response to correct `response_uri` endpoint
- **RPR093**: `nonce` parameter has sufficient entropy with at least 32 characters
- **RPR094**: JWT `exp` parameter is correctly set and not expired
