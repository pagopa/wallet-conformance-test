#!/bin/sh

set -eu

API_URL="https://localhost:8080/create-authorization-request"
VCT_VALUE="urn:eudi:pid:it:1"

PAYLOAD=$(
  cat <<EOF
{
  "dcqlQuery": {
    "credentials": [
      {
        "claims": [
          { "path": ["given_name"] },
          { "path": ["family_name"] }
        ],
        "format": "dc+sd-jwt",
        "id": "0",
        "meta": {
          "vct_values": ["$VCT_VALUE"]
        }
      }
    ]
  },
  "flow_type": "cross-device"
}
EOF
)

RESPONSE=$(
  curl -k -sS -w "\n%{http_code}" \
    -X POST "$API_URL" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD"
)

HTTP_BODY=$(printf '%s\n' "$RESPONSE" | sed '$d')
HTTP_STATUS=$(printf '%s\n' "$RESPONSE" | tail -n 1)

if [ "$HTTP_STATUS" != "200" ]; then
  printf 'HTTP %s: %s\n' "$HTTP_STATUS" "$HTTP_BODY" >&2
  exit 1
fi

AUTHORIZE_URL=$(printf '%s\n' "$HTTP_BODY" | jq -r '.url // empty')

if [ -z "$AUTHORIZE_URL" ]; then
  printf "La risposta non contiene la chiave 'url'\n" >&2
  exit 1
fi

printf '%s\n' "$AUTHORIZE_URL"
