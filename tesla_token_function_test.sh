#!/bin/bash
# Filename:             tesla_token_function_test.sh
# By:                   Dan Burkland
# Date:                 2021-02-03
# Purpose:              Validates the latest build of the Tesla Token function. This is meant to be used in a CI/CD pipeline.
# Version:              1.0

# Variables
FUNCTION_URL="$1"
TESLA_EMAIL="$2"
TESLA_PASSWORD="$3"
TESLA_MFA_CODE="$4"

# Generate Curl Request Body
generate_curl_body() {
  cat <<EOF
{
  "TESLA_EMAIL": "${TESLA_EMAIL}",
  "TESLA_PASSWORD": "${TESLA_PASSWORD}",
  "TESLA_MFA_CODE": "${TESLA_MFA_CODE}"
}
EOF
}

# Validate the front-end function
CURL_OUTPUT=$(curl -s -o /dev/null -w "%{http_code}" --location --request POST $FUNCTION_URL --header 'Content-Type: application/json' --data-raw "$(generate_curl_body)")

# Exit script with proper status code based on the test result
if [ "$CURL_OUTPUT" -eq "200" ]; then
  echo "tesla_token_aws_lambda_function build test result: PASSED"
  exit 0
else
  echo "tesla_token_aws_lambda_function build test result: FAILED"
  exit 1
fi
