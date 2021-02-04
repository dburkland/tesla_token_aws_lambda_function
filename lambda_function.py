#!/usr/bin/env python3

import base64,hashlib,json,os,random,re,requests,time
from urllib.parse import parse_qs

def lambda_handler(event, context):
  ########################################### Global Variables #####################################################
  BASE_URL = "https://auth.tesla.com/oauth2/v3"
  AUTH_URL = BASE_URL + "/authorize"
  CALLBACK_URL = "https://auth.tesla.com/void/callback"
  CLIENT_ID = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384"
  EVENT_BODY = json.loads(event["body"])
  EVENT_HEADERS = event["headers"]
  MAX_ATTEMPTS = 2
  TESLA_EMAIL = EVENT_BODY["TESLA_EMAIL"]
  TESLA_PASSWORD = EVENT_BODY["TESLA_PASSWORD"]
  TOKEN_URL = BASE_URL + "/token"
  UA = "Mozilla/5.0 (Linux; Android 10; Pixel 3 Build/QQ2A.200305.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/85.0.4183.81 Mobile Safari/537.36"
  X_TESLA_USER_AGENT = "TeslaApp/3.10.9-433/adff2e065/android/10"

  # If Tesla.com account is secured with MFA, store the supplied MFA code that'll be used during the token creation process
  if "TESLA_MFA_CODE" in EVENT_BODY:
    TESLA_MFA_CODE = EVENT_BODY["TESLA_MFA_CODE"]
  else:
    TESLA_MFA_CODE = "no_mfa"

  # If X-Forwarded-For exists then set CLIENT_IP_ADDRESS accordingly
  if "X-Forwarded-For" in EVENT_HEADERS:
    CLIENT_IP_ADDRESS = EVENT_HEADERS["X-Forwarded-For"]
  else:
    CLIENT_IP_ADDRESS = "127.0.0.1"
  ##################################################################################################################

  # Function that generates parameters used for the initial requests
  def gen_params():
    verifier_bytes = os.urandom(86)
    code_verifier = base64.urlsafe_b64encode(verifier_bytes).rstrip(b"=")
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier).digest()).rstrip(b"=")
    state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("utf-8")
    return code_verifier, code_challenge, state

  # Function that logins into the specified Tesla.com account and generates an access token that is valid for 45 days
  def login(email, password, mfa_code):
    headers = {
        "User-Agent": UA,
        "x-tesla-user-agent": X_TESLA_USER_AGENT,
        "X-Requested-With": "com.teslamotors.tesla",
    }

    for attempt in range(MAX_ATTEMPTS):
      code_verifier, code_challenge, state = gen_params()

      params = (
        ("client_id", "ownerapi"),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
        ("redirect_uri", CALLBACK_URL),
        ("response_type", "code"),
        ("scope", "openid email offline_access"),
        ("state", state),
      )

      session = requests.Session()
      resp = session.get(AUTH_URL, headers=headers, params=params)

      if resp.ok and "<title>" in resp.text:
        print("Get auth form success after " + str({attempt +1}) + " attempts on behalf of the " + email + " Tesla.com account connecting via " + CLIENT_IP_ADDRESS)
        break
      time.sleep(3)

    if resp.ok and "<title>" in resp.text:
      csrf = re.search(r'name="_csrf".+value="([^"]+)"', resp.text).group(1)
      transaction_id = re.search(r'name="transaction_id".+value="([^"]+)"', resp.text).group(1)

      data = {
        "_csrf": csrf,
        "_phase": "authenticate",
        "_process": "1",
        "transaction_id": transaction_id,
        "cancel": "",
        "identity": email,
        "credential": password,
      }

      for attempt in range(MAX_ATTEMPTS):
        resp = session.post(
          AUTH_URL, headers=headers, params=params, data=data, allow_redirects=False
        )
        if resp.ok and (resp.status_code == 302 or "<title>" in resp.text):
          print("Post auth form success after " + str({attempt +1}) + " attempts on behalf of the " + email + " Tesla.com account connecting via " + CLIENT_IP_ADDRESS)
          break
        time.sleep(3)

      if resp.ok and (resp.status_code == 302 or "<title>" in resp.text):
        # Determine if user has MFA enabled
        # In that case there is no redirect to `https://auth.tesla.com/void/callback` and app shows new form with Passcode / Backup Passcode field
        is_mfa = True if resp.status_code == 200 and "/mfa/verify" in resp.text else False

        if is_mfa:
          print("MFA is enabled for the " + email + " Tesla.com account connecting via " + CLIENT_IP_ADDRESS)

          URL = AUTH_URL + "/mfa/factors?transaction_id=" + transaction_id
          resp = session.get(
            URL, headers=headers
          )

          factor_id = resp.json()["data"][0]["id"]
          data = {"transaction_id": transaction_id, "factor_id": factor_id, "passcode": mfa_code}
          URL = AUTH_URL + "/mfa/verify"
          resp = session.post(URL, headers=headers, json=data)

          if "error" in resp.text or not resp.json()["data"]["approved"] or not resp.json()["data"]["valid"]:
            print("ERROR: Invalid passcode for the " + email + " Tesla.com account connecting via " + CLIENT_IP_ADDRESS)
          else:
            data = {"transaction_id": transaction_id}

            for attempt in range(MAX_ATTEMPTS):
              resp = session.post(
                AUTH_URL,
                headers=headers,
                params=params,
                data=data,
                allow_redirects=False,
              )
              if resp.headers.get("location"):
                print("Successfully retrieved the location in " + str({attempt +1}) + " attempts on behalf of the " + email + " Tesla.com account connecting via " + CLIENT_IP_ADDRESS)
                break
              time.sleep(3)

        if resp.headers.get("location"):
          URL = CALLBACK_URL + "?code"
          code = parse_qs(resp.headers["location"])[URL]
        
          headers = {"user-agent": UA, "x-tesla-user-agent": X_TESLA_USER_AGENT}
          payload = {
            "grant_type": "authorization_code",
            "client_id": "ownerapi",
            "code_verifier": code_verifier.decode("utf-8"),
            "code": code,
            "redirect_uri": CALLBACK_URL,
          }

          resp = session.post(TOKEN_URL, headers=headers, json=payload)
          bearer_token = resp.json()["access_token"]
          headers["authorization"] = "bearer " + bearer_token
          payload = {
              "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
              "client_id": CLIENT_ID,
          }
    
          resp = session.post("https://owner-api.teslamotors.com/oauth/token", headers=headers, json=payload)
          resp_json = resp.json()
        else:
          print("Failed to retrieve the location in " + str(MAX_ATTEMPTS) + " attempts on behalf of the " + email + " Tesla.com account connecting via " + CLIENT_IP_ADDRESS)
          resp_json = "empty"
      else:
        print("ERROR: Post auth form failed after " + str(MAX_ATTEMPTS) + " attempts on behalf of the " + email + " Tesla.com account connecting via " + CLIENT_IP_ADDRESS)
        resp_json = "empty"
    else:
      print("ERROR: Get auth form failed after " + str(MAX_ATTEMPTS) + " attempts on behalf of the " + email + " Tesla.com account connecting via " + CLIENT_IP_ADDRESS)
      resp_json = "empty"
    
    return(resp_json)

  if TESLA_EMAIL == "test@test.com":
    TOKEN_DATA = {
      "access_token": "test_access_token",
      "refresh_token": "test_refresh_token"
    }
  else:
    # Request a fresh authentication token using the provided credentials
    TOKEN_DATA = login(TESLA_EMAIL, TESLA_PASSWORD, TESLA_MFA_CODE)

  if TOKEN_DATA != "empty":
    print("Successfully retrieved an access and refresh token on behalf of the " + TESLA_EMAIL + " Tesla.com account connecting via " + CLIENT_IP_ADDRESS)
    ACCESS_TOKEN = TOKEN_DATA["access_token"]
    REFRESH_TOKEN = TOKEN_DATA["refresh_token"]

    RETURN_DATA = {
      "statusCode": 200,
      "ACCESS_TOKEN": ACCESS_TOKEN,
      "REFRESH_TOKEN": REFRESH_TOKEN
    }

    RETURN_DATA_STR = json.dumps(RETURN_DATA)
  else:
    print("ERROR: Exiting as communication with Tesla's APIs failed on behalf of the " + TESLA_EMAIL + " Tesla.com account connecting via " + CLIENT_IP_ADDRESS)
    RETURN_DATA = {
      "statusCode": 400,
      "ACCESS_TOKEN": "ERROR_NO_TOKEN",
      "REFRESH_TOKEN": "ERROR_NO_REFRESH_TOKEN"
    }

    RETURN_DATA_STR = json.dumps(RETURN_DATA)

  return {
    'headers': {'Content-Type': 'application/json'},
    'body': RETURN_DATA_STR
  }
