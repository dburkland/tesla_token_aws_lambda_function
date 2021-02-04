README
=========

### Introduction

Tesla Token is an AWS Lambda Function that works with Tesla's v3 Token system to create access and refresh tokens which are valid for 45 days. This function is designed for a set of iOS shortcuts however supports any application that can issue REST API calls. 

### Supported JSON payload

```json
{
  "TESLA_EMAIL": "user@domain.com",
  "TESLA_PASSWORD": "password",
  "TESLA_MFA_CODE": "123456"
}
```

### FAQs

* Where can I learn more about the aforementioned iOS Shortcuts?
  * Please refer to the Tesla iOS Shortcuts [README](https://github.com/dburkland/tesla_ios_shortcuts/blob/master/README.md)
* At a high level, how does the Tesla Token API service work?
  * iOS Shortcut -> AWS API Gateway -> AWS Lambda Function -> Tesla API Service
