[![JavaScript Style Guide](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

# jwe-ez

Easy usage confidential tamper-proofed tokens using A128CBC-HS256


## Setup

Install the necessary node packages by doing:

```
cd jwe-ez
npm install
```

## Usage

Provide a config object and a developmentKeyId which is used to detect if we should not be running in production.
_NB. "k" is a base64url encoded representation of a 256 bit symmetric key._

```
{
  "tokenProperties": {
    "iss": "alice",
    "validAudiences": ["alice", "bob"],
    "expirySeconds": 1
  },
  "keyDefinition": {
    "kty": "oct",
    "kid": "JWE-EZ_DEVELOPMENT",
    "k":   "Ls_HQn6Dow0dH_v4DQ5WZr5zfhqVdsaRlx416AOQ59M",
    "alg": "A256KW",
    "use": "enc"
  }
}
const developmentKeyId = 'JWE-EZ_DEVELOPMENT'
const je = require('jwe-ez')(config, developmentKeyId)

var claims = { foo: 'bar', stuff: 'nonsense' }
je.createJWE(claims, (err, tokenString) => {
  console.log(tokenString)
  /*
  eyJhbGciOiJBMjU2S1ciLCJraWQiOiJKV0UtRVpfREVWRUxPUE1FTlQiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.ox5JW3b5F-LuvHK60KK6ZxTNSsEL-eQOxXXrXGDqLeok2aOOPR_pqA.sbWamMH2WtXPiCO1VCbrqw.uhEhWKfA0hhEAzbsTOxaiSf9d45RHmxesDqs2fJYRzs6C0NWsL8SF6PdBzaOPqAUwgnR9-Fq1Ldsg6cRbJBnGQ.IasqvzuX7XXLgvBrOFrHgQ
  */

  je.verifyJWE(tokenString, (err, verifiedClaims) => {
    console.log(verifiedClaims)
    /*
    { foo: 'bar',
      stuff: 'nonsense',
      aud: 'bob',
      iss: 'alice',
      iat: 1523891758,
      exp: 1523891759
    }
    */
  })
})

```

## Linting

```npm run lint```

This runs the linting standards imposed by the "standard" JS package from https://github.com/feross/standard

## Testing

```npm test```

This runs all the test files that have been written into /test/tests.js by using the "tape" JS test framework from https://github.com/substack/tape

### TODO

- move payloads to the "sub" claim
- ensure audience is valid in createJWE
- move developmentKeyId to config
- assert(JWK.isKey(input.key)) for key verification
- whitelist claimsObject keys in createJWE from config
