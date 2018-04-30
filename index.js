'use strict'

const jose = require('node-jose')

module.exports = function (config, developmentKeyId, logger, errorLogger) {
  /* placeholder for reified key */
  var key

  /* can switch to noop or redirect to other logger if needed */
  const log = logger || console.log // ()=>{}
  const error = errorLogger || console.error // ()=>{}

  const errorHelper = (msg) => new Error(msg)

  /* json representation of the shared key, the json MUST be changed in production */
  const keyDefinition = config.keyDefinition
  if (!keyDefinition || !developmentKeyId) return errorHelper('invalid arguments, check config and developmentKeyId')

  // TODO check that this is the relevant ENV var
  if (keyDefinition.kid === developmentKeyId && process.ENV === 'prod') {
    error('FATAL ERROR: ensureKeyReady has a known development keyDefinition.kid for production!')
    process.exit(1)
  }

  /*
  Reifies the key from the description so node-jose can use it
  NB. only needed for decryption, encryption can use raw json def
  */
  function ensureKeyReady (callback) {
    /* sync */
    if (typeof callback !== 'function') return errorHelper('ensureKeyReady invalid callback')

    /* async */
    if (typeof keyDefinition !== 'object') return callback(errorHelper('ensureKeyReady invalid keyDefinition'))
    if (key) return callback(null, true)

    jose.JWK.asKey(keyDefinition)
      .then(function (result) {
        key = result
        callback(null, true)
      })
  }

  /* optimise by preparing key early */
  ensureKeyReady(() => {})

  /* UTC seconds since the epoch */
  function nowSeconds () {
    return Math.floor(Date.now() / 1000)
  }

  /* reduce uncaught exceptions */
  function safeParse (str) {
    try {
      return JSON.parse(str)
    } catch (err) {
      /* consider logging a portion of str if not personal data */
      log('safeParse received bad string', err.message)
      return null
    }
  }

  /* reduce uncaught exceptions */
  function safeStringify (obj) {
    try {
      return JSON.stringify(obj)
    } catch (err) {
      /* consider logging a portion of obj if not personal data */
      log('safeStringify received bad object', err.message)
      return null
    }
  }

  function createJWE (claimsObject, callback) {
    /* sync */
    if (typeof claimsObject !== 'object') return callback(errorHelper('createJWE invalid claimsObject'))
    if (typeof callback !== 'function') return callback(errorHelper('createJWE invalid callback'))

    /* async */
    var iat = nowSeconds()
    claimsObject.iss = config.tokenProperties.iss
    claimsObject.iat = iat
    claimsObject.exp = iat + config.tokenProperties.expirySeconds

    var payload = safeStringify(claimsObject)
    if (payload === null) return callback(errorHelper('createJWE unparsable object'))
    if (!key && !keyDefinition) return callback(errorHelper('createJWE no suitable encryption keys found'))

    jose.JWE.createEncrypt(
      {
        format: 'compact'
      }, key || keyDefinition)
      .update(payload)
      .final()
      .then(function (result) {
        /* {result} is a JSON Object -- JWE using the JSON General Serialization */
        callback(null, result)
      })
      .catch(function (err) {
        error(err)
        return callback(errorHelper('error encrypting token'))
      })
  }

  function verifyJWE (tokenString, callback) {
    /* sync */
    if (typeof tokenString !== 'string' || tokenString.length < 65) return errorHelper('verifyJWE invalid tokenString')
    if (typeof callback !== 'function') return errorHelper('verifyJWE invalid callback')

    /* async */
    // https://github.com/cisco/node-jose#allowing-or-disallowing-encryption-algorithms
    // the documents are misleading, these options do not restrict to A256KW so do some horrible string matching
    var opts = {
      algorithms: ['A256KW'],
      allowAlgs: ['A256KW']
    }
    // TODO move this post parse
    var headerB64 = Buffer.from(tokenString.split('.')[0], 'base64')
    if (headerB64.indexOf('"enc":"A128CBC-HS256"') === -1) return callback(errorHelper('verifyJWE invalid enc in header'))

    ensureKeyReady(() => {
      jose.JWE.createDecrypt(key, opts)
        .decrypt(tokenString)
        .then(function (result) {
          // {result} is a Object with:
          // *  header: the combined 'protected' and 'unprotected' header members
          // *  protected: an array of the member names from the "protected" member
          // *  key: Key used to decrypt
          // *  payload: Buffer of the decrypted content
          // *  plaintext: Buffer of the decrypted content (alternate)
          let parsed = safeParse(result.payload.toString('utf8'))
          if (parsed === null) return callback(errorHelper('verifyJWE unparsable payload'))

          let missing = []
          'iat,exp,iss,aud'.split(',').forEach((claimName) => {
            if (!parsed[claimName]) missing.push(claimName)
          })
          if (missing.length) return callback(errorHelper('verifyJWE missing mandatory claims: ' + missing.join(',')))

          // these could fail with tokens issued by another iss/server. consider adding a skew tolerance
          if (nowSeconds() < parsed.iat) return callback(errorHelper('verifyJWE time travel not allowed'))
          if (nowSeconds() > parsed.exp) return callback(errorHelper('verifyJWE token has expired'))

          if (config.tokenProperties.validAudiences.indexOf(parsed.aud) === -1) return callback(errorHelper('verifyJWE invalid audience'))

          callback(null, parsed)
        })
        .catch(function (err) {
          error(err)
          return callback(errorHelper('suspected tampering of token'))
        })
    })
  }

  return {
    createJWE, verifyJWE, errorHelper, ensureKeyReady
  }
}
