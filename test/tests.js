'use strict'

const it = require('tape')

const config = require('./example_config')
const developmentKeyId = 'JWE-EZ_DEVELOPMENT'

const je = require('../')(config, developmentKeyId)

const E = (message) => new Error(message)

it('API', (t) => {
  t.equal('object', typeof je)
  t.equal('function', typeof je.createJWE)
  t.equal('function', typeof je.verifyJWE)
  t.equal('function', typeof je.errorHelper)
  t.end()
})

it('errorHelper', (t) => {
  t.deepEqual(je.errorHelper('foobar'), E('foobar'), 'returns foobar Error message')
  t.deepEqual(je.errorHelper('verifyJWE broken'), E('verifyJWE broken'), 'returns verifyJWE broken Error message')
  t.end()
})

it('ensureKeyReady', (t) => {
  t.deepEqual(je.ensureKeyReady(), E('ensureKeyReady invalid callback'), 'returns Error with invalid callback')
  je.ensureKeyReady((err, status) => {
    t.ok(err === null, 'calls back with err null')
    t.ok(status === true, 'calls back with true')
    t.end()
  })
})

it('createJWE sync', (t) => {
  t.deepEqual(je.createJWE(), E('createJWE invalid claimsObject'), 'returns Error with no arguments')
  t.deepEqual(je.createJWE('foobar', () => {}), E('createJWE invalid claimsObject'), 'returns Error with bad claimsObject argument')
  t.end()
})

it('createJWE circular async', (t) => {
  let circular = {}
  let b = { circular }
  circular.b = b

  je.createJWE(circular, (err, tokenString) => {
    t.deepEqual(err, E('createJWE invalid claimsObject'), 'returns Error with bad claimsObject argument')
    t.end()
  })
})

it('createJWE async', (t) => {
  je.createJWE({ foo: 'bar' }, (err, tokenString) => {
    console.log('tokenString', tokenString)
    t.ok(err === null, 'null error when good result')
    t.ok(typeof tokenString === 'string' && tokenString.length > 0, 'returns a token string')
    // check it has right algorithm
    let header = JSON.parse(Buffer.from(tokenString.split('.')[0], 'base64'))
    t.ok(header.alg === 'A256KW' && header.enc === 'A128CBC-HS256', 'token is A128CBC-HS256 with A256KW Key Wrapping')
    t.end()
  })
})

it('verifyJWE sync', (t) => {
  t.deepEqual(je.verifyJWE(), E('verifyJWE invalid tokenString'), 'returns Error with no arguments')
  t.deepEqual(je.verifyJWE({}, () => {}), E('verifyJWE invalid tokenString'), 'returns Error with incorrect type tokenString argument')
  t.deepEqual(je.verifyJWE('foobar', () => {}), E('verifyJWE invalid tokenString'), 'returns Error with bad tokenString')
  t.end()
})

it('verifyJWE async', (t) => {
  let badHeader = Buffer.from('{"alg":"FOOBAR","kid":"SPOOFEYFOOFEYWOOFEY","enc":"FOOBARBAZQUX"}').toString('base64')

  je.verifyJWE(badHeader, (err, claimsObject) => {
    t.deepEqual(err, E('verifyJWE invalid enc in header'), 'returns Error with wrong header')
    t.end()
  })
})

it('verifyJWE async', (t) => {
  je.createJWE({ 'foo': 'bar', 'stuff': 'nonsense' }, (err, tokenString) => {
    if (err) { console.log('UNEXPECTED ERROR IN UNIT TEST', err) }
    je.verifyJWE(tokenString, (err, claimsObject) => {
      t.ok(err.message.indexOf('verifyJWE missing mandatory claims') === 0, 'callback returns Error with missing "aud" claim')
      t.end()
    })
  })
})

it('verifyJWE async', (t) => {
  je.createJWE({ 'foo': 'bar', 'stuff': 'nonsense', 'aud': 'INVALID' }, (err, tokenString) => {
    if (err) { console.log('UNEXPECTED ERROR IN UNIT TEST', err) }
    je.verifyJWE(tokenString, (err, claimsObject) => {
      t.ok(err.message.indexOf('verifyJWE invalid audience') === 0, 'callback returns Error with invalid "aud" claim')
      t.end()
    })
  })
})

it('verifyJWE async', (t) => {
  je.createJWE({ 'foo': 'bar', 'stuff': 'nonsense', 'aud': 'bob' }, (err, tokenString) => {
    if (err) { console.log('UNEXPECTED ERROR IN UNIT TEST', err) }
    // add a second onto the example config expiry
    let futureMillis = (config.tokenProperties.expirySeconds * 1000) + 1000
    setTimeout(() => {
      je.verifyJWE(tokenString, (err, claimsObject) => {
        t.ok(err.message.indexOf('verifyJWE token has expired') === 0, 'callback returns Error when the token has expired')
        t.end()
      })
    }, futureMillis)
  })
})

it('verifyJWE async', (t) => {
  je.createJWE({ 'foo': 'bar', 'stuff': 'nonsense', 'aud': 'bob' }, (err, tokenString) => {
    if (err) { console.log('UNEXPECTED ERROR IN UNIT TEST', err) }
    je.verifyJWE(tokenString, (err, claimsObject) => {
      console.log('claimsObject', claimsObject)
      t.ok(err === null, 'null error when good result')
      t.ok(claimsObject.foo === 'bar', 'verifies an encrypted JWE')
      t.ok(claimsObject.iss === config.tokenProperties.iss, 'iss is added from config')
      t.ok(typeof claimsObject.iat === 'number', 'iat is added')
      t.ok(typeof claimsObject.exp === 'number', 'exp is added')
      t.end()
    })
  })
})

it('verifyJWE async', (t) => {
  je.createJWE({ 'foo': 'bar', 'stuff': 'nonsense', 'aud': 'bob' }, (err, tokenString) => {
    if (err) { console.log('UNEXPECTED ERROR IN UNIT TEST', err) }
    let lastSigChar = tokenString.slice(-1)
    tokenString = tokenString.slice(0, -1)
    lastSigChar = String.fromCharCode(lastSigChar.charCodeAt(0) ^ 1)
    tokenString += lastSigChar
    je.verifyJWE(tokenString, (err, claimsObject) => {
      t.deepEqual(err, E('suspected tampering of token'), 'error when token has been tampered')
      t.end()
    })
  })
})
