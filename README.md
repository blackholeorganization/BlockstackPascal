# Blockstack for Pascal

This is an Open port of [blockstack.js](https://github.com/blockstack/blockstack.js) for Pascal used in [BlackHole][BH_DOMAIN].

## Build Instructions
* Use [Lazarus & FPC](https://www.lazarus-ide.org) Trunk
## About

Blockstack for Pascal is a library for profiles/identity, authentication, and storage.

The authentication portion of this library can be used to:

1.  create an authentication request
2.  create an authentication response

The profiles/identity portion of this library can be used to:

1.  transform a JSON profile into cryptographically-signed tokens
2.  recover a JSON profile from signed tokens
3.  validate signed profile tokens

The storage portion of this library can be used to:

1. store and retrieve your app's data in storage that is controlled by the user

[//]: # (LINKS)
[BH_DOMAIN]: https://blackhole.run/