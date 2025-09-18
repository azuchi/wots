# WOTS+

A Ruby implementation of the Winternitz One-Time Signature Plus (WOTS+) scheme as described in [RFC 8391](https://datatracker.ietf.org/doc/html/rfc8391).

WOTS+ is a post-quantum cryptographic signature scheme that provides security against quantum computer attacks.

## Features

- Complete implementation of WOTS+ as specified in RFC 8391
- Support for multiple hash functions:
  - `WOTSP-SHA2_256` (SHA-256)
  - `WOTSP-SHA2_512` (SHA-512)
  - `WOTSP-SHAKE_256` (SHAKE-256)
- Support for Winternitz parameters w=4 and w=16
- Key generation from seed
- Digital signature generation and verification

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'wots'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install wots

## Usage

### Basic Example

```ruby
require 'wots'

# Use predefined parameters
param = WOTS::Param::SHA256

# Generate private key from seed
seed = "693141c7ee701d13e1a7c733e0aa8326c19961429bfb54083f2f65b30c32e20b"
private_key = WOTS::PrivateKey.from_seed(param, seed)

# Generate public key
pub_seed = "46ece585b4c0bfa1186209270e22fa07c4716461b5a026c268e594fb94404f3a"
public_key = WOTS::PublicKey.from_private_key(private_key, pub_seed)

# Sign a message
message = "f16c96e88fb99a8287a43121962e89ed521699fa3e126c67eaaa168066354477"
signature = private_key.sign(pub_seed, message)

# Verify signature by reconstructing public key
recovered_pk = WOTS::PublicKey.from_signature(signature, pub_seed, message)
valid = (recovered_pk == public_key)
puts "Signature valid: #{valid}"
```

### Available Parameter Sets

```ruby
# SHA-256 based (n=32 bytes, w=16)
param = WOTS::Param::SHA256

# SHA-512 based (n=64 bytes, w=16)
param = WOTS::Param::SHA512

# SHAKE-256 based (n=32 bytes, w=16)
param = WOTS::Param::SHAKE256

# Custom parameters (for w=4, etc.)
param = WOTS::Param.new(name: 'WOTSP-SHA2_256', n: 32, w: 4)
```

## Security Considerations

**⚠️ IMPORTANT: This is a cryptographic library implementation. While it follows RFC 8391 specifications,
it has not undergone formal security audits. Use at your own risk in production environments.**

WOTS+ is a **one-time signature scheme**. Each private key should only be used to sign **one message**.
Reusing a private key to sign multiple messages can leak information about the private key and compromise security.

## Specifications

This implementation follows [RFC 8391 - XMSS: eXtended Merkle Signature Scheme](https://datatracker.ietf.org/doc/html/rfc8391), Section 3 (WOTS+).
