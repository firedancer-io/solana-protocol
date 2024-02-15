# Solana Transport Layer v1.0

The STL (Solana Transport Layer) is a partial redesign of the Solana
peer-to-peer network stack from first principles, with a focus on
security and high performance.

It includes a connection-less application transport that provides
authentication and (optionally) encryption to undirectional UDP
datagram flows.  Authentication is provided via a separate handshake
protocol, which can simultaneously secure multiple applications.

The protocols are carefully designed to minimize protocol complexity
and strictly bound compute and memory requirements.  The STL protocol
specifications include implementation guidance to assist with security
hardening and hardware offload.

This document specifies STL v1.0, the first release.

STL v1.0 features authentication and encryption using modern
cryptography.  The handshake mechanism follows the [Noise Protocol]
framework.  The authenticated encryption cipher [TLS 1.3].

  [Noise Protocol]: http://www.noiseprotocol.org/noise.html
  [TLS 1.3]: https://datatracker.ietf.org/doc/html/rfc8446

> **The acronym STL is deliberately annoying to discourage production**
> **use before finalization of the protocol.  If chosen for adoption,**
> **it is to be renamed by a Solana community vote.**

## 1. Requirements

We define a base set of requirements realized using the simple
mode.  A superset including stretch goals is realized using the
encrypted mode.

### 1.1. Application layer base requirements

STL serves as the transport layer of the Solana validator network.
Solana facilitates high-performance broadcast, sequencing,
and confirmation of public transaction data over WAN.

At a high level, STL aims to provide the following properties:

- Protection against malicious packet injection through spoofing of
  the source IP address.
- Protection against common Denial-of-Service (DoS) vulnerabilities,
  such as traffic amplification and volumetric flood attacks.
- High performance as a function of robustness.

STL aims to support the following technical capabilities:

- IP datagram abstraction: To support high performance networking
  over the Internet, the transport layer assumes unicast UDP traffic.

- Simple source IP authentication: Use plaintext ephemeral session
  IDs to protect against IP spoofing attacks and some forms of
  payload injection.  Negotiation of session IDs is provided by the
  handshake protocol.  Protection against eavesdroppers is separately
  provided in the encrypted mode.

- Uni/bidirectional mode: Support efficient multicast-over-unicast
  (e.g. Solana Turbine protocol) in unidirectional mode.
  Bidirectional mode is simply achieved via two unidirectional
  sessions in opposing directions.

- Throughput: Achieve per-core throughput close to the theoretical
  maximum.  Allow for linear scaling when using multiple cores.

- External filtering offload: Support high performance packet filtering
  using XDP or related technologies.

- Hardware offload: Support heterogenous architectures, such as
  packet filtering and cryptographic offload using FPGA.

### 1.2. Handshake layer base requirements

STL also defines a handshake protocol which is used to request
sessions from a server.  The handshake protocol is the first
destination of any new client, and thus also the first line of
defense of the STL server side.  Requirements:

- Preserve liveness in light of attackers with eavesdrop (read
  incoming packets) and source IP spoof (add outgoing packets)
  capabilities:  Such attackers must not be able to kill existing
  sessions or in-flight handshakes.

- Data authentication: Block attempts to modify data from unauthorized
  peers (such as middle boxes).

- Scalability: Minimize per-session server state to support a large
  amount of peers.

- Load shedding/QoS: Avoid dropping high priority packets when
  subjected to packet flood.  (Elliptic curve cryptography at line
  rate might exhaust compute resources)

### 1.3. Encrypted mode requirements

The application layer optionally supports an encrypted mode.
Encrypted application data is concealed from eavesdroppers.

### 1.4. Non-requirements

STL explicitly drops support for some features not required for use in
the Solana validator network.

**Cryptographic Padding**

When confidentiality is required, the sender should inject padding to
obfuscate the real size of the plaintext.  Eavesdroppers could otherwise
recover confidential information from public packet length information.

It is the responsibility of the application to pad the plaintext before
passing it to STL.

**Forward Secrecy**

Currently, Solana clients expect that the data they send to eventually
become public.  It is not an explicit design goal to maintain data
confidentiality for an extended period after sending (e.g. multiple
hours).

**Client Anonymity**

The STL v1.0 handshake does not encrypt peer identities (public keys).

**Public Key Infrastructure**

STL does not verify the cryptographic identity of each peer (the
static public key) against a logical identity (e.g. a domain name).

## 2. Architecture

### 2.1. Transport

STL is layered on top of an underlying unicast datagram transport.

In STL v1.0, all traffic is encapsulated in UDP/IP packets.

### 2.2. Session

STL is session oriented.  For any two peers to exchange data, they must
first negotiate a session.  Sessions are ephemeral in nature.  Once a
session expires, no more data may be sent over that session.

The session state minimally includes a pseudorandom 56-bit session ID
and the wallclock time of expiry.  It typically also includes symmetric
keys for encryption and authentication.

### 2.3. Handshake

Peers negotiate a new session using the handshake protocol.  The peer
that initiates a handshake is referred to as the "client".  The other
peer is referred to as the "server".  It is assumed that the client
knows the server endpoint and identity before sending the first packet.

The handshake mechanism verifies that both peers agree on their
respective cryptographic identities.

### 2.4. Application

The STL application protocol is a lightweight wrapper around application
data.  It provides data authentication, and optionally, encryption.

The following figure shows a typical stack of layers of an STL packet.

```
+-------------+
| Application |
+-------------+
| STL         |
+-------------+
| UDP         |
+-------------+
| IP          |
+-------------+
| Ethernet    |
+.............+
```

STL transparently exposes packet bounds between the lower layer (raw
datagram protocol) and upper layer (application).  In the above example,
each application datagram corresponds to exactly one UDP packet.

Application packet processing is connection-less in STL:  Processing an
application packet does not depend on information gathered from an
earlier aplication packet.  Instead, the only dependency is external
session data gathered from the handshake protocol.

Consequently, packet reordering and loss is also visible to the
application layer.

## 3. Protocol Specification

### 3.1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC2119] [RFC8174].

  [RFC2119]: https://datatracker.ietf.org/doc/html/rfc2119
  [RFC8174]: https://datatracker.ietf.org/doc/html/rfc8174

The protocol assumes that bytes are octets.  Scalar types are encoded in
little endian order.  Structures of multiple scalars are laid out
byte-aligned packed.

The STL protocol assumes unicast communication between two peers over
the Internet.  The two peers are named "client" and "server".  The
IP address of each peer MUST stay constant.  In the handshake protocol,
the client initiates communication by sending the first packet
A successful handshake may implicitly create application data flows.
Each flow is identified by the tuple (destination UDP port, session ID).
Packets belong to these application data flows MUST only originate
from the client.  The client SHOULD only send these packets to the
server.

Henceforth, we specify cases in which a packet should be dropped.
Unless otherwise noted, peers MUST NOT destroy any other state, such
as the session object, when dropping a packet.

### 3.2. Feature String

The feature string identifies the STL protocol version and cryptographic
configuration.  This specification covers the following configurations.

- `STL-1.0-A`: STL v1.0, authenticated, unencrypted
- `STL-1.0-AE`: STL v1.0, authenticated, encrypted

### 3.2. Common Header

All UDP payloads in STL start with the common packet header.
The common packet header is defined as follows.

| Offset | Field          | Type       |
|--------|----------------|------------|
| `0x00` | `version_type` | `u8`       |
| `0x01` | `session_id`   | `[u8; 7]`  |

The `version_type` field contains two packed 4-bit fields:
`version` (most significant bits) and `type` (least significant bits).

The `version` field is hardcoded to `0x01`.
STL v1.0 peers MUST ignore incoming packets with any other version
number.

The `type` field indicates how to interpret a packet.
It is one of the values in the following table.  Each packet
type is described in detail below.

Incoming packets with an unsupported `type` MUST be dropped.

| Value  | Protocol    | Meaning              |
|--------|-------------|----------------------|
| `0x01` | Application | Data                 |
| `0x02` | Handshake   | Client Initial       |
| `0x03` | Handshake   | Server Continue      |
| `0x04` | Handshake   | Client Accept        |
| `0x05` | Handshake   | Server Accept        |

At offset `0x08` follows packet type-specific data.

## 3.3. Handshake Protocol

The following figure shows the four-way sequence of handshake packets
in STL v1.0.

```
+---------+            +---------+
| Client  |            | Server  |
+---------+            +---------+
     |                      |
     | Client Initial       |
     |--------------------->|
     |                      |
     |      Server Continue |
     |<---------------------|
     |                      |
     | Client Accept        |
     |--------------------->|
     |                      |
     |        Server Accept |
     |<---------------------|
```

### 3.3.1. Handshake Packet

All `STL-1.0-A` and `STL-1.0-AE` packets in the handshake protocol use
the following layout.

| Offset | Field         | Type       |
|--------|---------------|------------|
| `0x00` | Base Header   |            |
| `0x08` | `cookie`      | `[u8; 32]` |
| `0x28` | `identity`    | `[u8; 32]` |
| `0x48` | `key_share`   | `[u8; 32]` |
| `0x68` | `random`      | `[u8; 32]` |
| `0x88` | `verify`      | `[u8; 32]` |
| `0xa8` | `suite`       | `u16`      |
| `0xaa` | `next_packet` | `u16`      |

### 3.3.2. Server Cookie

The _Server Cookie_ is a 32 byte message authentication code generated
by the server from the incoming _Client Initial_.  The _Server Cookie_
is sent back to the client via the _Server Continue_.  The client then
presents the cookie in any future packets.  This mechanism allows the
server to statelessly verify that the sender assuming the source network
address of the _Client Initial_ is able to receive response data at that
same address.

### 3.3.3. X25519 Key Exchange

The client and server use a key exchange algorithm to securely establish
a _shared secret_ from which symmetric authentication and encryption
keys can be derived.

The key exchange algorithm in `STL-1.0-A` and `STL-1.0-AE` is X25519.
Each peer MUST generate an X25519 key pair from cryptographically secure
randomness.

### 3.3.4. Peer Random

TODO

### 3.3.5. Ed25519 Authentification

The client and server respectively sign over a commitment to all
session parameters.

TODO

### 3.3.6. Client Initial

TODO

### 3.3.7. Server Continue

TODO

### 3.3.8. Client Accept

TODO

### 3.3.9. Server Accept

TODO

## 3.4. Base Application Protocol

### 3.4.1. Application Packet

Encrypted application packets use the following layout.

| Offset | Field       | Type       |
|--------|-------------|------------|
| `0x00` | Base Header |            |
| `0x08` | `mac_tag`   | `[u8; 16]` |
| `0x18` | `seq`       | `u32`      |
| `0x1c` | `payload`   | `[u8; ?]`  |

The `mac_tag` the authentication tag.  `payload` contains application
data (raw or encrypted depending on features string).  `seq` is the
sequence number described in Section 3.4.2.

### 3.4.2. Sequence Number

Each encrypted application packet is tagged with a sequence number by
the client.  The sequence number is a 32-bit little endian integer.
The sequence number of the first application packet is one.  The
sequence number is incremented by one for every subsequent packet.

Each peer MUST reject sequence numbers greater than `0x7fff_ffff`.

## 3.5. Authenticated Application Protocol

The authentication application protocol in STLv1.0 is identified by
feature string `STL-1.0-A`.

### 3.5.1. MAC Key Expansion

TODO

### 3.5.2. Payload

TODO

## 3.6. Encrypted Application Protocol

The encrypted application protocol in STLv1.0 is identified by feature
string `STL-1.0-AE`.

### 3.6.1. AEAD Key Expansion

TODO

### 3.6.2. AEAD Cipher

STL encrypts application packets using the AES-128-GCM AEAD cipher.
(Authenticated encryption with associated data)

At a high-level, AEAD encryption produces a ciphertext and MAC tag
given an encryption key, plaintext to be encrypted, associated data
that is not encrypted, and an initialization vector.

### 3.4.3. Initialization Vector

It is assumed that the AEAD function is based on a stream cipher
construction.  In STL, a separate AEAD stream is created for every
encrypted application packet.  Stream ciphers such as AES-GCM
or ChaChaPoly require unique a unique value for the initialization
vector to be secure.  Reusing the same key and IV for distinct
streams is considered a "catastrophic failure" because allows it for
trivial recovery of the plaintext.

STL thus takes steps to ensure the IV for each packet is unique.

A new IV MUST be used for every new stream.  The IV size is 12 bytes.
It is laid out as follows.

| Offset | Field          | Type  |
|--------|----------------|-------|
| `0x00` | `udp_dst_port` | `u16` |
| `0x02` | `_pad_02`      | `u16` |
| `0x04` | `seq`          | `u64` |

## 5. Design Considerations

### 5.1. Static Layout

TODO

### 5.2. Session ID size

TODO

### 5.3. Unidirectional Mode

### 5.4. Cryptography

This draft of STL chooses a conservative set of widely deployed
cryptographic algorithms.  These algorithms are thought to have been
subjected to sufficient security research.  High quality open source
implementations are also available.

#### 5.5. Hash Functions

SHA-256 is extremely widespread and supports hardware acceleration
on x86_64 and armv8.  SHA-256 is vulnerable to length extension
attacks and thus requires the use of the HMAC-SHA256 construction for
key expansion.

It is proposed to use SHAKE-256 instead for all uses of a crypto-
graphic hash function.  (Except Ed25519 signatures, for which it is
unsafe to replace SHA-512)

The handshake cookie has particularly weak security requirements.
If (second-)preimage resistance of the underlying cryptography is
broken, only server-side DDoS mitigation is temporarily degraded.
The handshake mechanism itself remains secure.  The cookie hash
function is also in the "hot path" of a flood attack involving
repeated client initial packets.  The cookie hash function should
thus be chosen for maximum performance.

## 6. Implementation Guidance

### 6.1. Load Shedding

TODO
