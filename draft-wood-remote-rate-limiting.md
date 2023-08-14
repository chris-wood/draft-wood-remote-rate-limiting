---
title: "The Remote Rate Limiting Protocol"
abbrev: Remote Rate Limiting Protocol
docname: draft-wood-remote-rate-limiting-latest
date:
category: std

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: caw@heapingbits.net

normative:

informative:
  WIREGUARD:
   title: "WireGuard: Next Generation Kernel Network Tunnel"
   target: https://www.ndss-symposium.org/wp-content/uploads/2017/09/ndss2017_04A-3_Donenfeld_paper.pdf

--- abstract

TODO

--- middle

# Introduction

Privacy proxy systems such as those built on MASQUE {{?CONNECT-UDP=RFC9298}},
Oblivious HTTP {{?OHTTP=I-D.ietf-ohai-ohttp}}, and WireGuard {{WIREGUARD}}.
provide one common feature: they mask a client's true IP address from the
targets to which clients interact with through these proxies. While this
offers meaningful privacy benefits to clients, it complicates common
operational security practices, such as IP addresses to help identify
and mitigate abusive traffic. Examples of abusive traffic include malicious
or otherwise malformed application data sent to targets through the proxies,
volumetric flooding attacks, and general (distributed) denial of service (DoS)
attacks. Naturally, absent some mechanism to apply granular rate limits
to individual client connections, targets are left with broad sweeping
mitigations that target the proxy service, such as IP-based rate limits,
and therefore affect all of its clients, including those which do not engage
in abusive behavior.

Proactively preventing abuse through (privacy-preserving) client authentication
is one alternative solution that can help mitigate such abuse in practice.
In particular, proxies can only admit service to authentiated clients, or 
targets can use privacy-preserving authentication protocols such as Privacy
Pass {{?PRIVACY-PASS=I-D.ietf-privacypass-architecture}} to admit client traffic.
Another type of solution might be in form of some "humanity check" such as a
CAPTCHA, with the intent of making sure that some human is responsible for client
traffic rather than an automated bot. However, there are several important ways
in which these proactive techniques can be inadequate in practice:

1. Authorization decisions based on client authentication do not attest to
client behavior -- they only attest to the client identity. This means that
authenticated clients can still engage in abusive behavior.
1. Authorization decisions based on humanity checks also do not attest to
client behavior. Humans interacting with an application can intentionally
initiate abusive traffic.

Reactive mitigation mechanisms complement proactive mechanisms. Reactive
mechanisms allow targets and proxy systems to work together to take
corrective action to minimize or remove abusive traffic.

This document describes a protocol that can implement one limited
form of reactive mitigation, called the remote rate limiting (RRL)
protocol. RRL builds on ACME to enable seamless registration and
configuration between proxies and targets. Targets use authentication
information from ACME to request rate limiting actions by the target.

# Terminology

{::boilerplate bcp14}

Client:
: An entity that interacts with remote services, called targets.

Target:
: A service or resource that clients interact with.

Proxy:
: An entity that sits between client and target.

# Threat Model

The remote rate limiting (RRL) protocol is based on the following threat model.
Clients are either honest or malicious. Honest clients do not engage in abusive
behavior, whereas malicious clients are carry out whatever behavior they wish,
including abusive behavior. Targets can also be honest or malicious. An honest
target will faithfully use the protocol to protect itself against abuse, whereas
a malicious target will try to use the protocol to carry out the following goals.

1. De-anonymize honest clients. The attacker aims to use the rate limiting protocol
   to violate whatever privacy properties the proxy purports to provide for its
   clients.
1. Disproportionately and negatively impact honest clients. The attacker aims to
   misuse the rate limiting protocol to single out honest clients and cause service
   disruption for them.

Malicious clients can engage in abusive behavior with the intent of disrupting service
for honest targets, or for negatively impacting the proxy service for other honest
clients.

XXX(caw): is the proxy honest or malicious? Probably honest, since otherwise it could just send abusive traffic or break client privacy

# Overview

Given the threat model in {{threat-model}}, the remote rate limiting (RRL) protocol
is based on the following assumptions:

1. The definition of abuse varies widely and depends on the target service.
   In other words, targets are authoritative for what is considered abusive traffic
   that negatively affects the target.
1. Proxies cannot trust targets which cannot authenticate themselves, as this can
   spoofed by attackers (malicious targets). Moreover, authenticating a target does
   necessarily mean the target is honest; an authenticated target can still engage
   in malicious behavior. As such, the rate limiting protocol cannot leak information
   to the the privacy proxy that it does not already know. In particular, the protocol
   cannot depend on application data that is encrypted and unknown to the proxy.
   This ensures that the protocol cannot be misused by targets in an attempt to
   deanonymize clients.
1. IP addresses are not suitable for authentication and authorization decisions. In
   particular, this means that proxies cannot use target IP addresses to determine
   whether or not a particular target message is authenticated.

1. XXX(caw): target should not be able to learn information based on the rule being enacted
 example: OHTTP with two clients vs OHTTP with 100 clients, and using rate limit to learn info about the set size

The protocol is divided into two phases: an offline registration phase ({{offline}}),
wherein targets obtain authentication material used for the online phase of the protocol,
and an online phase ({{online}}), wherein targets send rate limiting rules to the proxy
for enactment. Details about each phase are below.

## Offline Registration {#offline}

<!-- XXX(caw): describe how targets use ACME for registration -->

Registration is built on ACME, which is a protocol for obtaining authentication credentials
in the form of a certificate. Targets run the ACME protocol with a proxy to obtain
RRL authentication certificates. The certificate that's issued MUST have the clientAuthentication
EKU configured, as it will be used for authenticating the client. They then use these
certificates in the online phase of the protocol.

[[NOTE: this is pretty straightforward -- what more would we actually need to say here?]]

## Online Rule Generation {#online}

<!-- XXX(caw): describe how rules are encoded and how they're sent to the proxy -->

The online phase of RRL is based on HTTP. Targets, as HTTP clients, send messages to
a proxy Rule Resource to enact rate limit rules. Each rule is meant to limit the number
of acceptable connections or requests in a given time window. Rules are expressed using
the semantics in {{!RATE-LIMIT=I-D.ietf-httpapi-ratelimit-headers}}. In particular,
rate limits represent some limit, a policy (in terms of quota-units), and a time-based
condition after which the limit resets.

Proxies are configured with a URL for their RRL Rule Resource, e.g., "https://proxy.example/.well-known/rrl-rules".
Targets connect to the proxy using mutually authenticated TLS with the credentials
they obtained during the offline registration phase ({{offline}}). Once they connect,
they send POST messages to the proxy Rule Resource with a JSON object
({{!RFC8259, Section 4}}). The contents of this JSON object are defined in {{rrl-message}}.

| Field Name        | Value                                                  |
|:------------------|:-------------------------------------------------------|
| Target (optional) | Name of the target |
| RateLimit-Limit   | As defined in {{Section 5.1 of RATE-LIMIT}}, except that parameters are not permitted, encoded as a JSON string. |
| RateLimit-Policy  | As defined in {{Section 5.2 of RATE-LIMIT}}, except that parameters other than "unit" are not permitted, encoded as a JSON string. |
| RateLimit-Reset   | As defined in {{Section 5.4 of RATE-LIMIT}}, except that parameters are not permitted, encoded as a JSON string. |
{: #rrl-message title="RRL Rule Resource message"}

Proxies MUST validate the values received in the Rule Resource message fields before
using them and check if there are (significant) discrepancies with the expected ones.
This includes a RateLimit-Reset field moment too far in the future, a policy limit
too high, or fields with disallowed parameters. Proxies MAY ignore malformed Rule
Resource messages and respond to them with a 400 error.

The "unit" parameter for the RateLimit-Policy field has the following permissible values:

- requests: This means the rate limit quota applies to HTTP requests. This is only enforceable
by a proxy if it can see requests, e.g., if it is an OHTTP Relay Resource (see {{Section 2 of OHTTP}}).
- connections: This means the rate limit quota applies to number of connections.
- bandwidth: This means the rate limit applies to the bandwidth consumed by a given connection or request.

Proxies that validate and accept Rule Resource messages respond to them with 200 OK messages.

Sample Rule Resource messages and the scenario to which they would apply are in {{examples}}.

### Examples

XXX(caw): include the following:
- Simple OHTTP rule
- Port scanning rule
- Excessive bandwidth rule

## Limitations

<!-- XXX(caw): limited to targets which can authenticate themselves, and cannot detect attacks across targets -->

# Applications

XXX(caw): OHTTP, MASQUE (TCP/UDP), WireGuard (VPN)

# Security Considerations {#security}

TODO

# IANA Considerations {#iana}

<!-- This document has no IANA actions. -->

--- back

# Acknowledgements

This document was inspired by {{?OHTTP-RateLimit=I-D.rdb-ohai-feedback-to-proxy}},
which was focused on a variant of the problem addressed by this document and
tailored specifically work within OHTTP, rather than alongside it.