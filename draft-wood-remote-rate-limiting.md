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

This document specifies the remote rate limiting protocol. It is designed
to enable collaborative rate limiting between privacy proxy providers and
target services. It is one mechanism amongst others for dealing with abusive
traffic that negatively affects target services.

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

Application proxy:
: A proxy that relays application messages between client and target,
  such as an OHTTP Oblivious Relay Resource.

Transport proxy:
: A proxy that relays end-to-end transport connections between client
  and target, such as a MASQUE proxy or WireGuard VPN proxy.

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

The proxy is assumed to be honest, since a malicious proxy could easily violate
client privacy by revealing the client's IP address to targets.

# Overview

Given the threat model in {{threat-model}}, the remote rate limiting (RRL) protocol
is based on the following assumptions:

1. The definition of abuse varies widely and depends on the target service.
   In other words, targets are authoritative for what is considered abusive traffic
   that negatively affects the target.
1. Rate limiting rules can only be expressed in terms of behavior that can be validated
   by both proxy and taget. Importantly, this means that targets can only express rules
   in terms of information that both parties know. In other words, targets cannot express
   rules in terms of information they do not know. As an example, it is not possible to
   express rules in terms of the number of requests per client if the target does not know
   how many clients are behind a particular client, nor if the proxy does not know the number
   of requests that a particular client is sending because the client's connection to the
   target is encrypted.
1. Proxies cannot trust targets which cannot authenticate themselves, as this can
   spoofed by attackers (malicious targets). Moreover, authenticating a target does
   not necessarily mean the target is honest; an authenticated target can still engage
   in malicious behavior. As such, the rate limiting protocol cannot leak information
   to the the privacy proxy that it does not already know. In particular, the protocol
   cannot depend on application data that is encrypted and unknown to the proxy.
   This ensures that the protocol cannot be misused by targets in an attempt to
   deanonymize clients.
1. IP addresses are not suitable for authentication and authorization decisions. In
   particular, this means that proxies cannot use target IP addresses to determine
   whether or not a particular target message is authenticated.

RRL assumes that proxies are public, i.e., that targets have some realiable means
of discovering or learning about a proxy. RRL is therefore not applicable to deployment
scenarios where the proxy is meant to be private or otherwise does not seek to make its
presence known to targets.

The protocol is divided into two phases: an offline registration phase ({{offline}}),
wherein targets obtain authentication material used for the online phase of the protocol,
and an online phase ({{online}}), wherein targets send rate limiting rules to the proxy
for enactment. Details about each phase are below.

## Offline Registration {#offline}

Registration is built on ACME, which is a protocol for obtaining authentication credentials
in the form of a certificate. Targets run the ACME protocol with a proxy to obtain
RRL authentication certificates. The certificate issued MUST have the Client Authentication
EKU configured, as it will be used for authenticating the client. They then use these
certificates in the online phase of the protocol.

[[NOTE: this is pretty straightforward -- what more would we actually need to say here?]]

## Online Rate Limit Enforcement {#online}

The online phase of RRL is based on HTTP. Targets, as HTTP clients, send messages to
a proxy Rule Resource to enact rate limit rules. Each rule is meant to limit the number
of acceptable connections or requests in a given time window. Rules are expressed using
the semantics in {{!RATE-LIMIT=I-D.ietf-httpapi-ratelimit-headers}}. In particular,
rate limits represent some limit, a policy (in terms of quota-units), and a time-based
condition after which the limit resets.

Proxies are configured with a URL for their RRL Rule Resource, e.g., "https://proxy.example/.well-known/rrl-rules".
Targets send POST messages to the proxy Rule Resource with a JSON object
({{!RFC8259, Section 4}}). {{authentication}} describes the mechanism by which
these requests are authenticated. Note that the reason that RRL relies on targets
pushing messages to proxies rather than proxies pulling from targets is to enable
on-demand application of rate limit rules.

[[NOTE: Pushing vs pulling rate limit rules is somewhat of an implementation detail -- the salient point is that these messages are authenticated]]

The contents of the Rule Resource message JSON object are defined in {{rrl-message}}.

| Field Name        | Value                                                  |
|:------------------|:-------------------------------------------------------|
| Target (optional) | Name of the target |
| RateLimit-Limit   | As defined in {{Section 5.1 of RATE-LIMIT}} except that parameters are not permitted, encoded as a JSON string. |
| RateLimit-Policy  | As defined in {{Section 5.2 of RATE-LIMIT}} except that parameters other than "unit" and "scope" are not permitted, encoded as a JSON string. |
| RateLimit-Reset   | As defined in {{Section 5.4 of RATE-LIMIT}} except that parameters are not permitted, encoded as a JSON string. |
{: #rrl-message title="RRL Rule Resource message"}

The "unit" parameter for the RateLimit-Policy field has the following permissible values:

- requests: This means the rate limit quota applies to HTTP requests. This is only enforceable
by a proxy if it can see requests, e.g., if it is an OHTTP Relay Resource (see {{Section 2 of OHTTP}}).
- connections: This means the rate limit quota applies to number of connections.
- bandwidth: This means the rate limit applies to the bandwidth consumed by a given connection or request.

The "scope" parameter for the RateLimit-Policy field has the following permissible values:

- total: This means the rate limit quota applies to all client traffic from the proxy to the target.
- single: This means the rate limit quota applies to individual client traffic from proxy to target.

Proxies MUST validate the values received in the Rule Resource message fields as described
in {{validation-and-enforcement}}. Proxies MAY ignore malformed Rule Resource messages and
respond to them with a 400 error. Proxies that validate and accept Rule Resource messages
respond to them with 200 OK messages. Proxies enforce these rules sent to the Rule Resource
as described in {{validation-and-enforcement}}.

Sample Rule Resource messages and the scenario to which they would apply are in {{applications}}.

### Authentication

Rule Resource messages are authenticated using credentials obtained during the offline registration phase.
There are several options for request authentication, including those below:

- Mutually authenticated TLS. In this option, targets establish a mutually authenticated TLS connection
  to the proxy, using their credentials, before sending any Rule Resource messages.
- Message signing. In this option, targets sign the content of the Rule Resource message using
  their credentials and produce a signature according to {{Section 3.1 of !MESSAGE-SIGNATURES=I-D.ietf-httpbis-message-signatures}}.
  Proxies verify the signature using the credentials according to {{Section 3.2 of MESSAGE-SIGNATURES}}.

[[OPEN ISSUE: The HTTP message signature keyid needs to contain enough information for the proxy to obtain the credentials used for verifying the signature, so it's tightly bound to the way registration works. This is not specified now and needs more thought.]]

Proxies authenticate requests using one of these options (or something with similar properties).

### Validation and Enforcement {#validation-and-enforcement}

Rule Resource message validity depends on the proxy's behavior and, in particular, whether
the proxy is an application or transport proxy. Application proxies can observe the client
request boundaries, but cannot view their contents. In contrast, transport proxies can only
observe connection boundaries and cannot view request boundaries. As such, validation rules
are different depending on the type of proxy, though there are some general Rule Resource
message validation steps that apply to both. These common rules are as follows:

- Check that the RateLimit-Reset field is not too far in the future.
- Check that the RateLimit-Limit is not too high.
- Check that the RateLimit-Limit, RateLimit-Policy, and RateLimit-Reset fields do not contain any unexpected parameters.

Beyond these general validation rules, the validation rules for application proxies are as follows:

- Check that the RateLimit-Policy "unit" parameter is present and has the value "requests" if the "scope" parameter is "total",
  else the "unit" parameter has the value "bandwidth." This has the effect of limiting total number of requests to
  the target or the size of any one request.

Likewise, beyond the general validation rules above, the validation rules for transport proxies are as follows:

- Check that the RateLimit-Policy "unit" parameter is present and has the value "connections" if the "scope" parameter is "total",
  else the "unit" parameter has the value "bandwidth." This has the effect of limiting total number of connections to
  the target or the bandwidth consumed by any one connection.

If all checks pass, then the message is considered valid.

Proxies can enforce valid Rule Resource messages but are not required to do so. Enforcing a message
means enacting rate limit rules uniformly across all clients to the target; Proxies MUST NOT apply
any rate limit actions with "scope" equal to "total" on a per-client basis.

## Limitations

The RRL protocol is limited in several important ways:

- RRL is only usable by targets which can authenticate themselves. This means that services which, for example,
  are not capable of running HTTPS because they have not yet implemented ACME support, will not be able to
  submit RRL messages.
- RRL does not support mitigation of attacks that span targets. This is because there is no straightforward
  way for proxies to authenticate and validate the legitimacy of rate limit requests from two independent
  targets.

# Applications

This section contains example applications of RRL that may be used to mitigate attacks enabled
or otherwise exacerbated by deployed proxy technologies.

## OHTTP DoS

A rule for mitigating OHTTP attacks, which seek to overwhelm the target with too many requests is below.
In this example, the policy expresses that the target can handle at most 100 requests per minute.

~~~
{
   "RateLimit-Limit": 100,
   "RateLimit-Policy": "60; scope='total'; unit='requests'",
}
~~~

Similarly, a rule for mitigating OHTTP attacks due to excessively large messages (larger than 1024B) is below.

~~~
{
   "RateLimit-Limit": 1024,
   "RateLimit-Policy": "60; scope='single'; unit='bandwidth'",
}
~~~

Since OHTTP is an application proxy protocol, it is not possible to safely express rate limits that limit
the number of requests from any one client, as this could be misused by malicious targets to de-anonymize
clients.

## Port Scanning DoS

A rule for mitigating port scanning attacks, which open many connections to the target server in a short
amount of time, is shown below. In this example, the threshold for port scanning is determined to be more
than 10 connections per minute.

~~~
{
   "RateLimit-Limit": 10,
   "RateLimit-Policy": "60; scope='total'; unit='connections'",
}
~~~

## Volumetric DoS

A rule for mitigating volumetric attacks, which sends excessive data to the target server in a short
amount of time, is shown below. In this example, the threshold for port scanning is determined to be more
than 65536 bytes per connection in a given minute.

~~~
{
   "RateLimit-Limit": 65536,
   "RateLimit-Policy": "1; scope='total'; unit='bandwidth'; w=60",
}
~~~

# Security Considerations {#security}

The RRL protocol was motivated by the need to ensure that operational security does not regress
in the name of client privacy. As such, the design of RRL intentionally restricts what sort of
security mitigations can be enacted in practice. A consequence of this is that certain classes of
attack may not be mitigated entirely by RRL. For example, in the case of OHTTP, it is not possible
to limit the number of requests per any single client, since enforcing such a policy might be abused
by malicious targets to de-anonymize clients. As such, RRL is complementary to other approaches
for dealing with attacks from individual clients, such as Privacy Pass.

The RRL protocol is designed to allow any target which can authenticate itself to send rate limit
rules to the proxy. Each rate limit rule does require the proxy to store state for enacting the rule.
As such, absent restrictions, malicious targets could abuse this mechanism to exhaust resources
on the proxy. In settings where this is a problem, proxies SHOULD apply some form of allow list
for targets to ensure that state does not grow unbounded.

# IANA Considerations {#iana}

This document has no IANA actions.

--- back

# Acknowledgements

This document was inspired by {{?OHTTP-RateLimit=I-D.rdb-ohai-feedback-to-proxy}},
which was focused on a variant of the problem addressed by this document and
tailored specifically to work within OHTTP, rather than alongside it.
