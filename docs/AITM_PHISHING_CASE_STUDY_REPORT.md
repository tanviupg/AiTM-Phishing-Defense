# Adversary-in-the-Middle (AiTM) Phishing Case Study & Technical Defense Report

**Track H:** Adversary-in-the-Middle Phishing Case Study  
**DeepCytes Cyber Labs UK — Fellowship Technical Problem Statements (p. 45 of 59)**  
**Authors:** Tanvi, Devyani, Vaishnavi, Josna  
**Repository:** [https://github.com/tanviupg/AiTM-Phishing-Defense](https://github.com/tanviupg/AiTM-Phishing-Defense)

---

## Executive Summary

Traditional phishing attacks rely on static, deceptive web forms designed to mimic legitimate login interfaces. When multi-factor authentication (MFA)—such as SMS one-time passwords (OTP) or mobile authenticator apps—is introduced, conventional credential harvesting collapses because transient one-time passcodes cannot be reused after their short expiration window.

**Adversary-in-the-Middle (AiTM) phishing** represents a generational leap in social engineering and credential theft. Rather than hosting a static clone of a target website, the threat actor deploys a transparent **reverse proxy** (using platforms such as *Evilginx*, *Modlishka*, or *Muraena*) directly between the victim’s browser and the authentic Identity Provider (IdP) (e.g., Microsoft Entra ID, Google Workspace, Okta). The reverse proxy relays HTTP requests and responses live and in real time.

When the victim completes username/password entry and satisfies their MFA challenge, the authentic IdP issues authenticated **session cookies or OAuth bearer tokens**. The reverse proxy intercepts these session tokens directly from the HTTP transport layer (`Set-Cookie` response headers) and stores them. The threat actor then injects the stolen session cookie into their own browser, completely bypassing the victim's password, MFA factor, and device context.

This report documents the architectural mechanics of AiTM reverse proxies, explains why traditional perimeter blocklists and heuristic page scanners fail to detect them, presents a multi-signal detection framework, and establishes the technical blueprint for **phishing-resistant FIDO2/Passkey and cryptographic token-binding defenses**.

---

## 1. Real-World Threat Landscape & Case Studies

### 1.1 Storm-0832 (DEV-1101) & Large-Scale Phishing-as-a-Service (PaaS)
Public reporting from Microsoft Threat Intelligence, Mandiant, and the Cybersecurity and Infrastructure Security Agency (CISA) highlights the explosive growth of **Phishing-as-a-Service (PaaS)** kits utilizing reverse-proxy architectures:

* **Storm-0832 (DEV-1101):** An open-market PaaS operation that sells automated AiTM phishing kits configured for Microsoft 365. For a modest subscription fee, threat actors gain access to automated domain-generation algorithms (DGA), automated TLS certificate provisioning via Let's Encrypt, and pre-packaged "phishlets" targeting corporate Single Sign-On (SSO) portals.
* **Widespread Enterprise Compromise:** Microsoft disclosed that a single AiTM campaign orchestrated via DEV-1101 targeted more than **10,000 enterprise organizations**, attempting session-hijacking against corporate email accounts to execute Business Email Compromise (BEC) and unauthorized financial wire fraud.
* **Post-Compromise Automation:** Once session cookies are stolen, automated scripts immediately access the victim's mailbox via the Microsoft Graph API, create malicious inbox forwarding rules to conceal attacker communications, and conduct secondary internal phishing attacks against the victim's colleagues.

```
+---------------+           +--------------------+           +----------------------+
|  Victim User  | <=======> |  AiTM Reverse      | <=======> |  Legitimate Identity  |
|  Workstation  |  HTTPS    |  Proxy (Evilginx)  |  HTTPS    |  Provider (Entra ID)  |
+---------------+           +--------------------+           +----------------------+
                                      |
                      Intercepts HTTP "Set-Cookie"
                      (session_token / ESTSAUTH / ESTSAUTHPERSISTENT)
                                      |
                                      v
                             +------------------+
                             | Stolen Credential| ===> Attacker Replays Token
                             | & Session Vault  |      (Full Account Hijack)
                             +------------------+
```

---

## 2. Technical Mechanics of Transparent Reverse Proxies

### 2.1 Dynamic Request & Response Forwarding
Unlike traditional credential harvesting forms that execute a simple `POST` request to an attacker script, an AiTM proxy acts as a man-in-the-middle gateway:

1. **Client Handshake:** The victim clicks an email phishing link and connects to `https://login.contoso-security.com` (the attacker-controlled proxy).
2. **Upstream Tunneling:** The proxy terminates the incoming TLS connection and immediately initiates an outbound TLS connection to the genuine authentication service (e.g., `https://login.microsoftonline.com`).
3. **MIME-Type & String Substitution:** As the genuine HTML, CSS, JavaScript, and JSON payloads travel from the real IdP through the proxy back to the user, the proxy dynamically rewrites canonical domain names within the body text and HTTP headers:
   $$\text{login.microsoftonline.com} \longrightarrow \text{login.contoso-security.com}$$
   This ensures that subsequent API calls (such as credential submissions, telemetry beacons, and challenge requests) remain directed through the proxy rather than jumping directly to the authentic host.
4. **Transparent MFA Relay:** When the real IdP prompts for an SMS OTP, a TOTP authenticator code, or a mobile push prompt, the proxy forwards this exact form to the victim. The victim enters their valid OTP, which the proxy submits upstream within seconds.
5. **Session Interception:** Upon successful authentication, the genuine service responds with an HTTP `302 Found` or `303 See Other` containing `Set-Cookie` headers with authenticated session tokens (e.g., `ESTSAUTH`, `ESTSAUTHPERSISTENT`, `session_token`). The proxy captures these cookies from the header stream before relaying the redirect to the user.

---

## 3. Why AiTM Evades Classic Anti-Phishing Defenses

Traditional email security gateways (SEG), Web Content Filters, and Secure Web Gateways (SWG) rely on three primary defensive paradigms: URL blocklists, domain reputation scoring, and static webpage visual analysis. **AiTM reverse proxies systematically evade all three.**

### 3.1 Failure of URL & Domain Blocklists
* **Zero-Day Lookalike Domains:** Threat actors register newly created domains (NRDs) hours before launching an email campaign. Because blocklists (e.g., Spamhaus, Google Safe Browsing) require hours or days to crawl, analyze, and categorize malicious URLs, the attack window is completed before the domain appears on any list.
* **Dynamic Cloaking & IP Geofencing:** Advanced AiTM kits detect automated security crawlers (e.g., Microsoft Defender, Palo Alto WildFire) by inspecting User-Agent strings, checking for headless browser flags (`navigator.webdriver`), and verifying the source IP against known security vendor ASN ranges. If a crawler is detected, the proxy displays a benign 404 page or redirects to the authentic company homepage. Only legitimate victims receive the active phishing proxy.

### 3.2 Failure of Heuristic & Visual Scanners
* **100% Authentic Web Code:** Traditional heuristic engines look for mismatched CSS, suspicious form submission targets, or low-quality page clones. In an AiTM attack, **the HTML and CSS rendered in the browser are 100% genuine code directly fetched from Microsoft or Google**. Heuristic content scanners see authentic Microsoft copyrights, authentic company branding, and authentic cryptographic challenges.

### 3.3 The Core Root Cause: Channel De-coupling
Traditional authentication methods authenticate the user over whatever channel the user’s browser opened. The protocol does not bind the authentication assertion to the specific Fully Qualified Domain Name (FQDN) in the browser's address bar. Thus, a password or SMS code is universally valid whether sent to `microsoft.com` or `attacker-proxy.com`.

---

## 4. Multi-Signal Detection Architecture

To detect AiTM phishing before session tokens can be abused, security telemetry must be gathered across transport, redirect, and temporal behavioral layers.

### 4.1 Signal 1: Transport & TLS Certificate Telemetry
Phishing proxies terminate user TLS connections. Inspecting client-reported transport parameters reveals critical anomalies:
* **Certificate SAN Mismatch:** The presented certificate Subject Alternative Names (SAN) do not match the expected Identity Provider domain (e.g., `*.phish-proxy.com` presented when accessing an IdP service).
* **Untrusted Intermediate / Self-Signed Roots:** Proxies using rogue or automated staging CAs diverge from enterprise trust roots.
* **SNI Discrepancies:** Divergence between the client TLS Server Name Indication (SNI) header and the target endpoint host.

### 4.2 Signal 2: Redirect-Chain & Hop Traversal Analysis
Legitimate Single Sign-On typically follows strict canonical patterns (e.g., Service Provider $\rightarrow$ Identity Provider $\rightarrow$ Service Provider). AiTM proxies introduce:
* **Cyclic Redirect Loops:** Traversing back through intermediary domains (e.g., `SP -> Proxy -> IdP -> Proxy`).
* **Excessive Redirect Counts:** Traversal counts exceeding standard thresholds ($>3$ hops).
* **High Transition Complexity:** Traversing multiple distinct organizational entities within a single authentication sequence.

### 4.3 Signal 3: Temporal Session Correlation & Replay Signatures
Tracking authentication context over time enables SOC analysts to spot stolen session cookie replay:
* **Rapid Multi-IP Alternation:** Identical session tokens presenting requests from two geographically disparate IP addresses within minutes (e.g., user in London and attacker proxy in Frankfurt).
* **Client Platform Divergence:** A session initiated from Windows 11 / Edge suddenly presenting API calls from Linux / Python within the same session ID.
* **Token-Binding Cryptographic Failure:** Explicit failure or omission of proof-of-possession binding assertions.

---

## 5. Phishing-Resistant Authentication Hardening

The ultimate defense against Adversary-in-the-Middle attacks is **eliminating shared secrets and relayable bearer tokens entirely**.

```
+------------------------------------------------------------------------------------------+
| THE FIDO2 / WEBAUTHN ORIGIN-BINDING INVARIANT                                            |
|                                                                                          |
| 1. User visits https://login.microsoft.phish-proxy.com (AiTM Proxy)                     |
| 2. Proxy solicits WebAuthn assertion for rpId: "login.microsoft.com"                     |
| 3. Browser Kernel executes navigator.credentials.get():                                 |
|    - Inspects active TLS connection: Host is "login.microsoft.phish-proxy.com"           |
|    - Generates clientDataJSON: { "origin": "https://login.microsoft.phish-proxy.com" }   |
| 4. Security Check:                                                                       |
|    - rpId "login.microsoft.com" is NOT a registrable suffix of "phish-proxy.com"        |
|    ===> BROWSER REFUSES TO SIGN AND THROWS A SecurityError EXCEPTION!                    |
|    ===> The authenticator is never touched, and the proxy receives NOTHING.              |
+------------------------------------------------------------------------------------------+
```

### 5.1 FIDO2 / WebAuthn & Passkeys (NIST SP 800-63B AAL3)
* **Mathematical Immunity:** Because authentication signatures are generated over `clientDataJSON` containing the browser-verified origin, signatures produced on an attacker's domain are cryptographically invalid on the genuine domain.
* **Zero Shared Secrets:** Private keys never leave the hardware Security Key (YubiKey) or Platform TPM / Secure Enclave (Windows Hello / Apple Touch ID).

### 5.2 Cryptographic Token Binding (OAuth 2.0 DPoP — RFC 9449)
Even if an attacker intercepts an application-layer access token via an HTTP proxy, **Demonstrating Proof-of-Possession (DPoP)** binds the token to a private key generated in the legitimate client's browser storage (IndexedDB / WebCrypto).
* Every API request requires a newly signed `DPoP` HTTP header containing the request URI, HTTP method, and timestamp.
* When the threat actor attempts to replay the stolen bearer token from their command-and-control server, the API resource server rejects the request with `401 Unauthorized` because the attacker does not possess the client's non-exportable private key.

---

## 6. Enterprise Hardening Checklist

| Priority | Category | Control Title | Implementation Action | NIST / CISA Reference |
|---|---|---|---|---|
| **CRITICAL** | IDP_POLICY | Enforce Phishing-Resistant MFA | Mandate FIDO2 hardware keys or platform passkeys for all administrators. | NIST SP 800-63B § 5.1.7 |
| **CRITICAL** | WEBAUTHN | Strict Relying Party ID Origin Validation | Verify `clientDataJSON.origin` byte-for-byte against expected FQDN. | W3C WebAuthn § 7.2 |
| **CRITICAL** | TOKEN_BINDING | Deploy OAuth 2.0 DPoP (RFC 9449) | Bind API access tokens to asymmetric client key pairs. | RFC 9449 |
| **HIGH** | IDP_POLICY | Deprecate SMS & Voice OTP | Disable out-of-band cellular OTP in tenant authentication policies. | NIST SP 800-63B § 5.1.3 |
| **HIGH** | SESSION | Implement Continuous Access Evaluation (CAE) | Enable near-instantaneous token revocation upon critical security events. | NIST SP 800-63B § 7 |
| **HIGH** | CONDITIONAL | Require Compliant / Managed Device Trust | Restrict sensitive cloud resource access to MDM-enrolled devices. | CISA Zero Trust Pillar |
| **MEDIUM** | TRANSPORT | Enforce HSTS Preloading & DNS CAA | Mandate strict HTTPS across all subdomains with browser preload lists. | NIST SP 800-52 Rev 2 |

---

## 7. Conclusion

Adversary-in-the-Middle phishing has rendered classic email blocklists and traditional MFA (SMS, email codes, standard push notifications) obsolete against motivated threat actors. By deploying a comprehensive defensive strategy—combining **multi-signal heuristic detection in the SOC pipeline**, **simulated containment automation**, and **phishing-resistant FIDO2/passkey authentication**—organizations can mathematically eliminate their vulnerability to credential theft and session hijacking.
