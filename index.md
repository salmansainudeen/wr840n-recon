---
layout: default
---

# TP-Link TL-WR840N (v6) — Recon & Login-Crypto Study

A beginner security-research writeup documenting **passive reconnaissance** and
**client-side login-crypto reverse engineering** of a TP-Link TL-WR840N router,
performed on a **self-owned, isolated lab device**. No exploitation was performed.

> ⚠️ **Scope / ethics.** Everything here was done against hardware I own, on an
> isolated network, for learning. Do not run any of this against devices or
> networks you do not own or lack written authorization to test. Published for
> educational purposes.

## Target

| Field | Value |
|---|---|
| Model | TL-WR840N |
| Hardware revision | v6 (`00000007`) |
| Firmware | `0.9.1 4.18 v0002.0 Build 231121 Rel.2977n` (built 2023-11-21) |
| Mgmt IP (lab) | 192.168.0.104 |

## Method & findings

All findings came from **reading** pages/JS and a handful of **benign HTTP
requests** (no payloads, no auth attempts).

| # | Finding | How obtained |
|---|---------|--------------|
| 1 | Model/rev/firmware identified | Admin page + version-comparison script |
| 2 | Most 2018-era CVEs likely patched on fw 4.18; two need manual verification | `wr840n_cve_check.py` |
| 3 | No `Server:` response header (stripped banner) | Header read |
| 4 | Server enforces a `Referer` check on static assets (403 without it) | Asset fetch |
| 5 | Login UI is JavaScript-rendered (`document.title = modelName`) | Login page source |
| 6 | Login uses **hybrid RSA-512 + AES-128-CBC**; credential proof is **unsalted MD5(user+pass)** | Reading `tpEncrypt.js` / `encrypt.js` |
| 7 | RSA public key (`ee`,`nn`) + rotating `seq` served **pre-auth** at `/cgi/getParm` | One benign POST |
| 8 | **Observation:** 512-bit RSA is cryptographically obsolete (noted, not attacked) | Key length from `nn` |

### CVEs reviewed (version-based, not confirmed by exploitation)

- **CVE-2018-11714** — auth bypass / config download (EDB-44781). Affected fw
  `≤ 0.9.1 4.16`; this unit runs 4.18 → **likely patched**.
- **CVE-2019-15060** — traceroute OS command injection → **verify manually**.
- **CVE-2018-15172** — buffer overflow via long `Authorization` header → **verify manually**.
- **CVE-2021-46122**, **CVE-2022-26639..26642** — target the **v6.20** revision →
  **not applicable** to this v6 unit.

## The login crypto (reconstructed)

1. Client fetches server RSA public key (`ee`,`nn`) and `seq` from `/cgi/getParm` (pre-auth).
2. `hash = MD5(username + password)` (unsalted).
3. Client generates a random AES-128 key + IV (16 decimal digits each).
4. Request body is **AES-128-CBC / PKCS7** encrypted → base64 (`data`).
5. A signature string `key=..&iv=..&h=<md5>&s=<seq+len>` is **RSA-512 / PKCS#1 v1.5**
   encrypted in 53-byte blocks, hex output, each block zero-padded to 128 hex chars (`sign`).
6. `data` + `sign` are what the firmware expects. (The exact `/cgi/login` submission
   wiring lives in `lib.js` / `root.js` and was intentionally left unreconstructed.)

## Tools in this repo

### `wr840n_cve_check.py`
Passive, version-based CVE presence checker. Parses the firmware/hardware strings,
compares against a small CVE database, and prints verdicts
(`LIKELY PATCHED` / `VERIFY MANUALLY` / `NOT APPLICABLE` / `POTENTIALLY VULNERABLE`).
Optional `--fingerprint <ip>` does a single benign `GET`.

```bash
python3 wr840n_cve_check.py
python3 wr840n_cve_check.py --fingerprint 192.168.0.104
```

### `tp_login_crypto.py`
A faithful Python port of the router's client-side login crypto
(`tpEncrypt.js` + `encrypt.js`). It reproduces the browser's `data`/`sign`
generation and **prints** them — it does **not** submit a login. Requires the
`cryptography` package.

```bash
python3 tp_login_crypto.py
```

## Lessons

- Public CVEs are a **hypothesis**, not a guarantee — version ranges decide applicability.
- Detection (version comparison) is a first-class technique, separate from exploitation.
- Embedded web UIs often ship readable client-side crypto that can be ported 1:1 —
  a durable skill that outlives any single CVE.

---
*Educational security research against self-owned hardware.*
