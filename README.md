<a name="readme-top"></a>

<div align="center">
  <p align="center">
    <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=70&duration=2000&pause=1000&color=946DF7&center=true&width=1000&height=150&lines=%3C%7C%E2%80%94%E2%80%94%E2%80%94%E2%80%94%E2%80%94+proXXy+%E2%80%94%E2%80%94%E2%80%94%E2%80%94%E2%80%94%7C%3E" alt="Typing SVG" /></a>
  
  <p align="center">
    <strong>proXXy</strong> is a powerful tool designed for acquiring and managing a vast quantity of proxies. It is used to gather, organize, and procure HTTP/S, SOCKS4, and SOCKS5 proxies. They can be used for web scraping, penetration testing, bypassing censorship, and many other tasks!
  </p>
  
  <p align="center">
    The software is currently capable of retrieving over 500,000 proxies from many different sources.
  </p>
  
  <p align="center">
    This project is for educational purposes only— Please do not use this for illegal activities.
  </p>
</div>

---

## Installation

- Clone the repository:

```bash
git clone https://github.com/0xSolanaceae/proXXy.git
```

- Navigate to project directory:

```bash
cd proXXy
```

- Install dependencies with uv (creates a virtual environment and uv.lock):

```bash
uv sync
```

If you don't have uv installed, see install instructions at https://docs.astral.sh/uv/getting-started/installation/

## Usage

- Run with uv (no need to activate a virtualenv manually):

```bash
uv run python src/proXXy.py
```

- Running the program without flags results in only scraping, as checking is disabled by default.

The program will modify four files in the `output/` directory with your proxies:

- `HTTP.txt`
- `HTTPS.txt`
- `SOCKS4.txt`
- `SOCKS5.txt`

 with a logfile (`error.log`) with warnings/errors.

## Flags

Syntax for running proXXy is as follows:

```bash
uv run python src/proXXy.py [-h] [--validate] [--update] [--version]
```

1. `-V, --validate`: This flag enables proxy validation. The scraper will look to validate the scraped proxies by checking their accessibility.

2. `-u, --update`: This flag updates the project. Cannot be used in conjunction with any other flag.

3. `-h, --help`: Use this flag to spit out a help menu.

4. `-v, --version`: Use this flag to spit out `proXXy.py`'s version.

```bash
usage: proXXy.py [-h] [--validate] [--update] [--version]

A super simple asynchronous multithreaded proxy scraper;
scraping & checking ~500k HTTP, HTTPS, SOCKS4, & SOCKS5 proxies.

options:
  -h, --help      show this help message and exit
  --validate, -v  Flag to validate proxies after scraping (default: False)
  --update, -u    Flag to run the update script and then exit
  --version, -V   Print the version of the script and exit
```

## Planned Features

- Fix Unix-like compatibility errors. `proXXy` currently does not support unix-like proxy checking.
- Allow the user to choose the number of threads they'd like to use with flags, & provide the user recommended values based on their hardware.
- Implement SOCKS4 & SOCKS5 testing.
- Proxy sorting instead of hardcoding.
- Discerning between Elite, Anonymous, and Transparent anonymity classes of proxies.

## Support

Need help and can't get it to run correctly? Open an issue or contact me [here](https://solanaceae.xyz/).

## Sponsorship

If you like what I do, buy me boba so I can continue developing this tool and others!
[Ko-Fi](https://ko-fi.com/solanaceae)

## Changelog

[Release v2.6](https://github.com/0xSolanaceae/proXXy/releases/tag/v2.6)
- Full changelog: https://github.com/0xSolanaceae/proXXy/compare/v2.5...v2.6

---

## License

This project is licensed under the GNU General Public License v3.0 License. See the `LICENSE` file for more information.

## HTTP/2 validator (strict) — end-to-end H2 required

The validator now requires proxies to pass a real HTTP/2 fetch to the target URL before they are admitted to the pool. This prevents enabling proxies that later fail curl with “HTTP/2 stream was not closed cleanly: CANCEL (err 8)”.

Implementation details
- Code: see [src/validator.py](src/validator.py) and the new [def _check_one_http2()](src/validator.py:680).
- TLS preflight: [def _os_trust_tls_preflight()](src/validator.py:59) performs CONNECT + OS-trust TLS handshake and enforces ALPN “h2” when strict mode is on.
- Dependency: httpx with HTTP/2 support (declared in [pyproject.toml](pyproject.toml)).

Defaults (can be overridden via environment)
- PROXXY_VALIDATOR_HTTP2_ENABLE=1
  - Attempt HTTP/2 validation for HTTPS targets.
- PROXXY_VALIDATOR_HTTP2_REQUIRED=1
  - Strict mode: fail proxy if ALPN doesn’t negotiate “h2” or the HTTP/2 request fails streaming thresholds.
- Other validator tunables (already present and still honored):
  - PROXXY_VALIDATOR_MIN_BYTES (default 4096)
  - PROXXY_VALIDATOR_TTFB_SECONDS (default 0.8)
  - PROXXY_VALIDATOR_READ_SECONDS (default 1.0)
  - PROXXY_VALIDATOR_MIN_BPS (default 16384)
  - PROXXY_VALIDATOR_DOUBLE_CHECK (default 1)
  - PROXXY_VALIDATOR_SECOND_URL (optional second URL)
  - PROXXY_VALIDATOR_OS_TRUST_PREFLIGHT (default 1)
  - PROXXY_VALIDATOR_REQUIRE_HTTP11 applies only to the HTTP/1.1 fallback path (not used when H2 is required)

Install dependencies
- Using uv (recommended):
  - uv sync
- Using pip (if not using uv’s environment):
  - pip install "httpx[http2]>=0.27.0"

Operational notes
- Strict H2 applies to HTTPS targets only (no h2c).
- If httpx is missing at runtime, the validator emits a clear error reason and rejects the proxy (reason: h2_dep:httpx).
- This change is backward-compatible for non-HTTPS URLs and for deployments that set PROXXY_VALIDATOR_HTTP2_ENABLE=0.

Troubleshooting
- curl error 92 during client usage should be filtered out by the validator. If encountered post-change, ensure:
  - You ran uv sync (or installed httpx[http2]) so H2 can be exercised.
  - Your PROXXY_VALIDATION_URL actually supports HTTP/2 at the origin (ALPN must return “h2”).