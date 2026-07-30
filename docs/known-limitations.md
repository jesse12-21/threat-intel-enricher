# Known Limitations

Findings from testing this codebase against its own toolchain. Each entry records what was tested, what was observed, and what was done about it.

Two of these are bugs that shipped and survived for months. Both were caught by writing the tests that did not exist, which is the point.

---

## 1. The retry decorator never retried

**Affects:** all three remote enrichers
**Found:** 2026-07-29
**Status:** fixed

Every enricher carried what looked like sound retry logic:

```python
@retry(
    stop=stop_after_attempt(3),
    retry=retry_if_exception_type(aiohttp.ClientError),
    reraise=True,
)
async def enrich(self, ioc: IOC) -> EnrichmentResult | None:
    try:
        async with self.session.get(...) as response:
            ...
    except aiohttp.ClientError as e:
        return EnrichmentResult(..., error=str(e))
```

The decorator was attached to `enrich()`, and `enrich()` caught `aiohttp.ClientError` internally. Tenacity only retries on exceptions that **escape** the decorated function, so the exception was swallowed before tenacity could observe it. Measured against a session that always raised a transport error:

```
HTTP attempts made : 1
retry decorator says: stop_after_attempt(3)
>>> RETRY NEVER FIRED
```

One attempt where three were configured. A transient network blip produced a permanent "enrichment failed" result, and the exponential backoff never ran.

**Fixed** by splitting the HTTP call into a `_fetch()` method that carries the decorator and lets errors propagate, leaving `enrich()` to convert an error into a result only after all attempts are spent. Verified with the same probe:

```
HTTP attempts made : 3
>>> retry fired (3 attempts)
```

`tests/test_enrichers.py::test_retry_actually_fires_on_transport_error` asserts the attempt count directly, so a future refactor that reintroduces the swallow will fail rather than silently regress.

---

## 2. The URLhaus enricher had been returning 401 for over a year

**Affects:** `enrichers/urlhaus.py`
**Found:** 2026-07-29
**Status:** fixed

abuse.ch made authentication mandatory on **30 June 2025** across URLhaus, ThreatFox, and MalwareBazaar. Unauthenticated requests are rejected.

The enricher sent no headers at all:

```python
async with self.session.post(endpoint, data=form_data) as response:
```

`.env.example` had no URLhaus key, `config.py` did not model one, and its docstring stated that "URLhaus doesn't need an API key, so enrichment always works". The README's source table said `API Key Required: No`.

So one of three enrichment sources had been silently dead since the change, and every artifact in the repository asserted it was fine.

**Fixed** by adding the `Auth-Key` header, a `URLHAUS_API_KEY` setting, an `.env.example` entry, and a 401 handler whose message names the remedy:

```
URLhaus rejected the Auth-Key. abuse.ch requires authentication
since 2025-06-30; get a free key at https://auth.abuse.ch/
```

`test_urlhaus_sends_auth_key` asserts the header is present on every request.

**The general lesson:** a third-party API is a dependency that changes without a version bump. This one broke quietly, and nothing in the codebase or its tests would have noticed.

---

## 3. The toolchain was configured but never enforced

**Affects:** repository-wide
**Found:** 2026-07-29
**Status:** fixed

`pyproject.toml` configured ruff, mypy in strict mode, and pytest with coverage. There was no CI. Running them revealed:

| Check | Before | After |
|---|---|---|
| `pytest` | 29 passed | 102 passed |
| `ruff check` | **47 errors** | clean |
| `mypy --strict` | clean | clean |
| Coverage | **23%** | **89%** |

mypy strict passing across the whole package was genuinely good and is worth stating plainly. The rest was aspiration.

The coverage distribution mattered more than the number:

```
models.py        99%
correlator.py    97%
scoring.py       91%
everything else   0%
```

The three tested modules were the three pure-logic ones. Every module that touched I/O — all enrichers, the ingester, the pipeline, both reporters, the CLI, config — had no tests at all. That is the ordinary shape of a test suite written without HTTP mocking, and it is exactly where findings 1 and 2 lived.

`tests/conftest.py` now provides a `FakeSession` that stands in for `aiohttp.ClientSession`, which is the piece whose absence made the enrichers feel untestable.

---

## 4. What CI validates, and what it does not

| Validated | Not validated |
|---|---|
| Tests pass on Python 3.11 and 3.12 | That live APIs still behave as mocked |
| Coverage stays above 85% | That enrichment verdicts are *correct* |
| ruff and mypy strict clean | Rate-limit behaviour under real load |
| Every component implements its base class | STIX conformance against a validator |
| CLI is invocable | Report rendering quality |

The first row of the right-hand column is the important one. **Every enricher test mocks the HTTP layer, so the suite proves the code handles a given response shape — not that the API still returns that shape.** Finding 2 is precisely a case where the mocks would have kept passing while production was broken.

Closing that needs contract tests against live APIs on a schedule, which requires storing credentials in CI. That is a deliberate omission for a public portfolio repository rather than an oversight, but it is a real gap.

---

## 5. STIX output is emitted, not consumed, and not validated

**Affects:** `reporters/stix_reporter.py`

The reporter produces STIX 2.1 bundles containing `identity`, `indicator`, and `note` objects. Three honest limits:

- **No TAXII.** Bundles can be imported into a TIP or pushed to an existing TAXII endpoint, but this project does not implement a TAXII server. That is a hosting concern rather than a serialisation one.
- **No import path.** STIX goes out; nothing comes in. Consuming a STIX feed as an enrichment source is a natural next step and is not built.
- **Structure is asserted by tests, not by a validator.** Bundles are constructed without the `stix2` library to keep the dependency footprint small. The tests check object types, spec version, pattern syntax, and ID stability, but a conformance validator would check more.

Campaigns are deliberately not serialised. STIX models a campaign as an SDO carrying attribution semantics this pipeline does not establish, and emitting under-evidenced campaign objects into a shared TIP is worse than omitting them.

---

## 6. Enrichment coverage gaps

| Gap | Detail |
|---|---|
| **RFC 5737 addresses are not enrichable** | Python's `ipaddress` classifies documentation ranges (198.51.100.0/24, 203.0.113.0/24, 192.0.2.0/24) as private, so ingesters correctly skip them. Sample data using those ranges produces no IP indicators — surprising until you know it. Asserted in `test_documentation_ranges_are_not_enrichable`. |
| **CVE indicators need version detection** | The KEV and EPSS enrichers act on CVE identifiers. The Nmap ingester extracts them from service version strings, which requires the scan to have run with `-sV` and a script that emits CVE IDs. Without that, no CVEs are produced. |
| **KEV absence is not safety** | The catalog records *confirmed* exploitation, not all exploitable vulnerabilities. A CVE missing from KEV may simply not have been observed yet. |
| **EPSS misses are usually recency** | An unscored CVE is typically too new to have been scored rather than low risk. |
| **Source weights are judgement, not measurement** | `SOURCE_WEIGHTS` in `scoring.py` reflects reasoning about data quality. They have not been calibrated against a labelled dataset, and doing so properly would require ground truth this project does not have. |
| **No caching between runs** | Each invocation re-queries every source. The KEV catalog is cached within a run but not across them, so repeated runs on overlapping data waste quota. |

---

*Findings recorded while testing against Python 3.12, pytest 9.1, ruff, and mypy 1.7 in strict mode. CI enforces all four on every push.*
