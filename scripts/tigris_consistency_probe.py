#!/usr/bin/env python3
"""
Tigris consistency probe — stdlib-only.

Probes whether `X-Tigris-Consistent: true` on a GET against a Global bucket
routes to the leader, and whether plain GETs against an object pinned to a
distant region differ in routing or body.

Requires only the Python standard library. SigV4 signed against the AWS_*
env vars (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, optionally
AWS_SESSION_TOKEN).

Limitation: from a single client region we cannot directly observe a stale
window. We pin writes to a far region (default nrt) and compare plain vs
consistent reads via response bodies, response headers, and latency.
"""

import argparse
import datetime
import hashlib
import hmac
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ENDPOINT_HOST = "fly.storage.tigris.dev"
REGION = "auto"
SERVICE = "s3"
ALGO = "AWS4-HMAC-SHA256"


def _hmac(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret, datestamp, region, service):
    k = _hmac(("AWS4" + secret).encode("utf-8"), datestamp)
    k = _hmac(k, region)
    k = _hmac(k, service)
    return _hmac(k, "aws4_request")


def _canonical_uri(bucket, key):
    parts = [bucket] + (key.split("/") if key else [])
    return "/" + "/".join(urllib.parse.quote(p, safe="") for p in parts)


def s3_request(method, bucket, key, payload, extra_headers,
               access_key, secret_key, session_token=None, timeout=30):
    now = datetime.datetime.now(datetime.timezone.utc)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")

    canonical_uri = _canonical_uri(bucket, key)
    payload_hash = hashlib.sha256(payload).hexdigest()

    headers = {
        "host": ENDPOINT_HOST,
        "x-amz-date": amzdate,
        "x-amz-content-sha256": payload_hash,
    }
    if session_token:
        headers["x-amz-security-token"] = session_token
    for k, v in extra_headers.items():
        headers[k.lower()] = v

    sorted_keys = sorted(headers)
    signed_headers = ";".join(sorted_keys)
    canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in sorted_keys)
    canonical_request = (
        f"{method}\n{canonical_uri}\n\n"
        f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )

    scope = f"{datestamp}/{REGION}/{SERVICE}/aws4_request"
    string_to_sign = (
        f"{ALGO}\n{amzdate}\n{scope}\n"
        f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    )
    sig = hmac.new(
        _signing_key(secret_key, datestamp, REGION, SERVICE),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    headers["authorization"] = (
        f"{ALGO} Credential={access_key}/{scope},"
        f"SignedHeaders={signed_headers},Signature={sig}"
    )

    url = f"https://{ENDPOINT_HOST}{canonical_uri}"
    req = urllib.request.Request(url, data=(payload or None), method=method)
    for k, v in headers.items():
        if k == "host":
            continue  # urllib sets Host from the URL
        req.add_header(k, v)

    last_err = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last_err = e
            time.sleep(0.1 * (attempt + 1))
    return 0, {}, f"network error after retries: {last_err!r}".encode()


def serving_region(headers):
    for k in ("x-tigris-region", "x-tigris-regions", "x-amz-bucket-region"):
        if k in headers:
            return headers[k]
    return None


def percentile(xs, p):
    if not xs:
        return float("nan")
    s = sorted(xs)
    i = min(len(s) - 1, max(0, int(round((p / 100.0) * (len(s) - 1)))))
    return s[i]


def fmt_ms(secs):
    return f"{secs * 1000:.0f}ms"


def run(bucket, pin_region, iterations, overwrite, consistent_puts, single_key, ak, sk, st):
    prefix = f"probe/{uuid.uuid4().hex[:8]}"
    print(
        f"bucket={bucket} pin={pin_region or '(none)'} iterations={iterations} "
        f"overwrite={overwrite} consistent_puts={consistent_puts} "
        f"single_key={single_key} prefix={prefix}"
    )

    plain_ok = plain_stale = plain_404 = plain_err = 0
    cons_ok = cons_stale = cons_404 = cons_err = 0
    put_lat, plain_lat, cons_lat = [], [], []
    put_regions, plain_regions, cons_regions = {}, {}, {}

    put_headers = {}
    if pin_region:
        put_headers["X-Tigris-Regions"] = pin_region
    if consistent_puts:
        put_headers["X-Tigris-Consistent"] = "true"

    plain_get_headers = {}
    if pin_region:
        plain_get_headers["X-Tigris-Regions"] = pin_region

    cons_headers = {"X-Tigris-Consistent": "true"}
    if pin_region:
        cons_headers["X-Tigris-Regions"] = pin_region

    fixed_key = f"{prefix}/key"
    for seq in range(iterations):
        key = fixed_key if single_key else f"{prefix}/{seq}"
        expected = f"v{seq}".encode()

        # In single_key mode every iteration's PUT is itself an overwrite of
        # the previous one, so we skip the explicit v_initial write.
        if overwrite and not single_key:
            s3_request("PUT", bucket, key, b"v_initial", put_headers, ak, sk, st)

        t0 = time.perf_counter()
        status, hdrs, body = s3_request("PUT", bucket, key, expected, put_headers, ak, sk, st)
        put_lat.append(time.perf_counter() - t0)
        if status != 200:
            print(f"  [PUT fail]    seq={seq} status={status} body={body[:120]!r}")
            continue
        r = serving_region(hdrs)
        if r:
            put_regions[r] = put_regions.get(r, 0) + 1

        # Plain GET (no consistency header; pin region applied if set).
        t0 = time.perf_counter()
        status, hdrs, body = s3_request("GET", bucket, key, b"", plain_get_headers, ak, sk, st)
        plain_lat.append(time.perf_counter() - t0)
        r = serving_region(hdrs)
        if r:
            plain_regions[r] = plain_regions.get(r, 0) + 1
        if status == 200:
            if body == expected:
                plain_ok += 1
            else:
                plain_stale += 1
                print(f"  [plain stale] seq={seq} got={body!r} expected={expected!r} region={r}")
        elif status == 404:
            plain_404 += 1
            print(f"  [plain 404]   seq={seq} region={r}")
        else:
            plain_err += 1
            print(f"  [plain err]   seq={seq} status={status} body={body[:120]!r}")

        # Consistent GET (X-Tigris-Consistent: true).
        t0 = time.perf_counter()
        status, hdrs, body = s3_request("GET", bucket, key, b"", cons_headers, ak, sk, st)
        cons_lat.append(time.perf_counter() - t0)
        r = serving_region(hdrs)
        if r:
            cons_regions[r] = cons_regions.get(r, 0) + 1
        if status == 200:
            if body == expected:
                cons_ok += 1
            else:
                cons_stale += 1
                print(f"  [cons stale]  seq={seq} got={body!r} expected={expected!r} region={r}")
        elif status == 404:
            cons_404 += 1
            print(f"  [cons 404]    seq={seq} region={r}")
        else:
            cons_err += 1
            print(f"  [cons err]    seq={seq} status={status} body={body[:120]!r}")

    print()
    print("=== results ===")
    print(f"PUT pinned to {pin_region}:")
    print(f"  served by: {put_regions or '(no region header)'}")
    print(f"  latency:  p50={fmt_ms(percentile(put_lat, 50))} "
          f"p95={fmt_ms(percentile(put_lat, 95))} "
          f"p99={fmt_ms(percentile(put_lat, 99))}")
    print()
    print("plain GET (no header):")
    print(f"  ok={plain_ok} stale={plain_stale} 404={plain_404} err={plain_err}")
    print(f"  served by: {plain_regions or '(no region header)'}")
    print(f"  latency:  p50={fmt_ms(percentile(plain_lat, 50))} "
          f"p95={fmt_ms(percentile(plain_lat, 95))} "
          f"p99={fmt_ms(percentile(plain_lat, 99))}")
    print()
    print("consistent GET (X-Tigris-Consistent: true):")
    print(f"  ok={cons_ok} stale={cons_stale} 404={cons_404} err={cons_err}")
    print(f"  served by: {cons_regions or '(no region header)'}")
    print(f"  latency:  p50={fmt_ms(percentile(cons_lat, 50))} "
          f"p95={fmt_ms(percentile(cons_lat, 95))} "
          f"p99={fmt_ms(percentile(cons_lat, 99))}")
    print()

    print("cleaning up probe keys...")
    keys_to_delete = [fixed_key] if single_key else [f"{prefix}/{i}" for i in range(iterations)]
    deleted = 0
    for k in keys_to_delete:
        status, _, _ = s3_request("DELETE", bucket, k, b"", {}, ak, sk, st)
        if status in (200, 204):
            deleted += 1
    print(f"deleted {deleted}/{len(keys_to_delete)}")


def classify_get(status, body, v_old, v_new):
    if status == 404:
        return "404"
    if status != 200:
        return "err"
    if body == v_new:
        return "new"
    if body == v_old:
        return "old"
    return "other"


def run_repin(bucket, pin_a, pin_b, iterations, recheck_delays, ak, sk, st):
    prefix = f"probe/{uuid.uuid4().hex[:8]}"
    print(
        f"REPIN: bucket={bucket} pin_a={pin_a} pin_b={pin_b} "
        f"iterations={iterations} prefix={prefix}"
    )

    a_hdr = {"X-Tigris-Regions": pin_a}
    b_hdr = {"X-Tigris-Regions": pin_b}

    paths = {
        "GET pin_a": {"hdr": a_hdr, "tally": {}, "regions": {}, "lat": []},
        "GET pin_b": {"hdr": b_hdr, "tally": {}, "regions": {}, "lat": []},
        "GET (no pin)": {"hdr": {}, "tally": {}, "regions": {}, "lat": []},
    }
    put_a_lat, put_b_lat = [], []
    put_a_regions, put_b_regions = {}, {}
    put_b_status = {}

    for seq in range(iterations):
        key = f"{prefix}/{seq}"
        v_old = f"v_old_{seq}".encode()
        v_new = f"v_new_{seq}".encode()

        # PUT v_old pinned to pin_a.
        t0 = time.perf_counter()
        status, hdrs, body = s3_request("PUT", bucket, key, v_old, a_hdr, ak, sk, st)
        put_a_lat.append(time.perf_counter() - t0)
        if status != 200:
            print(f"  [PUT_A fail]  seq={seq} status={status} body={body[:120]!r}")
            continue
        r = serving_region(hdrs)
        if r:
            put_a_regions[r] = put_a_regions.get(r, 0) + 1

        # PUT v_new pinned to pin_b (same key).
        t0 = time.perf_counter()
        status, hdrs, body = s3_request("PUT", bucket, key, v_new, b_hdr, ak, sk, st)
        put_b_lat.append(time.perf_counter() - t0)
        put_b_status[status] = put_b_status.get(status, 0) + 1
        if status != 200:
            if status not in (200,):
                print(f"  [PUT_B {status}] seq={seq} body={body[:120]!r}")
            continue
        r = serving_region(hdrs)
        if r:
            put_b_regions[r] = put_b_regions.get(r, 0) + 1

        # Three GETs.
        for label, info in paths.items():
            t0 = time.perf_counter()
            status, hdrs, body = s3_request("GET", bucket, key, b"", info["hdr"], ak, sk, st)
            info["lat"].append(time.perf_counter() - t0)
            outcome = classify_get(status, body, v_old, v_new)
            info["tally"][outcome] = info["tally"].get(outcome, 0) + 1
            r = serving_region(hdrs)
            if r:
                info["regions"][r] = info["regions"].get(r, 0) + 1
            if outcome == "other":
                print(f"  [{label} other] seq={seq} got={body[:60]!r} status={status}")

    print()
    print("=== repin results ===")
    print(f"PUT pin_a={pin_a}:")
    print(f"  served by: {put_a_regions or '(no region header)'}")
    print(f"  latency:  p50={fmt_ms(percentile(put_a_lat, 50))} "
          f"p95={fmt_ms(percentile(put_a_lat, 95))} "
          f"p99={fmt_ms(percentile(put_a_lat, 99))}")
    print()
    print(f"PUT pin_b={pin_b} (repin):")
    print(f"  served by: {put_b_regions or '(no region header)'}")
    print(f"  status counts: {put_b_status}")
    print(f"  latency:  p50={fmt_ms(percentile(put_b_lat, 50))} "
          f"p95={fmt_ms(percentile(put_b_lat, 95))} "
          f"p99={fmt_ms(percentile(put_b_lat, 99))}")
    print()
    for label, info in paths.items():
        print(f"{label}:")
        print(f"  outcomes: {info['tally']}  (new=v_new_<seq>, old=v_old_<seq>)")
        print(f"  served by: {info['regions'] or '(no region header)'}")
        print(f"  latency:  p50={fmt_ms(percentile(info['lat'], 50))} "
              f"p95={fmt_ms(percentile(info['lat'], 95))} "
              f"p99={fmt_ms(percentile(info['lat'], 99))}")
        print()

    if recheck_delays:
        elapsed = 0
        for delay in recheck_delays:
            sleep_for = delay - elapsed
            if sleep_for > 0:
                print(f"sleeping {sleep_for}s before recheck at +{delay}s ...")
                time.sleep(sleep_for)
                elapsed = delay
            print(f"=== recheck at +{delay}s ===")
            recheck = {
                f"GET pin_a (+{delay}s)": {"hdr": a_hdr, "tally": {}, "regions": {}},
                f"GET pin_b (+{delay}s)": {"hdr": b_hdr, "tally": {}, "regions": {}},
                f"GET no-pin (+{delay}s)": {"hdr": {}, "tally": {}, "regions": {}},
            }
            for seq in range(iterations):
                key = f"{prefix}/{seq}"
                v_old = f"v_old_{seq}".encode()
                v_new = f"v_new_{seq}".encode()
                for label, info in recheck.items():
                    status, hdrs, body = s3_request("GET", bucket, key, b"", info["hdr"], ak, sk, st)
                    outcome = classify_get(status, body, v_old, v_new)
                    info["tally"][outcome] = info["tally"].get(outcome, 0) + 1
                    r = serving_region(hdrs)
                    if r:
                        info["regions"][r] = info["regions"].get(r, 0) + 1
            for label, info in recheck.items():
                print(f"{label}:")
                print(f"  outcomes: {info['tally']}")
                print(f"  served by: {info['regions'] or '(no region header)'}")
            print()

    print("cleaning up probe keys...")
    deleted = 0
    for seq in range(iterations):
        status, _, _ = s3_request(
            "DELETE", bucket, f"{prefix}/{seq}", b"", {}, ak, sk, st
        )
        if status in (200, 204):
            deleted += 1
    print(f"deleted {deleted}/{iterations}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bucket", default="elide-global-test")
    ap.add_argument("--pin-region", default="",
                    help="region to pin PUTs to (X-Tigris-Regions); empty for no pin")
    ap.add_argument("-n", "--iterations", type=int, default=100)
    ap.add_argument("--overwrite", action="store_true",
                    help="write v_initial, then overwrite, then read")
    ap.add_argument("--consistent-puts", action="store_true",
                    help="also send X-Tigris-Consistent: true on PUTs")
    ap.add_argument("--single-key", action="store_true",
                    help="overwrite a single key across all iterations "
                         "(stress test PUT-after-PUT visibility on one key)")
    ap.add_argument("--repin-region", default="",
                    help="enable repin test: PUT v_old pinned to --pin-region, "
                         "PUT v_new pinned to this region, then GET via each pin")
    ap.add_argument("--recheck-after", default="",
                    help="comma-separated delays in seconds for repin rechecks "
                         "(e.g. '30,300,1800'); re-issues all three GETs at each")
    args = ap.parse_args()

    ak = os.environ.get("AWS_ACCESS_KEY_ID")
    sk = os.environ.get("AWS_SECRET_ACCESS_KEY")
    st = os.environ.get("AWS_SESSION_TOKEN")
    if not ak or not sk:
        raise SystemExit("AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY not set")

    if args.repin_region:
        if not args.pin_region:
            raise SystemExit("--repin-region requires --pin-region")
        recheck_delays = []
        if args.recheck_after:
            recheck_delays = sorted(int(s) for s in args.recheck_after.split(","))
        run_repin(args.bucket, args.pin_region, args.repin_region,
                  args.iterations, recheck_delays, ak, sk, st)
        return

    run(args.bucket, args.pin_region, args.iterations, args.overwrite,
        args.consistent_puts, args.single_key, ak, sk, st)


if __name__ == "__main__":
    main()
