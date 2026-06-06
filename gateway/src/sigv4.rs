//! AWS Signature Version 4 — the one outbound auth mechanism that is a *request
//! transform* rather than a header set. halter re-signs an allowed request with the real
//! account credential before forwarding (the consumer never holds it). The same
//! primitive [`verify`]s an inbound signature against a minted dummy credential.
//!
//! Built on `ring` (SHA-256 + HMAC), no AWS SDK. The canonical form here signs the
//! minimal `host;x-amz-content-sha256;x-amz-date` header set, which is what halter itself
//! produces and what the common AWS request shape uses.

use ring::{digest, hmac};

/// An AWS credential pair.
pub struct Creds<'a> {
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
}

/// The headers a caller must set on the outbound request to make it SigV4-signed.
pub struct Signed {
    pub authorization: String,
    pub amz_date: String,
    pub content_sha256: String,
}

const SIGNED_HEADERS: &str = "host;x-amz-content-sha256;x-amz-date";

/// Sign a request, returning the `Authorization`, `X-Amz-Date`, and `X-Amz-Content-Sha256`
/// header values. `canonical_uri` is the (already `/`-prefixed) path; `query` is the raw
/// query string (sorted here); `epoch_ms` is the signing time.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    creds: &Creds,
    region: &str,
    service: &str,
    method: &str,
    host: &str,
    canonical_uri: &str,
    query: &str,
    body: &[u8],
    epoch_ms: u64,
) -> Signed {
    let (amz_date, datestamp) = format_amz_datetime(epoch_ms);
    let content_sha256 = sha256_hex(body);
    let signature = compute_signature(
        creds.secret_access_key,
        region,
        service,
        method,
        host,
        canonical_uri,
        query,
        &content_sha256,
        &amz_date,
        &datestamp,
    );
    let scope = format!("{datestamp}/{region}/{service}/aws4_request");
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={SIGNED_HEADERS}, Signature={signature}",
        creds.access_key_id
    );
    Signed {
        authorization,
        amz_date,
        content_sha256,
    }
}

/// Verify that `signature` matches what `secret_access_key` would produce for this
/// request (the inbound check against a minted dummy credential). Constant work; compares
/// the lowercase hex signatures.
#[allow(clippy::too_many_arguments)]
pub fn verify(
    secret_access_key: &str,
    region: &str,
    service: &str,
    method: &str,
    host: &str,
    canonical_uri: &str,
    query: &str,
    content_sha256: &str,
    amz_date: &str,
    datestamp: &str,
    signature: &str,
) -> bool {
    let expected = compute_signature(
        secret_access_key,
        region,
        service,
        method,
        host,
        canonical_uri,
        query,
        content_sha256,
        amz_date,
        datestamp,
    );
    constant_time_eq(expected.as_bytes(), signature.as_bytes())
}

#[allow(clippy::too_many_arguments)]
fn compute_signature(
    secret: &str,
    region: &str,
    service: &str,
    method: &str,
    host: &str,
    canonical_uri: &str,
    query: &str,
    content_sha256: &str,
    amz_date: &str,
    datestamp: &str,
) -> String {
    let canonical_headers =
        format!("host:{host}\nx-amz-content-sha256:{content_sha256}\nx-amz-date:{amz_date}\n");
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{}\n{canonical_headers}\n{SIGNED_HEADERS}\n{content_sha256}",
        canonical_query(query)
    );
    let scope = format!("{datestamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let signing_key = derive_signing_key(secret, datestamp, region, service);
    to_hex(&hmac256(&signing_key, string_to_sign.as_bytes()))
}

/// The SigV4 signing-key derivation chain.
fn derive_signing_key(secret: &str, datestamp: &str, region: &str, service: &str) -> [u8; 32] {
    let k_date = hmac256(format!("AWS4{secret}").as_bytes(), datestamp.as_bytes());
    let k_region = hmac256(&k_date, region.as_bytes());
    let k_service = hmac256(&k_region, service.as_bytes());
    hmac256(&k_service, b"aws4_request")
}

/// Canonicalize a query string: split into `k=v` pairs and sort. (Values are assumed
/// already percent-encoded, matching the rest of the proxy.)
fn canonical_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<&str> = query.split('&').filter(|p| !p.is_empty()).collect();
    pairs.sort_unstable();
    pairs.join("&")
}

fn hmac256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&k, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

fn sha256_hex(data: &[u8]) -> String {
    to_hex(digest::digest(&digest::SHA256, data).as_ref())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Format epoch milliseconds as the SigV4 `YYYYMMDDTHHMMSSZ` and `YYYYMMDD` strings (UTC).
fn format_amz_datetime(epoch_ms: u64) -> (String, String) {
    let secs = (epoch_ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, m, d) = civil_from_days(days);
    (
        format!("{y:04}{m:02}{d:02}T{h:02}{mi:02}{s:02}Z"),
        format!("{y:04}{m:02}{d:02}"),
    )
}

/// Convert days-since-Unix-epoch to a civil (year, month, day). Howard Hinnant's
/// `civil_from_days` algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn datetime_formats_known_epoch() {
        // 2012-02-15T00:00:00Z = 1329264000 s.
        let (amz, date) = format_amz_datetime(1_329_264_000_000);
        assert_eq!(amz, "20120215T000000Z");
        assert_eq!(date, "20120215");
    }

    #[test]
    fn signing_key_matches_aws_documented_vector() {
        // AWS docs "deriving a signing key for SigV4": secret/date/region/service →
        // a published signing key.
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            to_hex(&key),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }

    #[test]
    fn sign_then_verify_round_trips_and_detects_tampering() {
        let creds = Creds {
            access_key_id: "AKIDEXAMPLE",
            secret_access_key: "secret-key",
        };
        let body = b"Action=DescribeInstances&Version=2016-11-15";
        let signed = sign(
            &creds,
            "us-east-1",
            "ec2",
            "POST",
            "ec2.us-east-1.amazonaws.com",
            "/",
            "",
            body,
            1_700_000_000_000,
        );
        // Pull the signature back out of the Authorization header.
        let signature = signed
            .authorization
            .rsplit("Signature=")
            .next()
            .unwrap()
            .to_string();
        let (amz_date, datestamp) = format_amz_datetime(1_700_000_000_000);
        assert!(verify(
            "secret-key",
            "us-east-1",
            "ec2",
            "POST",
            "ec2.us-east-1.amazonaws.com",
            "/",
            "",
            &signed.content_sha256,
            &amz_date,
            &datestamp,
            &signature,
        ));
        // Wrong secret → no match.
        assert!(!verify(
            "WRONG",
            "us-east-1",
            "ec2",
            "POST",
            "ec2.us-east-1.amazonaws.com",
            "/",
            "",
            &signed.content_sha256,
            &amz_date,
            &datestamp,
            &signature,
        ));
    }
}
