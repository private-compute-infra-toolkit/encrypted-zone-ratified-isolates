// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use boring::{
    asn1::Asn1Time,
    pkey::{PKey, Public},
    stack::Stack,
    x509::{
        X509, X509Ref, X509Req, X509StoreContext, store::X509StoreBuilder, verify::X509VerifyFlags,
    },
};
use metrics::Metrics;
use setup_isolate_proto::setup_isolate::v1::{
    CertificateBundle, GetCertificateResponse, RotatedTrustAnchor, UnattestedFallbackBundle,
};
use tonic::Status;
use x509_cert::{Certificate, der::Decode, ext::pkix::BasicConstraints};

const MAX_DER_BYTES: usize = 64 * 1024;
const MAX_SUB_CA_CERTIFICATES: usize = 8;
const MAX_ROTATED_TRUST_ANCHORS: usize = 8;
const EMPTY_FLAGS: X509VerifyFlags = X509VerifyFlags::empty();
const NO_CHECK_TIME: X509VerifyFlags = X509VerifyFlags::from_bits_retain(0x200000);
// Must match the external attestation certificate provider's
// `kUnattestedFallbackSpiffeId` constant so issuer and verifier do not drift.
const UNATTESTED_FALLBACK_SPIFFE_ID: &str = concat!(
    "spiffe://untrusted-operator.untrusted-domain/operator/untrusted-operator/",
    "role/publisher/untrusted/role/workload/untrusted-fallback"
);

fn invalid_csr(msg: impl std::fmt::Display) -> Status {
    Status::invalid_argument(format!("Invalid CSR: {msg}"))
}

fn verify_err(msg: impl std::fmt::Display) -> Status {
    Status::internal(format!("Certificate verification failed: {msg}"))
}

/// Parses a DER-encoded X.509 certificate and verifies its BasicConstraints CA flag.
fn parse_x509_and_verify_bc(der: &[u8], expect_ca: bool, label: &str) -> Result<X509, Status> {
    if der.is_empty() || der.len() > MAX_DER_BYTES {
        return Err(verify_err(format!("{label} DER size out of bounds")));
    }
    let cert = Certificate::from_der(der).map_err(verify_err)?;
    let bc = cert
        .tbs_certificate
        .get::<BasicConstraints>()
        .map_err(verify_err)?;
    if bc.is_some_and(|(_, b)| b.ca) != expect_ca {
        return Err(verify_err(format!("{label} CA constraint mismatch")));
    }
    X509::from_der(der).map_err(verify_err)
}

fn same_pubkey(a: &X509Ref, b: &X509Ref) -> bool {
    let (Ok(ak), Ok(bk)) = (a.public_key(), b.public_key()) else {
        return false;
    };
    ak.public_eq(&bk)
}

/// Validates a certificate path from `target` through `untrusted` to `roots` at
/// `posix_timestamp_sec` using BoringSSL's `X509_STORE` and `X509_verify_cert`.
fn verify_chain(
    target: &X509Ref,
    untrusted: &[X509],
    roots: &[&X509Ref],
    posix_timestamp_sec: i64,
    flags: X509VerifyFlags,
) -> Result<Vec<X509>, Status> {
    let mut sb = X509StoreBuilder::new().map_err(verify_err)?;
    for r in roots {
        sb.add_cert(r).map_err(verify_err)?;
    }
    sb.set_flags(X509VerifyFlags::CHECK_SS_SIGNATURE | flags);
    sb.verify_param_mut().set_time(posix_timestamp_sec);
    let mut stack = Stack::new().map_err(verify_err)?;
    for c in untrusted {
        stack.push(c.clone()).map_err(verify_err)?;
    }
    let mut ctx = X509StoreContext::new().map_err(verify_err)?;
    ctx.init(&sb.build(), target, &stack, |c| {
        if !c.verify_cert()? {
            return Ok(Err(verify_err("X509_verify_cert failed")));
        }
        let ch = c.chain().into_iter().flatten();
        Ok(Ok(ch.map(|x| x.to_owned()).collect()))
    })
    .map_err(verify_err)?
}

pub(crate) type CertChainAndAnchors = (Vec<Vec<u8>>, Vec<Vec<u8>>);

/// Resolves and verifies a `GetCertificateResponse` into `(certificate_chain, trust_anchors)`:
/// 1. When `certificate_bundle` is populated, verifies the CSR signature, leaf public key
///    binding, and X.509 path (`leaf -> sub_ca -> current_trust_anchor`) via BoringSSL; if
///    `allow_unattested_fallback` is true and `unattested_fallback` is present, verifies
///    `fallback_bridge_certificate` against `fallback_trust_anchor` and `current_trust_anchor`
///    (logging a warning and keeping the attested chain if the bridge is invalid).
/// 2. When only `unattested_fallback` is populated, rejects with `FailedPrecondition` unless
///    `allow_unattested_fallback` is true, in which case it verifies `fallback_leaf_certificate`
///    against `fallback_trust_anchor` and the mandatory untrusted SPIFFE URI SAN.
/// 3. When neither structured bundle is populated, falls back to the legacy flat `certs` list.
pub(crate) fn process_certificate_response(
    now: SystemTime,
    signed_csr_der: &[u8],
    resp: GetCertificateResponse,
    allow_unattested_fallback: bool,
    metrics: &Metrics,
) -> Result<CertChainAndAnchors, Status> {
    let cert_bundle = resp.certificate_bundle.filter(|b| {
        !b.leaf_certificate.is_empty()
            || !b.sub_ca_certificates.is_empty()
            || !b.current_trust_anchor.is_empty()
            || !b.rotated_trust_anchors.is_empty()
    });
    let fallback_bundle = resp.unattested_fallback.filter(|f| {
        !f.fallback_trust_anchor.is_empty()
            || !f.fallback_bridge_certificate.is_empty()
            || !f.fallback_leaf_certificate.is_empty()
    });
    if cert_bundle.is_none() && fallback_bundle.is_none() {
        let mut certs = resp.certs;
        let trust_anchors = certs.pop().into_iter().collect();
        return Ok((certs, trust_anchors));
    }

    let csr_pubkey = extract_and_verify_csr_pubkey(signed_csr_der)?;
    let posix_timestamp_sec = now
        .duration_since(UNIX_EPOCH)
        .map_err(verify_err)?
        .as_secs() as i64;

    if let Some(bundle) = cert_bundle {
        let (mut chain, mut anchors) =
            verify_certificate_bundle(&bundle, &csr_pubkey, posix_timestamp_sec)?;
        if let (Some(fb), Some(curr)) = (
            fallback_bundle.filter(|_| allow_unattested_fallback),
            anchors.first(),
        ) {
            match verify_fallback_bridge(curr, &fb, posix_timestamp_sec) {
                Ok((bridge, fb_root)) => {
                    // With fallback enabled, this node trusts the public-seed `fb_root` even when
                    // its attested cert is valid, so backend peer identity is not enforced.
                    if !anchors.iter().any(|a| same_pubkey(a, &fb_root)) {
                        anchors.push(fb_root);
                    }
                    chain.push(bridge);
                }
                Err(e) => {
                    log::warn!("Ignoring invalid fallback bridge; keeping attested chain: {e}");
                    metrics.record_unattested_fallback("invalid_bridge");
                }
            }
        }
        return Ok((to_ders(&chain)?, to_ders(&anchors)?));
    }

    let fb = fallback_bundle.ok_or_else(|| verify_err("empty GetCertificateResponse"))?;
    if !allow_unattested_fallback {
        return Err(Status::failed_precondition(
            "Unattested fallback certificates are disabled",
        ));
    }
    verify_standalone_fallback(fb, &csr_pubkey, posix_timestamp_sec, metrics)
}

fn to_ders(certs: &[X509]) -> Result<Vec<Vec<u8>>, Status> {
    certs
        .iter()
        .map(|c| c.to_der().map_err(verify_err))
        .collect()
}

/// Verifies the CSR self-signature and extracts its `SubjectPublicKeyInfo` so the leaf
/// certificate returned across the untrusted host bridge is bound to the caller's keypair.
fn extract_and_verify_csr_pubkey(signed_csr_der: &[u8]) -> Result<PKey<Public>, Status> {
    if signed_csr_der.is_empty() || signed_csr_der.len() > MAX_DER_BYTES {
        return Err(invalid_csr("CSR size out of bounds"));
    }
    let csr = X509Req::from_der(signed_csr_der).map_err(invalid_csr)?;
    let pubkey = csr.public_key().map_err(invalid_csr)?;
    if !csr.verify(&pubkey).map_err(invalid_csr)? {
        return Err(invalid_csr("CSR signature verification failed"));
    }
    Ok(pubkey)
}

fn verify_certificate_bundle(
    bundle: &CertificateBundle,
    csr_pubkey: &PKey<Public>,
    posix_timestamp_sec: i64,
) -> Result<(Vec<X509>, Vec<X509>), Status> {
    if bundle.sub_ca_certificates.len() > MAX_SUB_CA_CERTIFICATES
        || bundle.rotated_trust_anchors.len() > MAX_ROTATED_TRUST_ANCHORS
    {
        return Err(verify_err("bundle certificate count exceeds maximum"));
    }
    let leaf = parse_x509_and_verify_bc(&bundle.leaf_certificate, false, "leaf")?;
    if !leaf.public_key().is_ok_and(|k| k.public_eq(csr_pubkey)) {
        return Err(verify_err("leaf_certificate SPKI does not match CSR SPKI"));
    }
    if leaf.subject_alt_names().is_some_and(|s| {
        s.iter()
            .any(|n| n.uri() == Some(UNATTESTED_FALLBACK_SPIFFE_ID))
    }) {
        return Err(verify_err(
            "attested leaf must not carry fallback SPIFFE ID",
        ));
    }
    // TODO(b/579043441): Check that backend `current_trust_anchor` matches the
    // frontend TLS trust anchor once frontend TLS and backend mTLS share one root.
    let root = parse_x509_and_verify_bc(&bundle.current_trust_anchor, true, "root")?;
    verify_chain(&root, &[], &[&root], posix_timestamp_sec, EMPTY_FLAGS)?;

    let mut seen_ders = HashSet::with_capacity(bundle.sub_ca_certificates.len());
    let mut sub_cas = Vec::with_capacity(bundle.sub_ca_certificates.len());
    for sub_der in &bundle.sub_ca_certificates {
        if !seen_ders.insert(sub_der.as_slice()) {
            continue;
        }
        let sub_ca = parse_x509_and_verify_bc(sub_der, true, "sub_ca")?;
        if same_pubkey(&sub_ca, &root) {
            return Err(verify_err("sub_ca reuses current_trust_anchor key"));
        }
        sub_cas.push(sub_ca);
    }

    let rotations =
        verify_rotated_trust_anchors(&bundle.rotated_trust_anchors, &root, posix_timestamp_sec)?;
    let mut roots: Vec<&X509Ref> = vec![&root];
    if !sub_cas.is_empty() {
        roots.extend(rotations.iter().map(|(c2p, _)| c2p.as_ref()));
    }
    let mut validated = verify_chain(&leaf, &sub_cas, &roots, posix_timestamp_sec, EMPTY_FLAGS)?;
    if validated.pop().is_none_or(|top| !same_pubkey(&top, &root)) {
        return Err(verify_err(
            "chain did not terminate at current_trust_anchor",
        ));
    }
    let used_c2p = validated
        .last()
        .is_some_and(|pen| rotations.iter().any(|(c2p, _)| same_pubkey(c2p, pen)));
    if validated.len() != 1 + sub_cas.len() + usize::from(used_c2p) {
        return Err(verify_err("unreachable sub_ca_certificates"));
    }
    let anchors = std::iter::once(root)
        .chain(rotations.iter().map(|(c2p, _)| c2p.clone()))
        .collect();
    if !used_c2p {
        validated.extend(rotations.into_iter().map(|(_, p2c)| p2c));
    }
    Ok((validated, anchors))
}

fn verify_rotated_trust_anchors(
    rotations: &[RotatedTrustAnchor],
    curr_root: &X509Ref,
    posix_timestamp_sec: i64,
) -> Result<Vec<(X509, X509)>, Status> {
    let now_asn1 = Asn1Time::from_unix(posix_timestamp_sec).map_err(verify_err)?;
    let mut seen_prev = HashSet::with_capacity(rotations.len());
    let mut active = Vec::with_capacity(rotations.len());
    for rot in rotations {
        let c2p = parse_x509_and_verify_bc(&rot.current_signs_previous, true, "c2p")?;
        let p2c = parse_x509_and_verify_bc(&rot.previous_signs_current, true, "p2c")?;
        if same_pubkey(&c2p, curr_root)
            || !same_pubkey(&p2c, curr_root)
            || c2p.not_before() > now_asn1
            || p2c.not_before() > now_asn1
            || c2p.not_before() > c2p.not_after()
            || p2c.not_before() > p2c.not_after()
        {
            return Err(verify_err("invalid rotated_trust_anchors"));
        }
        let ca = verify_chain(&c2p, &[], &[curr_root], posix_timestamp_sec, NO_CHECK_TIME)?;
        let cb = verify_chain(
            &p2c,
            std::slice::from_ref(&c2p),
            &[curr_root],
            posix_timestamp_sec,
            NO_CHECK_TIME,
        )?;
        if ca.len() != 2 || cb.len() != 3 {
            return Err(verify_err("invalid rotated_trust_anchors chain"));
        }
        let spki = c2p
            .public_key()
            .and_then(|pk| pk.public_key_to_der())
            .map_err(verify_err)?;
        if c2p.not_after() >= now_asn1 && p2c.not_after() >= now_asn1 && seen_prev.insert(spki) {
            active.push((c2p, p2c));
        }
    }
    Ok(active)
}

fn verify_fallback_bridge(
    current_root: &X509Ref,
    fb: &UnattestedFallbackBundle,
    posix_timestamp_sec: i64,
) -> Result<(X509, X509), Status> {
    if !fb.fallback_leaf_certificate.is_empty() {
        return Err(verify_err(
            "attested fallback bundle must not contain fallback_leaf_certificate",
        ));
    }
    let fb_root =
        parse_x509_and_verify_bc(&fb.fallback_trust_anchor, true, "fallback_trust_anchor")?;
    let bridge =
        parse_x509_and_verify_bc(&fb.fallback_bridge_certificate, true, "fallback_bridge")?;
    let bridged = verify_chain(&bridge, &[], &[&fb_root], posix_timestamp_sec, EMPTY_FLAGS)?;
    if bridged.len() != 2
        || bridge.subject_alt_names().is_some()
        || !same_pubkey(current_root, &bridge)
        || same_pubkey(&fb_root, &bridge)
        || current_root.subject_name().to_der().map_err(verify_err)?
            != bridge.subject_name().to_der().map_err(verify_err)?
    {
        return Err(verify_err(
            "fallback_bridge_certificate path or SPKI mismatch",
        ));
    }
    Ok((bridge, fb_root))
}

fn verify_standalone_fallback(
    fb: UnattestedFallbackBundle,
    csr_pubkey: &PKey<Public>,
    posix_timestamp_sec: i64,
    metrics: &Metrics,
) -> Result<CertChainAndAnchors, Status> {
    if !fb.fallback_bridge_certificate.is_empty() {
        return Err(verify_err(
            "standalone fallback bundle must not contain fallback_bridge_certificate",
        ));
    }
    let fb_root =
        parse_x509_and_verify_bc(&fb.fallback_trust_anchor, true, "fallback_trust_anchor")?;
    let fb_leaf = parse_x509_and_verify_bc(&fb.fallback_leaf_certificate, false, "fallback_leaf")?;
    if !fb_leaf.public_key().is_ok_and(|k| k.public_eq(csr_pubkey)) {
        return Err(verify_err(
            "fallback_leaf_certificate SPKI does not match CSR SPKI",
        ));
    }
    let validated = verify_chain(&fb_leaf, &[], &[&fb_root], posix_timestamp_sec, EMPTY_FLAGS)?;
    if validated.len() != 2 {
        return Err(verify_err("invalid standalone fallback chain"));
    }
    let Some(sans) = fb_leaf.subject_alt_names() else {
        return Err(verify_err("fallback leaf missing SAN"));
    };
    if sans.len() != 1
        || sans.iter().next().and_then(|n| n.uri()) != Some(UNATTESTED_FALLBACK_SPIFFE_ID)
    {
        return Err(verify_err(
            "fallback leaf must carry sole designated fallback URI SAN",
        ));
    }
    // In standalone fallback mode this node trusts only the public-seed `fb_root`,
    // so it cannot cryptographically verify any backend mTLS peer identity.
    log::warn!("Attested backend mTLS certificate unavailable; issuing unattested fallback leaf");
    metrics.record_unattested_fallback("standalone_leaf");
    Ok((
        vec![fb.fallback_leaf_certificate],
        vec![fb.fallback_trust_anchor],
    ))
}
