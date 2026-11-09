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

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, SanType};

pub const TEST_SPIFFE_URI: &str = "spiffe://mesh.example/operator/op/publisher/pub/workload/iso";
pub const FALLBACK_SPIFFE_URI: &str = concat!(
    "spiffe://untrusted-operator.untrusted-domain/operator/untrusted-operator/",
    "role/publisher/untrusted/role/workload/untrusted-fallback"
);
const DAY: Duration = Duration::from_secs(24 * 60 * 60);
pub type Win = (SystemTime, SystemTime);

pub struct CaMaterial {
    pub name: &'static str,
    pub key: KeyPair,
    pub cert: Certificate,
    pub der: Vec<u8>,
}

pub struct CsrNode {
    pub key: KeyPair,
    pub csr_der: Vec<u8>,
}

fn gen_key() -> KeyPair {
    KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap()
}

pub fn active_window() -> Win {
    let now = SystemTime::now();
    (now.checked_sub(DAY).unwrap_or(UNIX_EPOCH), now + 7 * DAY)
}

pub fn expired_window() -> Win {
    let now = SystemTime::now();
    (
        now.checked_sub(10 * DAY).unwrap_or(UNIX_EPOCH),
        now.checked_sub(DAY).unwrap_or(UNIX_EPOCH),
    )
}

pub fn future_window() -> Win {
    let now = SystemTime::now();
    (now + 2 * DAY, now + 10 * DAY)
}

fn ca_params(name: &str, (not_before, not_after): Win) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, name);
    params.not_before = not_before.into();
    params.not_after = not_after.into();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
}

pub fn sign_ca(name: &str, key: &KeyPair, iss: &CaMaterial, win: Win) -> Vec<u8> {
    ca_params(name, win)
        .signed_by(key, &iss.cert, &iss.key)
        .unwrap()
        .der()
        .to_vec()
}

fn build_ca(name: &'static str, key: KeyPair, cert: Certificate) -> CaMaterial {
    let der = cert.der().to_vec();
    CaMaterial {
        name,
        key,
        cert,
        der,
    }
}

pub fn make_root_ca(name: &'static str, win: Win) -> CaMaterial {
    let key = gen_key();
    let cert = ca_params(name, win).self_signed(&key).unwrap();
    build_ca(name, key, cert)
}

pub fn make_sub_ca(name: &'static str, iss: &CaMaterial, win: Win) -> CaMaterial {
    let key = gen_key();
    let cert = ca_params(name, win)
        .signed_by(&key, &iss.cert, &iss.key)
        .unwrap();
    build_ca(name, key, cert)
}

pub fn make_cross_signed_ca(subj: &CaMaterial, iss: &CaMaterial, win: Win) -> Vec<u8> {
    sign_ca(subj.name, &subj.key, iss, win)
}

pub fn make_csr_node(name: &str) -> CsrNode {
    let key = gen_key();
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, name);
    let csr_der = params.serialize_request(&key).unwrap().der().to_vec();
    CsrNode { key, csr_der }
}

pub fn issue_leaf(key: &KeyPair, issuer: &CaMaterial, win: Win, sans: &[&str]) -> Vec<u8> {
    let mut params = ca_params("workload-leaf", win);
    params.is_ca = IsCa::NoCa;
    params.subject_alt_names = sans
        .iter()
        .map(|u| SanType::URI((*u).try_into().unwrap()))
        .collect();
    params
        .signed_by(key, &issuer.cert, &issuer.key)
        .unwrap()
        .der()
        .to_vec()
}

pub fn tamper_der_signature(der: &[u8]) -> Vec<u8> {
    let mut out = der.to_vec();
    if let Some(last) = out.last_mut() {
        *last ^= 0x55;
    }
    out
}
