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

mod mock_bridge;
mod pki_fixtures;

use std::sync::Arc;

use mock_bridge::{build_service_with_handler, take_recorded_requests};
use pki_fixtures::{
    FALLBACK_SPIFFE_URI, TEST_SPIFFE_URI, active_window, expired_window, future_window, issue_leaf,
    make_cross_signed_ca, make_csr_node, make_root_ca, make_sub_ca, sign_ca, tamper_der_signature,
};
use prost::Message;
use setup_isolate_lib::{SetupConfig, SetupService};
use setup_isolate_proto::setup_isolate::v1::{
    CertificateBundle, ExpectedClaims, FetchFrontendTlsCertificateRequest,
    FetchTlsCertificateRequest, FetchTlsCertificateResponse, GetCertificateResponse,
    GetTlsCsrRequest, IsolatePackageEndorsement, PolicyHint, RotatedTrustAnchor,
    UnattestedFallbackBundle, ValidateIsolateEndorsementRequest,
    validate_isolate_endorsement_response::IsolateEndorsementValidationError,
};
use setup_isolate_sdk::{
    IsolateRpcService, SetupService as SetupServiceTrait, SetupServiceIsolateRpcService,
};
use tonic::{Code, Request, Status};

#[tokio::test]
async fn test_get_tls_csr_unimplemented() {
    let service = SetupService::new(SetupConfig::default());
    let request = Request::new(GetTlsCsrRequest::default());
    let response = service.get_tls_csr(request).await;
    assert!(response.is_err());
    assert_eq!(response.unwrap_err().code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn test_get_tls_csr_adapter_unimplemented() {
    let service = Arc::new(SetupService::new(SetupConfig::default()));
    let adapter = SetupServiceIsolateRpcService::new(service);
    let request = GetTlsCsrRequest::default();
    let mut request_bytes = Vec::new();
    request.encode(&mut request_bytes).unwrap();

    let response = adapter
        .unary_rpc_handler("GetTlsCsr", &request_bytes, None)
        .await;
    assert!(response.is_err());
    assert_eq!(response.unwrap_err().code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn test_validate_isolate_endorsement_missing_claims() {
    let service = SetupService::new(SetupConfig::default());
    let request = Request::new(ValidateIsolateEndorsementRequest {
        expected_claims: None,
        isolate_package_endorsement: Some(IsolatePackageEndorsement {
            endorsement_json: vec![1],
            signature: vec![2],
            pes_confirmation_json: vec![3],
        }),
        package_digest_sha256: "test-digest".to_string(),
    });
    let response = service
        .validate_isolate_endorsement(request)
        .await
        .unwrap()
        .into_inner();
    assert!(response.validity.is_none());
    assert_eq!(
        response.validation_error,
        IsolateEndorsementValidationError::ParsingFailure as i32
    );
    assert!(response.error_message.contains("Missing expected_claims"));
}

#[tokio::test]
async fn test_validate_isolate_endorsement_missing_digest() {
    let service = SetupService::new(SetupConfig::default());
    let request = Request::new(ValidateIsolateEndorsementRequest {
        expected_claims: Some(ExpectedClaims {
            publisher_id: "test-publisher".to_string(),
            isolate_name: "test-isolate".to_string(),
            package_filename: "test-package.tar".to_string(),
        }),
        isolate_package_endorsement: Some(IsolatePackageEndorsement {
            endorsement_json: vec![1],
            signature: vec![2],
            pes_confirmation_json: vec![3],
        }),
        package_digest_sha256: "".to_string(),
    });
    let response = service
        .validate_isolate_endorsement(request)
        .await
        .unwrap()
        .into_inner();
    assert!(response.validity.is_none());
    assert_eq!(
        response.validation_error,
        IsolateEndorsementValidationError::ParsingFailure as i32
    );
    assert!(
        response
            .error_message
            .contains("Missing package_digest_sha256")
    );
}

#[tokio::test]
async fn test_validate_isolate_endorsement_missing_endorsement() {
    let service = SetupService::new(SetupConfig::default());
    let request = Request::new(ValidateIsolateEndorsementRequest {
        expected_claims: Some(ExpectedClaims {
            publisher_id: "test-publisher".to_string(),
            isolate_name: "test-isolate".to_string(),
            package_filename: "test-package.tar".to_string(),
        }),
        isolate_package_endorsement: None,
        package_digest_sha256: "test-digest".to_string(),
    });
    let response = service
        .validate_isolate_endorsement(request)
        .await
        .unwrap()
        .into_inner();
    assert!(response.validity.is_none());
    assert_eq!(
        response.validation_error,
        IsolateEndorsementValidationError::ParsingFailure as i32
    );
    assert!(
        response
            .error_message
            .contains("Missing isolate_package_endorsement")
    );
}

#[tokio::test]
async fn test_validate_isolate_endorsement_invalid_endorsement_bytes() {
    let service = SetupService::new(SetupConfig::default());
    let request = Request::new(ValidateIsolateEndorsementRequest {
        expected_claims: Some(ExpectedClaims {
            publisher_id: "test-publisher".to_string(),
            isolate_name: "test-isolate".to_string(),
            package_filename: "test-package.tar".to_string(),
        }),
        isolate_package_endorsement: Some(IsolatePackageEndorsement {
            endorsement_json: vec![1],
            signature: vec![2],
            pes_confirmation_json: vec![3],
        }),
        package_digest_sha256: "test-digest".to_string(),
    });
    let response = service
        .validate_isolate_endorsement(request)
        .await
        .unwrap()
        .into_inner();
    assert!(response.validity.is_none());
    assert_eq!(
        response.validation_error,
        IsolateEndorsementValidationError::ParsingFailure as i32
    );
    assert!(!response.error_message.is_empty());
}

#[tokio::test]
async fn test_fetch_certs_legacy_split_empty_and_concurrent_isolation() {
    let root = make_root_ca("Mesh Root", active_window());
    let node = make_csr_node("node-legacy");
    let leaf_der = issue_leaf(&node.key, &root, active_window(), &[TEST_SPIFFE_URI]);
    let (csr_der, root_der) = (node.csr_der.clone(), root.der.clone());

    let (svc, role) = build_service_with_handler(false, {
        let (leaf_der, root_der) = (leaf_der.clone(), root_der.clone());
        move |req| match req.csr.as_slice() {
            csr if csr == csr_der.as_slice() || csr == b"fe" => Ok(GetCertificateResponse {
                certs: vec![leaf_der.clone(), root_der.clone()],
                ..Default::default()
            }),
            b"empty" => Ok(GetCertificateResponse::default()),
            _ => Err(Status::unavailable("backend unavailable")),
        }
    });

    let call_mtls = |csr: &[u8]| {
        svc.fetch_mtls_certificate(Request::new(FetchTlsCertificateRequest {
            signed_certificate_signing_request: csr.to_vec(),
        }))
    };
    let (mtls, fe, empty, err) = tokio::join!(
        call_mtls(&node.csr_der),
        svc.fetch_frontend_tls_certificate(Request::new(FetchFrontendTlsCertificateRequest {
            signed_certificate_signing_request: b"fe".to_vec(),
        })),
        call_mtls(b"empty"),
        call_mtls(b"fail"),
    );

    let (m, f) = (mtls.unwrap().into_inner(), fe.unwrap().into_inner());
    let empty = empty.unwrap().into_inner();
    assert_eq!(m.certificate_chain, vec![leaf_der.clone()]);
    assert_eq!(m.trust_anchors, vec![root_der.clone()]);
    assert_eq!(f.certificate_chain, vec![leaf_der]);
    assert_eq!(f.trust_anchors, vec![root_der]);
    assert!(empty.certificate_chain.is_empty() && empty.trust_anchors.is_empty());
    assert_eq!(err.unwrap_err().code(), Code::Unavailable);

    let recs: Vec<_> = take_recorded_requests(&role)
        .into_iter()
        .map(|r| (r.csr, r.policy_hint))
        .collect();
    assert_eq!(recs.len(), 4);
    assert!(recs.contains(&(node.csr_der, PolicyHint::BackendMtlsCert as i32)));
    assert!(recs.contains(&(b"fe".to_vec(), PolicyHint::FrontendTlsCert as i32)));
}

#[tokio::test]
async fn test_fetch_direct_bundle_and_invalid_csr_or_direct_rejections() {
    let root = make_root_ca("Mesh Root", active_window());
    let b_root = make_root_ca("Other Root", active_window());
    let node = make_csr_node("node-direct");
    let b_node = make_csr_node("wrong-key");
    let leaf_der = issue_leaf(&node.key, &root, active_window(), &[TEST_SPIFFE_URI]);
    let bad_key = issue_leaf(&b_node.key, &root, active_window(), &[]);
    let untrusted = issue_leaf(&node.key, &b_root, active_window(), &[]);
    let bundle = CertificateBundle {
        leaf_certificate: leaf_der.clone(),
        current_trust_anchor: root.der.clone(),
        ..Default::default()
    };

    for bad_csr in [
        Vec::new(),
        vec![0x30, 0x03, 0x01, 0x02, 0x03],
        tamper_der_signature(&node.csr_der),
    ] {
        assert_eq!(
            fetch_bundle(&bad_csr, bundle.clone())
                .await
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
    }

    let mtls = fetch_bundle(&node.csr_der, bundle.clone()).await.unwrap();
    assert_eq!(
        (mtls.certificate_chain, mtls.trust_anchors),
        (vec![leaf_der.clone()], vec![root.der.clone()])
    );

    let (svc, _) = build_service_with_handler(false, move |_| {
        Ok(GetCertificateResponse {
            certificate_bundle: Some(bundle.clone()),
            ..Default::default()
        })
    });
    let fe = svc
        .fetch_frontend_tls_certificate(Request::new(FetchFrontendTlsCertificateRequest {
            signed_certificate_signing_request: node.csr_der.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (fe.certificate_chain, fe.trust_anchors),
        (vec![leaf_der.clone()], vec![root.der.clone()])
    );

    for (l_der, a_der) in [
        (Vec::new(), root.der.clone()),
        (vec![0x30, 0x03, 0x01, 0x02, 0x03], root.der.clone()),
        (bad_key, root.der.clone()),
        (untrusted, root.der.clone()),
        (leaf_der.clone(), leaf_der.clone()),
        (tamper_der_signature(&leaf_der), root.der),
    ] {
        let bad = CertificateBundle {
            leaf_certificate: l_der,
            current_trust_anchor: a_der,
            ..Default::default()
        };
        assert_eq!(
            fetch_bundle(&node.csr_der, bad).await.unwrap_err().code(),
            Code::Internal
        );
    }
}

#[tokio::test]
async fn test_fetch_mtls_sub_ca_assembly_validity_and_constraints() {
    let root = make_root_ca("Mesh Root", active_window());
    let other_root = make_root_ca("Other Root", active_window());
    let sub_l1 = make_sub_ca("SubCA L1", &root, active_window());
    let sub_l2 = make_sub_ca("SubCA L2", &sub_l1, active_window());
    let extra_sub = make_sub_ca("Disconnected", &other_root, active_window());
    let node = make_csr_node("node-subca");
    let non_ca_key = make_csr_node("non-ca-sub");
    let leaf = issue_leaf(&node.key, &sub_l2, active_window(), &[TEST_SPIFFE_URI]);
    let (l1_der, l2_der, root_der) = (sub_l1.der.clone(), sub_l2.der.clone(), root.der.clone());

    let ok_bundle = CertificateBundle {
        leaf_certificate: leaf.clone(),
        sub_ca_certificates: vec![l1_der.clone(), l2_der.clone(), l1_der.clone()],
        current_trust_anchor: root_der.clone(),
        ..Default::default()
    };
    let resp = fetch_bundle(&node.csr_der, ok_bundle).await.unwrap();
    assert_eq!(
        resp.certificate_chain,
        vec![leaf.clone(), l2_der.clone(), l1_der.clone()]
    );
    assert_eq!(resp.trust_anchors, vec![root_der.clone()]);

    let exp_leaf = issue_leaf(&node.key, &sub_l1, expired_window(), &[]);
    let fut_leaf = issue_leaf(&node.key, &sub_l1, future_window(), &[]);
    let inv_leaf = issue_leaf(
        &node.key,
        &sub_l1,
        (future_window().0, expired_window().1),
        &[],
    );
    let ca_leaf = sign_ca("ca-leaf", &node.key, &sub_l1, active_window());
    let non_ca = issue_leaf(&non_ca_key.key, &root, active_window(), &[]);

    for (l_der, subs) in [
        (leaf.clone(), vec![l1_der.clone(); 9]),
        (
            leaf.clone(),
            vec![l2_der.clone(), l1_der.clone(), root_der.clone()],
        ),
        (leaf, vec![l2_der, l1_der.clone(), extra_sub.der]),
        (exp_leaf, vec![l1_der.clone()]),
        (fut_leaf, vec![l1_der.clone()]),
        (inv_leaf, vec![l1_der.clone()]),
        (ca_leaf, vec![l1_der.clone()]),
        (
            issue_leaf(&node.key, &sub_l1, active_window(), &[]),
            vec![l1_der, non_ca],
        ),
    ] {
        let bad = CertificateBundle {
            leaf_certificate: l_der,
            sub_ca_certificates: subs,
            current_trust_anchor: root_der.clone(),
            ..Default::default()
        };
        assert_eq!(
            fetch_bundle(&node.csr_der, bad).await.unwrap_err().code(),
            Code::Internal
        );
    }
}
#[tokio::test]
async fn test_fetch_mtls_rotated_trust_anchors_straggler_and_rejections() {
    let (act, exp, fut) = (active_window(), expired_window(), future_window());
    let r1 = make_root_ca("Gen1", act);
    let r2 = make_root_ca("Gen2", act);
    let sub_old = make_sub_ca("Straggler SubCA", &r1, act);
    let sub_new = make_sub_ca("SubCA Gen2", &r2, act);
    let c2p = make_cross_signed_ca(&r1, &r2, act);
    let p2c = make_cross_signed_ca(&r2, &r1, act);
    let exp_c2p = make_cross_signed_ca(&r1, &r2, exp);
    let exp_p2c = make_cross_signed_ca(&r2, &r1, exp);
    let fut_c2p = make_cross_signed_ca(&r1, &r2, fut);
    let bad_p2c = make_cross_signed_ca(&sub_new, &r1, act);

    let node = make_csr_node("node-rotation");
    let fresh_leaf = issue_leaf(&node.key, &sub_new, act, &[]);
    let strag_leaf = issue_leaf(&node.key, &sub_old, act, &[]);
    let (sub_new_der, sub_old_der, root_der) = (sub_new.der, sub_old.der, r2.der);
    let active_rot = RotatedTrustAnchor {
        current_signs_previous: c2p.clone(),
        previous_signs_current: p2c.clone(),
    };
    let expired_rot = RotatedTrustAnchor {
        current_signs_previous: exp_c2p.clone(),
        previous_signs_current: exp_p2c.clone(),
    };

    let rot_bundle = CertificateBundle {
        leaf_certificate: fresh_leaf.clone(),
        sub_ca_certificates: vec![sub_new_der.clone()],
        current_trust_anchor: root_der.clone(),
        rotated_trust_anchors: vec![active_rot.clone(), active_rot.clone(), expired_rot],
    };
    let resp = fetch_bundle(&node.csr_der, rot_bundle).await.unwrap();
    assert_eq!(
        resp.certificate_chain,
        vec![fresh_leaf.clone(), sub_new_der.clone(), p2c.clone()]
    );
    assert_eq!(resp.trust_anchors, vec![root_der.clone(), c2p.clone()]);

    let strag_bundle = CertificateBundle {
        leaf_certificate: strag_leaf.clone(),
        sub_ca_certificates: vec![sub_old_der.clone()],
        current_trust_anchor: root_der.clone(),
        rotated_trust_anchors: vec![active_rot],
    };
    let s_resp = fetch_bundle(&node.csr_der, strag_bundle).await.unwrap();
    assert_eq!(
        s_resp.certificate_chain,
        vec![strag_leaf, sub_old_der, c2p.clone()]
    );
    assert_eq!(s_resp.trust_anchors, vec![root_der.clone(), c2p.clone()]);

    let mut bad_rots = vec![vec![RotatedTrustAnchor::default(); 9]];
    for (c, p) in [
        (root_der.clone(), root_der.clone()),
        (c2p, bad_p2c),
        (fut_c2p, p2c),
        (exp_c2p, tamper_der_signature(&exp_p2c)),
    ] {
        bad_rots.push(vec![RotatedTrustAnchor {
            current_signs_previous: c,
            previous_signs_current: p,
        }]);
    }
    for rots in bad_rots {
        let bad = CertificateBundle {
            leaf_certificate: fresh_leaf.clone(),
            sub_ca_certificates: vec![sub_new_der.clone()],
            current_trust_anchor: root_der.clone(),
            rotated_trust_anchors: rots,
        };
        assert_eq!(
            fetch_bundle(&node.csr_der, bad).await.unwrap_err().code(),
            Code::Internal
        );
    }
}

#[tokio::test]
async fn test_fetch_mtls_fallback_bridge_scoping_rotation_and_rejections() {
    let act = active_window();
    let (r1, r2, fb_root) = (
        make_root_ca("Gen1", act),
        make_root_ca("Gen2", act),
        make_root_ca("FbRoot", act),
    );
    let (sub1, sub2) = (make_sub_ca("Sub1", &r1, act), make_sub_ca("Sub2", &r2, act));
    let (c2p, p2c) = (
        make_cross_signed_ca(&r1, &r2, act),
        make_cross_signed_ca(&r2, &r1, act),
    );
    let rot = vec![RotatedTrustAnchor {
        current_signs_previous: c2p.clone(),
        previous_signs_current: p2c.clone(),
    }];
    let (br_r2, br_r1) = (
        make_cross_signed_ca(&r2, &fb_root, act),
        make_cross_signed_ca(&r1, &fb_root, act),
    );
    let bad_dn_br = sign_ca("WrongDN", &r2.key, &fb_root, act);
    let n = make_csr_node("node-bridge");
    let leaf = issue_leaf(&n.key, &sub2, act, &[TEST_SPIFFE_URI]);
    let s_leaf = issue_leaf(&n.key, &sub1, act, &[TEST_SPIFFE_URI]);
    let fb_att = issue_leaf(&n.key, &sub2, act, &[TEST_SPIFFE_URI, FALLBACK_SPIFFE_URI]);
    let (sub1_der, sub_der, r2_der, fb_der) = (sub1.der, sub2.der, r2.der, fb_root.der);
    let base = (vec![leaf.clone(), sub_der.clone()], vec![r2_der.clone()]);

    let att = CertificateBundle {
        leaf_certificate: leaf.clone(),
        sub_ca_certificates: vec![sub_der.clone()],
        current_trust_anchor: r2_der.clone(),
        rotated_trust_anchors: vec![],
    };
    let fb_ok = mk_fb(&fb_der, br_r2.clone(), vec![]);
    let resp = GetCertificateResponse {
        certificate_bundle: Some(att.clone()),
        unattested_fallback: fb_ok.clone(),
        ..Default::default()
    };

    let r_on = fetch_mtls(true, &n.csr_der, resp.clone()).await.unwrap();
    assert_eq!(
        r_on.certificate_chain,
        vec![leaf.clone(), sub_der.clone(), br_r2.clone()]
    );
    assert_eq!(r_on.trust_anchors, vec![r2_der.clone(), fb_der.clone()]);
    let r_off = fetch_mtls(false, &n.csr_der, resp.clone()).await.unwrap();
    assert_eq!((r_off.certificate_chain, r_off.trust_anchors), base);

    let (svc_on, _) = build_service_with_handler(true, move |_| Ok(resp.clone()));
    let r_fe = svc_on
        .fetch_frontend_tls_certificate(Request::new(FetchFrontendTlsCertificateRequest {
            signed_certificate_signing_request: n.csr_der.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!((r_fe.certificate_chain, r_fe.trust_anchors), base);

    for (b_leaf, b_sub, mid) in [
        (leaf.clone(), sub_der, p2c),
        (s_leaf, sub1_der, c2p.clone()),
    ] {
        let rot_b = CertificateBundle {
            leaf_certificate: b_leaf.clone(),
            sub_ca_certificates: vec![b_sub.clone()],
            rotated_trust_anchors: rot.clone(),
            ..att.clone()
        };
        let rot_r = GetCertificateResponse {
            certificate_bundle: Some(rot_b),
            unattested_fallback: fb_ok.clone(),
            ..Default::default()
        };
        let r_rot = fetch_mtls(true, &n.csr_der, rot_r).await.unwrap();
        assert_eq!(
            r_rot.certificate_chain,
            vec![b_leaf, b_sub, mid, br_r2.clone()]
        );
        assert_eq!(
            r_rot.trust_anchors,
            vec![r2_der.clone(), c2p.clone(), fb_der.clone()]
        );
    }

    for (br, fl) in [
        (Vec::new(), Vec::new()),
        (br_r2.clone(), leaf.clone()),
        (br_r1, Vec::new()),
        (bad_dn_br, Vec::new()),
        (tamper_der_signature(&br_r2), Vec::new()),
    ] {
        let ign = GetCertificateResponse {
            certificate_bundle: Some(att.clone()),
            unattested_fallback: mk_fb(&fb_der, br, fl),
            ..Default::default()
        };
        let r_ign = fetch_mtls(true, &n.csr_der, ign).await.unwrap();
        assert_eq!((r_ign.certificate_chain, r_ign.trust_anchors), base);
    }

    let bad_att = CertificateBundle {
        leaf_certificate: fb_att,
        ..att
    };
    assert_eq!(
        fetch_bundle(&n.csr_der, bad_att).await.unwrap_err().code(),
        Code::Internal
    );
}

#[tokio::test]
async fn test_fetch_mtls_standalone_fallback_scoping_and_san_rejections() {
    let act = active_window();
    let (fb_root, r2) = (make_root_ca("FbRoot", act), make_root_ca("Gen2", act));
    let br_r2 = make_cross_signed_ca(&r2, &fb_root, act);
    let (fb_n, bad_n) = (make_csr_node("fb"), make_csr_node("bad"));
    let fb_leaf = issue_leaf(&fb_n.key, &fb_root, act, &[FALLBACK_SPIFFE_URI]);
    let fb_der = fb_root.der.clone();
    let fb_resp = GetCertificateResponse {
        unattested_fallback: mk_fb(&fb_der, vec![], fb_leaf.clone()),
        ..Default::default()
    };

    let r_fb = fetch_mtls(true, &fb_n.csr_der, fb_resp.clone())
        .await
        .unwrap();
    assert_eq!(
        (r_fb.certificate_chain, r_fb.trust_anchors),
        (vec![fb_leaf.clone()], vec![fb_der.clone()])
    );
    let off = fetch_mtls(false, &fb_n.csr_der, fb_resp.clone()).await;
    assert_eq!(off.unwrap_err().code(), Code::FailedPrecondition);

    let (svc_on, _) = build_service_with_handler(true, move |_| Ok(fb_resp.clone()));
    let err_fe = svc_on
        .fetch_frontend_tls_certificate(Request::new(FetchFrontendTlsCertificateRequest {
            signed_certificate_signing_request: fb_n.csr_der.clone(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err_fe.code(), Code::FailedPrecondition);

    let bad_uri = issue_leaf(&fb_n.key, &fb_root, act, &[TEST_SPIFFE_URI]);
    let multi = issue_leaf(
        &fb_n.key,
        &fb_root,
        act,
        &[FALLBACK_SPIFFE_URI, TEST_SPIFFE_URI],
    );
    let no_san = issue_leaf(&fb_n.key, &fb_root, act, &[]);
    let bad_key = issue_leaf(&bad_n.key, &fb_root, act, &[FALLBACK_SPIFFE_URI]);
    let ca_leaf = sign_ca("ca-leaf", &fb_n.key, &fb_root, act);
    for (br, leaf) in [
        (vec![], bad_uri),
        (vec![], multi),
        (vec![], no_san),
        (vec![], bad_key),
        (vec![], ca_leaf),
        (vec![], tamper_der_signature(&fb_leaf)),
        (br_r2, fb_leaf),
        (vec![], vec![]),
    ] {
        let bad = GetCertificateResponse {
            unattested_fallback: mk_fb(&fb_der, br, leaf),
            ..Default::default()
        };
        let err = fetch_mtls(true, &fb_n.csr_der, bad).await.unwrap_err();
        assert_eq!(err.code(), Code::Internal);
    }
}

async fn fetch_mtls(
    allow_fallback: bool,
    csr: &[u8],
    resp: GetCertificateResponse,
) -> Result<FetchTlsCertificateResponse, Status> {
    let (svc, _) = build_service_with_handler(allow_fallback, move |_| Ok(resp.clone()));
    svc.fetch_mtls_certificate(Request::new(FetchTlsCertificateRequest {
        signed_certificate_signing_request: csr.to_vec(),
    }))
    .await
    .map(tonic::Response::into_inner)
}

async fn fetch_bundle(
    csr: &[u8],
    bundle: CertificateBundle,
) -> Result<FetchTlsCertificateResponse, Status> {
    fetch_mtls(
        false,
        csr,
        GetCertificateResponse {
            certificate_bundle: Some(bundle),
            ..Default::default()
        },
    )
    .await
}

fn mk_fb(anchor: &[u8], bridge: Vec<u8>, leaf: Vec<u8>) -> Option<UnattestedFallbackBundle> {
    Some(UnattestedFallbackBundle {
        fallback_trust_anchor: anchor.to_vec(),
        fallback_bridge_certificate: bridge,
        fallback_leaf_certificate: leaf,
    })
}
