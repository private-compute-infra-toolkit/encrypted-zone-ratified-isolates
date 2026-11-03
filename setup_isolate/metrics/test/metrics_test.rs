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

use ez_mtls_proto::enforcer::v1::PolicyHint;
use metrics::{
    AVS_PROXY_RPC_LATENCIES_NAME, CERTIFICATE_FETCH_COUNT_NAME, Metrics,
    PES_VALIDATION_OUTCOME_NAME, RPC_COUNT_NAME, RPC_LATENCIES_NAME,
};
use opentelemetry::global;
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
use setup_isolate_proto::setup_isolate::v1::validate_isolate_endorsement_response::IsolateEndorsementValidationError;

#[test]
fn test_metrics_recording_and_validation() {
    let exporter = InMemoryMetricExporter::default();
    let reader = PeriodicReader::builder(exporter.clone()).build();
    let provider = SdkMeterProvider::builder().with_reader(reader).build();
    global::set_meter_provider(provider.clone());
    let metrics = Metrics::default();

    metrics.record_rpc_call("GetTlsCsr", "UNIMPLEMENTED");
    metrics.record_certificate_fetch(PolicyHint::BackendMtlsCert, "OK");
    metrics.record_pes_validation_outcome(IsolateEndorsementValidationError::Unspecified);
    metrics.record_rpc_latency("GetTlsCsr", 0.0125);
    metrics.record_avs_proxy_latency(0.045);

    provider.force_flush().expect("Flush failed");

    let finished_metrics = exporter
        .get_finished_metrics()
        .expect("Failed to get finished metrics");
    let metric_names: Vec<&str> = finished_metrics
        .iter()
        .flat_map(|rm| rm.scope_metrics())
        .flat_map(|sm| sm.metrics())
        .map(|m| m.name())
        .collect();

    assert!(
        metric_names.contains(&RPC_COUNT_NAME),
        "Missing {}",
        RPC_COUNT_NAME
    );
    assert!(
        metric_names.contains(&CERTIFICATE_FETCH_COUNT_NAME),
        "Missing {}",
        CERTIFICATE_FETCH_COUNT_NAME
    );
    assert!(
        metric_names.contains(&PES_VALIDATION_OUTCOME_NAME),
        "Missing {}",
        PES_VALIDATION_OUTCOME_NAME
    );
    assert!(
        metric_names.contains(&RPC_LATENCIES_NAME),
        "Missing {}",
        RPC_LATENCIES_NAME
    );
    assert!(
        metric_names.contains(&AVS_PROXY_RPC_LATENCIES_NAME),
        "Missing {}",
        AVS_PROXY_RPC_LATENCIES_NAME
    );
}

#[test]
fn test_metric_name_macro() {
    assert_eq!(
        metrics::metric_name!("sample_metric"),
        "encrypted_zone.ratified_isolate.setup_isolate.sample_metric"
    );
}
