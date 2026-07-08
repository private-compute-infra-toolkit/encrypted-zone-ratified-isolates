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

use crate::telemetry::grpc_connector::{GrpcChannelPool, DEFAULT_POOL_SIZE};
use opentelemetry::global;
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::Resource;

const CONNECT_RETRY_COUNT: usize = 10;
const CONNECT_RETRY_DELAY_MS: u64 = 5000;
const CONNECT_RETRY_SCALING: u64 = 1;

/// Initializes the global OpenTelemetry MeterProvider.
///
/// If an endpoint is provided, it configures an OTLP exporter to send metrics to that endpoint
/// and records an initial heartbeat metric to verify connectivity..
pub async fn setup_metrics(service_name: &str, endpoint: Option<String>) {
    let Some(endpoint) = endpoint else {
        log::info!("OTel metrics endpoint is not provided, skipping metrics configuration.");
        return;
    };

    if endpoint.is_empty() || endpoint == "none" || endpoint == "disabled" {
        log::info!("OTel metrics endpoint is '{}', skipping metrics configuration.", endpoint);
        return;
    }

    log::info!(
        "Initializing SDK metrics exporter for service '{}' targeting endpoint: {}",
        service_name,
        endpoint
    );

    let mut exporter_builder = opentelemetry_otlp::MetricExporter::builder().with_tonic();

    if endpoint.starts_with("unix:") {
        let channel_pool = match GrpcChannelPool::new(
            endpoint.to_string(),
            DEFAULT_POOL_SIZE,
            CONNECT_RETRY_COUNT,
            CONNECT_RETRY_DELAY_MS,
            CONNECT_RETRY_SCALING,
        )
        .await
        {
            Ok(pool) => pool,
            Err(e) => {
                log::error!("FATAL: Failed to initialize OTel metrics: {:?}", e);
                std::process::exit(1);
            }
        };
        let channel = channel_pool.next_channel();
        exporter_builder = exporter_builder.with_channel(channel);
    } else {
        exporter_builder = exporter_builder.with_endpoint(endpoint);
    }

    let exporter_res = exporter_builder.build();

    let exporter = match exporter_res {
        Ok(exp) => exp,
        Err(e) => {
            log::error!(
                "FATAL: Failed to initialize OTel metrics: failed to construct exporter: {:?}",
                e
            );
            std::process::exit(1);
        }
    };

    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter).build();

    let resource = Resource::builder().with_service_name(service_name.to_string()).build();

    let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build();

    global::set_meter_provider(provider.clone());
    log::info!("Global OpenTelemetry MeterProvider configured.");

    // Record an initial metric to verify the path to the enforcer
    let meter = global::meter("encrypted_zone.ratified_isolate_sdk");
    let heartbeat = meter
        .u64_counter("encrypted_zone.ratified_isolate.init_heartbeat")
        .with_description("Sent upon successful initialization of the OTel stack.")
        .build();
    heartbeat.add(1, &[]);

    // Force flush to ensure the heartbeat is sent immediately
    if let Err(e) = provider.force_flush() {
        log::warn!("Failed to flush initial heartbeat metric: {:?}", e);
    } else {
        log::info!("Initial heartbeat metric sent to enforcer.");
    }
}
