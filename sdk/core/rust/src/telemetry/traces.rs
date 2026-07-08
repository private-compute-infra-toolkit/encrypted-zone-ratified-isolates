// Copyright 2025 Google LLC
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
use anyhow::Result;
use enforcer_proto::enforcer::v1::ControlPlaneMetadata;
use opentelemetry::global;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::{SpanExporter, WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{SdkTracerProvider, TraceError};
use opentelemetry_sdk::Resource;
use std::collections::HashMap;
use tonic::metadata::MetadataMap;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{prelude::*, EnvFilter, Registry};

const CONNECT_RETRY_COUNT: usize = 10;
const CONNECT_RETRY_DELAY_MS: u64 = 5000;
const CONNECT_RETRY_SCALING: u64 = 1;

async fn setup_tracer(
    endpoint: &str,
    service_name: &str,
    sample_probability: f64,
) -> Result<SdkTracerProvider, TraceError> {
    let mut exporter_builder = SpanExporter::builder().with_tonic();

    if endpoint.starts_with("unix:") {
        let channel_pool = GrpcChannelPool::new(
            endpoint.to_string(),
            DEFAULT_POOL_SIZE,
            CONNECT_RETRY_COUNT,
            CONNECT_RETRY_DELAY_MS,
            CONNECT_RETRY_SCALING,
        )
        .await
        .map_err(|e| TraceError::Other(e.into()))?;
        let channel = channel_pool.next_channel();

        exporter_builder = exporter_builder.with_channel(channel);
    } else {
        exporter_builder = exporter_builder.with_endpoint(endpoint);
    }
    let exporter = exporter_builder.build().map_err(|e| TraceError::Other(e.into()))?;

    let resource = Resource::builder().with_service_name(service_name.to_string()).build();

    let sampler = opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(sample_probability);

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .with_sampler(opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(sampler)))
        .build();

    global::set_text_map_propagator(TraceContextPropagator::new());
    global::set_tracer_provider(provider.clone());

    Ok(provider)
}

/// Initializes the global OpenTelemetry TracerProvider and tracing subscriber.
///
/// If an endpoint is provided, it configures an OTLP exporter to send traces to that endpoint.
/// It also sets up a tracing subscriber with an `EnvFilter` and the OpenTelemetry layer.
pub async fn setup_traces(
    service_name: &str,
    endpoint: &Option<String>,
    sample_probability: f64,
) -> anyhow::Result<SdkTracerProvider> {
    // 1. Initialize OpenTelemetry tracing IF an endpoint is provided.
    let (telemetry_layer, tracer_provider) = if let Some(endpoint) = endpoint {
        if endpoint.is_empty() || endpoint == "none" || endpoint == "disabled" {
            log::info!("OTel traces endpoint is '{}', skipping traces configuration.", endpoint);
            (None, SdkTracerProvider::builder().build())
        } else {
            match setup_tracer(endpoint, service_name, sample_probability).await {
                Ok(provider) => {
                    let tracer = provider.tracer(service_name.to_string());
                    let filter = EnvFilter::new("debug,h2=info");
                    let layer =
                        tracing_opentelemetry::layer().with_tracer(tracer).with_filter(filter);
                    (Some(layer), provider)
                }
                Err(e) => {
                    log::error!("Failed to initialize tracer: {:?}. Tracing is disabled.", e);
                    (None, SdkTracerProvider::builder().build())
                }
            }
        }
    } else {
        log::info!("Telemetry endpoint not provided. Tracing is disabled.");
        (None, SdkTracerProvider::builder().build())
    };

    // 2. Register whatever layers were successfully configured.
    // Registry::default() builds the base subscriber. We optionally add our layers to it.
    let subscriber = Registry::default().with(telemetry_layer);

    // 3. Set the global tracing subscriber.
    // We ignore errors here because `set_global_default` will fail if it's called
    // multiple times in the same process, which happens frequently during unit tests.
    let _ = tracing::subscriber::set_global_default(subscriber);

    Ok(tracer_provider)
}

/// Extracts the active tracing span's context and serializes it into a HashMap for propagation.
pub fn get_trace_context() -> HashMap<String, String> {
    let mut metadata_headers = HashMap::new();
    let context = tracing::Span::current().context();
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&context, &mut metadata_headers);
    });
    metadata_headers
}

/// Extracts trace context from a HashMap of headers and sets it as the parent of the given span.
pub fn extract_and_set_parent_from_map(span: &tracing::Span, headers: &HashMap<String, String>) {
    let parent_context = global::get_text_map_propagator(|propagator| propagator.extract(headers));
    let _ = span.set_parent(parent_context);
}

/// Extracts trace context from ControlPlaneMetadata and sets it as the parent of the given span.
pub fn extract_and_set_parent(span: &tracing::Span, metadata: Option<&ControlPlaneMetadata>) {
    if let Some(metadata) = metadata {
        extract_and_set_parent_from_map(span, &metadata.metadata_headers);
    }
}

/// Converts a tonic MetadataMap into a HashMap of String key-value pairs (ASCII only).
pub fn metadata_to_hashmap(metadata: &MetadataMap) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for key_and_value in metadata.iter() {
        if let tonic::metadata::KeyAndValueRef::Ascii(key, value) = key_and_value {
            if let Ok(value_str) = value.to_str() {
                map.insert(key.as_str().to_string(), value_str.to_string());
            }
        }
    }
    map
}
