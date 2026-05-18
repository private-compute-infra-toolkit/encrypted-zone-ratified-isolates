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

use anyhow::Result;
use grpc_connector::{
    GrpcChannelPool, DEFAULT_CONNECT_RETRY_COUNT, DEFAULT_CONNECT_RETRY_DELAY_MS,
    DEFAULT_CONNECT_RETRY_SCALING, DEFAULT_POOL_SIZE,
};
use opentelemetry::global;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::{SpanExporter, WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{SdkTracerProvider, TraceError};
use opentelemetry_sdk::Resource;
use tracing_subscriber::{prelude::*, EnvFilter, Registry};

async fn init_tracer(
    endpoint: &str,
    service_name: &str,
    sample_probability: f64,
) -> Result<SdkTracerProvider, TraceError> {
    let mut exporter_builder = SpanExporter::builder().with_tonic();

    if endpoint.starts_with("unix:") {
        let channel_pool = GrpcChannelPool::new(
            endpoint.to_string(),
            DEFAULT_POOL_SIZE,
            DEFAULT_CONNECT_RETRY_COUNT,
            DEFAULT_CONNECT_RETRY_DELAY_MS,
            DEFAULT_CONNECT_RETRY_SCALING,
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

pub async fn setup_telemetry(
    service_name: &str,
    endpoint: &Option<String>,
    sample_probability: f64,
) -> anyhow::Result<SdkTracerProvider> {
    // 1. Initialize OpenTelemetry tracing IF an endpoint is provided.
    let (telemetry_layer, tracer_provider) = if let Some(endpoint) = endpoint {
        let tracer_provider = init_tracer(endpoint, service_name, sample_probability).await?;
        let tracer = tracer_provider.tracer(service_name.to_string());
        let filter = EnvFilter::new("debug,h2=info");
        let layer = tracing_opentelemetry::layer().with_tracer(tracer).with_filter(filter);
        (Some(layer), tracer_provider)
    } else {
        (None, SdkTracerProvider::builder().build())
    };

    // 3. Register whatever layers were successfully configured.
    // Registry::default() builds the base subscriber. We optionally add our layers to it.
    let subscriber = Registry::default().with(telemetry_layer);

    // 4. Set the global tracing subscriber.
    // We ignore errors here because `set_global_default` will fail if it's called
    // multiple times in the same process, which happens frequently during unit tests.
    let _ = tracing::subscriber::set_global_default(subscriber);

    Ok(tracer_provider)
}
