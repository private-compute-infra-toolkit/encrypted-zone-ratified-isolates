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

use std::future::Future;
use std::time::Duration;
use tokio_retry::strategy::{jitter, FixedInterval};
use tokio_retry::RetryIf;
use tonic::{Code, Status};

// Matches C++ IsolateEzBridge gRPC retry policy (5 maxAttempts = 1 initial + 4
// retries, 300ms backoff with 1.0 backoffMultiplier and uniform jitter).
const BRIDGE_MAX_RETRIES: usize = 4;
const BRIDGE_RETRY_BACKOFF: Duration = Duration::from_millis(300);

/// Per the `IsolateEzBridge` contract, only `UNAVAILABLE` is safe to retry
/// automatically (codes like `ABORTED` indicate invalid state transitions).
pub(crate) fn is_retryable_bridge_status(status: &Status) -> bool {
    status.code() == Code::Unavailable
}

/// Returns the standard `IsolateEzBridge` retry backoff strategy.
pub(crate) fn bridge_retry_strategy() -> impl Iterator<Item = Duration> {
    FixedInterval::new(BRIDGE_RETRY_BACKOFF).map(jitter).take(BRIDGE_MAX_RETRIES)
}

/// Executes an idempotent `IsolateEzBridge` control-plane RPC with bounded
/// retries on transient `UNAVAILABLE` errors.
///
/// Note: Do not wrap `InvokeEz` (whose shared-memory request slots are freed by
/// the Enforcer on first read; see TODO(b/579495779)) or streaming RPCs whose
/// request streams cannot be replayed.
pub(crate) async fn retry_bridge_rpc<T, F, Fut>(operation: &str, action: F) -> Result<T, Status>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, Status>>,
{
    RetryIf::start(bridge_retry_strategy(), action, |status: &Status| {
        let retryable = is_retryable_bridge_status(status);
        if retryable {
            log::warn!(
                "{operation} returned UNAVAILABLE ({}); retrying if attempts remain",
                status.message()
            );
        }
        retryable
    })
    .await
}
