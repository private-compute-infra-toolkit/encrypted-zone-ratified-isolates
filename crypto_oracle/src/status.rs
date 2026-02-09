// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use status_proto::enforcer::v1::Status;
use tink_core::TinkError;

/* TODO: Use enums for status code, once status is moved to a common EZ location
 * See: b/425442136, b/421253802, https://cs/google3/google/rpc/code.proto
 * Enum provided below following the same pattern, with example use cases
 */
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Code {
    Ok = 0,                 // Success
    InvalidArgument = 3,    // Bad / malformed argument
    NotFound = 5,           // Key ID doesn't exist
    AlreadyExists = 6,      // Key ID already exists
    PermissionDenied = 7,   // Scope not allowed
    FailedPrecondition = 9, // Bad key type
    Unimplemented = 12,     // Not implemented yet
    Internal = 13,          // Misc internal error (generic tink)
}

pub fn create_status(code: Code, message: &str) -> Status {
    Status { code: code as i32, message: message.to_string() }
}
pub fn tink_err_status(message: &str, err: TinkError) -> Status {
    Status { code: Code::Internal as i32, message: message.to_string() + ": " + &err.to_string() }
}
