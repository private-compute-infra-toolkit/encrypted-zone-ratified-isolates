#!/bin/bash
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit

declare -r PREFIX='{"reason":"compiler-message","package_id":"","target":{"kind":[""],"crate_types":[""],"name":"","src_path":"","edition":"2021","doc":true,"doctest":true,"test":true},"message":'
declare -r SUFFIX='}'
declare -r SAVED_FILE="$1"
declare -r PATH_PREFIX="$2"
declare -r OUTPUT_BASE="$3"

# List of known sub-repositories that are separate Bazel workspaces
declare -r SUB_REPOS=("approver" "crypto_oracle" "noise_session_manager")

# see https://bazel.build/run/scripts
declare -r BAZEL_BUILD_FAILED_ERROR_CODE=1
declare -r BAZEL_SUCCESS_CODE=0

function run_analyzer() {
  local project_root="${PATH_PREFIX}"
  local file_rel_path="${SAVED_FILE/#"${PATH_PREFIX}/"}"
  local output_base="${OUTPUT_BASE}"

  # Check for known sub-repos
  for sub_repo in "${SUB_REPOS[@]}"; do
    if [[ "${file_rel_path}" == "${sub_repo}/"* ]]; then
      project_root="${PATH_PREFIX}/${sub_repo}"
      file_rel_path="${file_rel_path/#"${sub_repo}/"}"
      output_base="${OUTPUT_BASE}_${sub_repo}"
      cd "${project_root}" || exit 1
      break
    fi
  done

  # If we are in a sub-repo, we need to make sure the relative path is correct
  declare -r FILE_PATH="${file_rel_path}"
  declare -r FILE_TARGET="$(bazel query "${FILE_PATH}")"
  declare -r BAZEL_TARGET="$(bazel query "attr('srcs', ${FILE_TARGET}, ${FILE_TARGET//:*/}:*)")"
  set +o errexit
  rustfmt "${FILE_PATH}"
  bazel --output_base="${output_base}" build --@rules_rust//rust/settings:error_format=json "${BAZEL_TARGET}"
  declare -r -i RC=$?
  set -o errexit
  if [[ ${RC} -eq ${BAZEL_BUILD_FAILED_ERROR_CODE} ]]; then
    STD_ERR_DIR="${output_base}/execroot/_main/bazel-out/_tmp/actions"
    if [[ ! -d "${STD_ERR_DIR}" ]]; then
        # Fallback for older Bazel versions or different layouts (e.g. WORKSPACE vs MODULE.bazel)
        # We try to find the execroot dir using wildcard
        STD_ERR_DIR="${output_base}/execroot/*/bazel-out/_tmp/actions"
    fi
    # Use glob expansion safely
    if ls "${STD_ERR_DIR}"/stderr-* 1> /dev/null 2>&1; then
      cat "${STD_ERR_DIR}"/stderr-* | while read -r line; do
        printf "%s%s%s\n" "${PREFIX}" "${line}" "${SUFFIX}"
      done
    fi
  elif [[ ${RC} -ne ${BAZEL_SUCCESS_CODE} ]]; then
    # TODO: update debug instructions when we can reproduce error and try bazel clean
    printf "XXXXXX rust-analyzer is out of sync, please try 'rm -rf \"%s\"' and save again XXXXXX\n" "${output_base}"
    exit ${RC}
  fi
}

run_analyzer
