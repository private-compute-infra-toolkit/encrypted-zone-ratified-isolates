# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Bazel macro for creating an isolate package"""

load("@oak//bazel:defs.bzl", "oci_runtime_bundle")
load("@rules_oci//oci:defs.bzl", "oci_image")
load("@rules_pkg//pkg:mappings.bzl", "pkg_attributes", "pkg_files")
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")

def isolate_package(base_name, binary, install_path = "/usr/local/bin"):
    """Packages a binary into an OCI runtime bundle and copies it to dist.

    Creates [[base_name]_isolate]: _bin, _tar, _image, _bundle, and _bundle.tar
    _bin saved to install_path
    Sets up dist/artifacts/isolate_rootfs.tar
    Also creates a genrule "copy_to_dist"

    Args:
        name: The base name of the package names
        binary: The label of the rust_binary target to package.
        install_path: The path where the binary will be installed inside the image
    """
    isolate_name = "{}_isolate".format(base_name)

    pkg_files(
        name = "{}_bin".format(isolate_name),
        srcs = [binary],
        attributes = pkg_attributes(mode = "0500"),
        prefix = install_path,
    )

    user = get_user(user = "root")

    pkg_tar(
        name = "{}_tar".format(isolate_name),
        srcs = [":{}_bin".format(isolate_name)],
        owner = "{}.{}".format(user.uid, user.gid),
    )

    oci_image(
        name = "{}_image".format(isolate_name),
        base = "@isolate_runtime_ubuntu_base",
        tars = [":{}_tar".format(isolate_name)],
    )

    oci_runtime_bundle(
        name = "{}_bundle".format(isolate_name),
        image = ":{}_image".format(isolate_name),
        visibility = ["//visibility:public"],
    )

    native.genrule(
        name = "copy_to_dist",
        srcs = [":{}_bundle.tar".format(isolate_name)],
        outs = ["copy_to_dist.bin"],
        cmd_bash = """cat <<EOF >'$@'
mkdir -p dist/artifacts
cp -f $(execpath :{}_bundle.tar) dist/artifacts/isolate_rootfs.tar
EOF""".format(isolate_name),
        executable = True,
        local = True,
        message = "Copying artifacts to dist dir",
    )

DISTROLESS_USERS = [
    struct(
        flavor = "nonroot",
        uid = 65532,
        user = "nonroot",
        gid = 65532,
        group = "nonroot",
    ),
    struct(
        flavor = "root",
        uid = 0,
        user = "root",
        gid = 0,
        group = "root",
    ),
]

def get_user(user = "nonroot"):
    """
    Extracts a struct with details from DISTROLESS_USERS based on the given user.

    Args:
      user: The user to search for (e.g., "root" or "nonroot").

    Returns:
      The struct with the matching user, or None if no match is found.
    """
    for entry in DISTROLESS_USERS:
        if entry.user == user:
            return entry
    return None
