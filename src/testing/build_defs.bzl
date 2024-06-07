"""Build definitions for gVNIC Windows driver source code on Linux."""

load("//devtools/build_cleaner/skylark:build_defs.bzl", "register_extension_info")

def gvnic_library(name, srcs = None, hdrs = None, textual_hdrs = None, deps = None):
    """Create a C++ library for testing using a mocked NDIS framework."""

    native.cc_library(
        name = name,
        srcs = srcs,
        hdrs = hdrs,
        textual_hdrs = textual_hdrs,
        testonly = 1,
        deps = deps,
        copts = ["-Wno-non-virtual-dtor"],  # MSBuild handles this gracefully
        includes = [
            "testing",
            "testing/include",
        ],
        defines = [
            "MAJOR_DRIVER_VERSION=0",
            "MINOR_DRIVER_VERSION=9",
            "RELEASE_VERSION=5",
            "RELEASE_VERSION_QEF=123",
            "NDIS_SUPPORT_NDIS61",  # There is no trailing zero.
            "NDIS_SUPPORT_NDIS620",
            "NDIS_SUPPORT_NDIS630",
            "NDIS_MINIPORT_MAJOR_VERSION=6",
            "NDIS_MINIPORT_MINOR_VERSION=30",
        ],
    )

register_extension_info(
    extension = gvnic_library,
    label_regex_for_dep = "{extension_name}",
)
