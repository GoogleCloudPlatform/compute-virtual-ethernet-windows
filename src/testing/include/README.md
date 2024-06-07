# Additional Headers

Files here are globbed by the `additional-headers` build rule, and made
available to the driver build targets. The `gvnic_library` build macro
automatically includes this directory via the `includes = [ ... ]` attribute,
but targets using these headers must also depend on the
`additional-headers` library.

Most files in this directory are intentionally left blank.
