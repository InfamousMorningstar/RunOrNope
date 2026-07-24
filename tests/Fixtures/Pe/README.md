# PE fixtures

PE tests generate harmless, minimal byte arrays in memory or inspect the already-built test
assembly. No downloaded binaries or malware samples belong in this directory.

Fixtures deliberately cover truncated headers, overflowing ranges, invalid directories,
overlays, CLR metadata, bounded method inventories, and trust-backend seams. They are never
executed by the analyzer.
