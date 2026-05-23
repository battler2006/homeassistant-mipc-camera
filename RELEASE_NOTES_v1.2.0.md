## v1.2.0

Maintained fork release for Home Assistant compatibility and current MIPC connectivity.

### Fixed

- Restored Home Assistant config flow loading.
- Replaced js2py-based runtime logic with pure Python helpers for Python 3.14 compatibility.
- Added bootstrap fallback from failing legacy TLS endpoint to usable MIPC signal hosts.
- Fixed JavaScript-compatible NID/session encoding so camera stream and still images no longer fail with InvalidSession.
- Added local brand assets required by HACS validation.
- Improved login and API error handling.

### Changed

- Updated manifest metadata to point to the maintained battler2006 fork.
- Published maintained fork as version 1.2.0.

### Notes

- Domain remains `mipc_camera` for compatibility with existing Home Assistant entities and config entries.
- Home Assistant may still show a small delay for live view depending on stream handling.