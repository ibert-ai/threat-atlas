//! ATLAS-OSINT-013 - PhishTank phishing layer.
//!
//! Stub created by CL on 14 November 2026 so that every source lives in its own file and no two
//! agents edit the same file (see handover ATLAS-CL-OSINT-DISTRIBUTION-20261114-01).
//! The owner named in that handover fills this file. Rules for this file:
//!
//! - Pure functions only: parsers, filters, caps and decisions. No network, no clock, no file system.
//! - Tests use fixtures; live provider checks are manual and documented.
//! - Skip malformed records instead of failing; bound every list and string.
//! - No keys, tokens or personal data in source, fixtures or tests.
//! - The registry entry (licence, attribution, minimum interval, key requirement) is added to
//!   `osint.rs` by the integrator (CL), not here. Put the proposed values in a doc comment.
//! - Do not edit `osint.rs`, `lib.rs`, `soc_osint.rs` or `soc_host.rs` from this branch.
