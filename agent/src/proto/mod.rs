//! Wire protocols spoken by the probe data plane.
//!
//! [`mqp`] is the native format (see `docs/protocol.md`). [`twamp`] implements
//! RFC 5357 unauthenticated mode for interop with carrier responders and test
//! sets — and so that a MikroTik can answer TWAMP at all, since RouterOS 7.x
//! provides no TWAMP menu and no package supplies one.

pub mod mqp;
pub mod twamp;
