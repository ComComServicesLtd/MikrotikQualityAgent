//! Wire protocols spoken by the probe data plane.
//!
//! [`mqp`] is the native format (see `docs/protocol.md`); `twamp` will add
//! RFC 5357 unauthenticated mode for interop with MikroTik's own TWAMP
//! reflector and third-party gear.

pub mod mqp;
