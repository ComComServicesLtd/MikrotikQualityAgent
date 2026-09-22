//! Network discovery: collecting local state from the host router and
//! reducing it to explanations.
//!
//! An operator asking "why is this site slow" is not helped by an inventory.
//! Collectors gather raw RouterOS state; [`findings`] turns it into a short,
//! ranked list of things that are actually wrong.

pub mod collect;
pub mod findings;
pub mod tools;
