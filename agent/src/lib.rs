//! Remote TCP/UDP network quality testing agent for MikroTik RouterOS
//! containers.
//!
//! The library half exists so the wire codec and the statistics maths can be
//! unit-tested on the host without cross-compiling for armv7.

pub mod agent;
pub mod cli;
pub mod collector;
pub mod controller;
pub mod discovery;
pub mod config;
pub mod probe;
pub mod proto;
pub mod routeros;
pub mod spool;
pub mod tasks;
