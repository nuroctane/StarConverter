//! Internal capsule-persistence fault boundaries.
//!
//! Only the no-fault implementation is reachable in production. Deterministic injectors are
//! compiled solely for the capsule store's unit tests so recovery can be qualified at each I/O
//! ordering boundary without exposing a fault-injection API to callers.

use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsuleFaultBoundary {
    BeforeWrite,
    AfterWrite,
    AfterSyncData,
    AfterReadback,
    AfterSyncAll,
    BeforeAdopt,
}

pub trait CapsuleFaultInjector {
    fn hit(&mut self, boundary: CapsuleFaultBoundary) -> io::Result<()>;
}

#[derive(Debug, Default)]
pub struct NoCapsuleFault;

impl CapsuleFaultInjector for NoCapsuleFault {
    fn hit(&mut self, _boundary: CapsuleFaultBoundary) -> io::Result<()> {
        Ok(())
    }
}
