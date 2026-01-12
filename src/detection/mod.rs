pub mod threat;
pub mod scanner;
pub mod pipeline;

// Re-export common types for convenience
pub use threat::{ThreatLevel, ThreatResponse, ThreatMatch};
