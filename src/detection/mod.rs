pub mod pipeline;
pub mod scanner;
pub mod threat;

// Re-export common types for convenience
pub use threat::{ThreatLevel, ThreatMatch, ThreatResponse};
