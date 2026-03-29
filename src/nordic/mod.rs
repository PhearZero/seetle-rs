#[cfg(feature = "nordic")]
pub mod backend;

#[cfg(feature = "nordic")]
pub use backend::NordicBackend;
