//! Middleware specific storage.

use core::error::Error;

use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;

/// Type alias for a boxed [`Error`].
pub type BoxError = Box<dyn Error + Send + Sync>;

/// Key-value store of data belonging to an IBC middleware.
///
/// Library users should namespace the keys utilized by each
/// middleware, to avoid key conflicts.
pub trait Store {
    /// Read some value from the store.
    fn read(&self, key: &str) -> Result<Vec<u8>, BoxError>;

    /// Write some value to the store.
    fn write(&mut self, key: &str, value: &[u8]) -> Result<(), BoxError>;
}

/// Store implementation whose keys are namespaced.
#[derive(Debug)]
pub struct NamespacedStore<'namespace, S> {
    namespace: &'namespace str,
    store: S,
}

impl<'namespace, S> NamespacedStore<'namespace, S> {
    /// Create a new namespace key-value store, wrapping an
    /// existing store implementation.
    pub const fn new(namespace: &'namespace str, store: S) -> Self {
        Self { namespace, store }
    }
}

impl<S: Store> Store for NamespacedStore<'_, S> {
    #[inline]
    fn read(&self, key: &str) -> Result<Vec<u8>, BoxError> {
        self.store.read(&format!("{}/{}", self.namespace, key))
    }

    #[inline]
    fn write(&mut self, key: &str, value: &[u8]) -> Result<(), BoxError> {
        self.store
            .write(&format!("{}/{}", self.namespace, key), value)
    }
}
