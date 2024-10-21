//! Middleware specific storage.

use alloc::format;
use alloc::vec::Vec;

use super::BoxError;

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

    /// Return the namespace of this [`NamespacedStore`].
    pub fn namespace(&self) -> &'namespace str {
        self.namespace
    }

    /// Return a reference to the inner store.
    pub fn inner(&self) -> &S {
        &self.store
    }

    /// Return a mutable reference to the inner store.
    pub fn inner_mut(&mut self) -> &S {
        &mut self.store
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

#[cfg(test)]
mod store_tests {
    use super::*;
    use crate::test_utils::MockStore;

    #[test]
    fn namespaced_store() {
        let mock_store = MockStore::default();
        let mut namespaced = mock_store.namespaced("test-app");

        _ = namespaced.write("ganda", b"cena");
        _ = namespaced.write("de boa", b"velho");
        _ = namespaced.write("aew", b"mermau");

        assert!(namespaced
            .store
            .btreemap
            .keys()
            .all(|k| k.starts_with("test-app/")));
    }
}
