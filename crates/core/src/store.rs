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

#[cfg(test)]
mod store_test_utils {
    use std::collections::BTreeMap;
    use std::io;

    use super::*;

    #[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct MockStore {
        pub btreemap: BTreeMap<String, Vec<u8>>,
    }

    impl Store for MockStore {
        fn read(&self, key: &str) -> Result<Vec<u8>, BoxError> {
            self.btreemap.get(key).cloned().ok_or_else(|| {
                let err = io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no value found for key {key:?}"),
                );
                let err: BoxError = Box::new(err);
                err
            })
        }

        fn write(&mut self, key: &str, value: &[u8]) -> Result<(), BoxError> {
            self.btreemap.insert(key.to_owned(), value.to_vec());
            Ok(())
        }
    }
}

#[cfg(test)]
mod store_tests {
    use self::store_test_utils::MockStore;
    use super::*;

    #[test]
    fn namespaced_store() {
        let mock_store = MockStore::default();
        let mut namespaced = NamespacedStore::new("test-app", mock_store);

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
