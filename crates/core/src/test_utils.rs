use std::collections::BTreeMap;
use std::io;

use super::BoxError;
use crate::store::{NamespacedStore, Store};

#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MockStore {
    pub btreemap: BTreeMap<String, Vec<u8>>,
}

impl MockStore {
    pub const fn namespaced(self, namespace: &str) -> NamespacedStore<'_, Self> {
        NamespacedStore::new(namespace, self)
    }
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
