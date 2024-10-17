//! Core crate defining IBC middleware types and traits.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod ics26_callbacks;
pub mod ics26_router;
pub mod store;

/*
use self::metadata::Metadata;
use self::store::Store;

/// IBC middleware definition.
pub trait Middleware: IbcCoreModule {
    /// Middleware metadata. This is required to be
    /// able to namespace the store data pertaining
    /// to some IBC middleware.
    type Metadata: Metadata;

    /// Key-value store of data pertaining to the middleware.
    type Store: Store<Self::Metadata>;

    /// Return a reference to the [`Store`].
    fn store(&self) -> &Self::Store;

    /// Return a mutable reference to the [`Store`].
    fn store_mut(&mut self) -> &mut Self::Store;
}
*/
