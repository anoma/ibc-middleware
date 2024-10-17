//! ICS-26 module callbacks.

use ibc_core_router::module::Module as IbcCoreModule;

use crate::store::Store;

/// Module callbacks, as specified in ICS-26.
pub trait Module: IbcCoreModule {
    /// Return a reference to the [`Store`].
    fn store(&self) -> &dyn Store;

    /// Return a mutable reference to the [`Store`].
    fn store_mut(&mut self) -> &mut dyn Store;

    /// Upcast to a [core IBC module](IbcCoreModule).
    fn upcast_to_core(&self) -> &dyn IbcCoreModule;

    /// Upcast (mutably) to a [core IBC module](IbcCoreModule).
    fn upcast_to_core_mut(&mut self) -> &mut dyn IbcCoreModule;
}
