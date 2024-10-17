//! ICS-26 router.

use ibc_core_host_types::identifiers::PortId;
use ibc_core_router::module::Module as IbcCoreModule;
use ibc_core_router::router::Router as IbcCoreRouter;
use ibc_core_router_types::module::ModuleId;

use crate::ics26_callbacks::Module;

/// Router, as specified in ICS-26, which binds modules to ports.
pub trait Router {
    /// Return a reference to a [`Module`] registered against the specified [`ModuleId`].
    fn get_route(&self, module_id: &ModuleId) -> Option<&dyn Module>;

    /// Return a mutable reference to a [`Module`] registered against the specified [`ModuleId`].
    fn get_route_mut(&mut self, module_id: &ModuleId) -> Option<&mut dyn Module>;

    /// Return the [`ModuleId`] associated with a given [`PortId`].
    fn lookup_module(&self, port_id: &PortId) -> Option<ModuleId>;

    /// Upcast to a [core IBC router](IbcCoreRouter).
    fn as_core_router(&self) -> &CoreRouter<Self>
    where
        Self: Sized,
    {
        // SAFETY: A [`CoreRouter`] has the same layout as `Self`.
        unsafe { &*(self as *const Self).cast::<CoreRouter<Self>>() }
    }

    /// Upcast (mutably) to a [core IBC router](IbcCoreModule).
    fn as_core_router_mut(&mut self) -> &mut CoreRouter<Self>
    where
        Self: Sized,
    {
        // SAFETY: A [`CoreRouter`] has the same layout as `Self`.
        unsafe { &mut *(self as *mut Self).cast::<CoreRouter<Self>>() }
    }
}

/// Wrapper around a [core IBC router](IbcCoreRouter) implementation.
#[derive(Debug)]
#[repr(transparent)]
pub struct CoreRouter<R> {
    inner: R,
}

impl<R: Router> IbcCoreRouter for CoreRouter<R> {
    fn get_route(&self, module_id: &ModuleId) -> Option<&dyn IbcCoreModule> {
        self.inner.get_route(module_id).map(Module::upcast_to_core)
    }

    fn get_route_mut(&mut self, module_id: &ModuleId) -> Option<&mut dyn IbcCoreModule> {
        self.inner
            .get_route_mut(module_id)
            .map(Module::upcast_to_core_mut)
    }

    fn lookup_module(&self, port_id: &PortId) -> Option<ModuleId> {
        self.inner.lookup_module(port_id)
    }
}
