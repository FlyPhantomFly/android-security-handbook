// examples/IVaultWatcher.aidl
//
// The callback interface a client registers with IVaultService.registerWatcher().
//
// EVERY METHOD HERE IS `oneway`, AND THAT IS A SECURITY DECISION, NOT A
// PERFORMANCE ONE.
//
//   A callback runs in the CLIENT's process, but it is invoked from a Binder
//   thread in the SERVICE. If the method were synchronous, the service's
//   thread would block until the client returned. A hostile client that
//   simply never returns holds that thread forever. Sixteen of them hold the
//   service's entire pool, and the service stops answering anybody --
//   including the system.
//
//   `oneway` makes that impossible: the service's thread returns the moment
//   the driver has queued the transaction. The cost is that the service
//   cannot learn whether the client handled it, or receive a return value,
//   or see an exception. That is the correct trade: a service must never be
//   able to be hung by the processes it serves.
//
// See README section 3.10 and section 3.15.

package com.example.vault;

interface IVaultWatcher {

    /** Code 1. oneway: the service must never block on us. */
    oneway void onSecretChanged(String name);

    /** Code 2. oneway, for the same reason. */
    oneway void onVaultLocked();
}
