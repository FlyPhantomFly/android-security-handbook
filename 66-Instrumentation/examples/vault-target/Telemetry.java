// examples/vault-target/Telemetry.java
//
// An ordinary collaborator interface, of the kind every real app has several of:
// a Retrofit service, an OkHttp interceptor, an analytics sink, a dependency
// injection graph entry. The only thing that matters about it for chapter 66 is
// that it is an INTERFACE held in a static field.
//
// Interface-typed collaborators are the one shape that pure-Java interception
// reaches with no native code at all, because java.lang.reflect.Proxy can
// manufacture an implementation at runtime. examples/HookFromInstrumentation.java
// replaces VaultStore.sSink with such a proxy from inside an instrumentation,
// before Application.onCreate() has run, and therefore sees the first event the
// app ever emits.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch66.vault;

public interface Telemetry {

    /** Called by the app at points it considers worth recording. */
    void event(String name, String value);
}
