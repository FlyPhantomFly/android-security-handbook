// examples/04-hardening-a-settings-screen.kt   [H3]
//
// The migration a real application performs when somebody reports fragment
// injection against its settings screen. It is not "add an allowlist"; it is
// "stop accepting a type name", and the difference is what this file is for.
//
// WHAT IT REPLACES
//
//     class SettingsActivity : PreferenceActivity() {
//         override fun isValidFragment(name: String) = true          // [V1]
//     }
//
// WHAT IT DOES INSTEAD
//
//   1. Drops android.preference.PreferenceActivity entirely. That class is
//      deprecated (API 29), still functional on API 35, and carries the
//      reflective :android:show_fragment path whether the app wants it or not.
//      androidx.preference has no Activity that loads a Fragment named by an
//      Intent, which is not an accident.
//
//   2. Accepts a ROUTE KEY, not a class name. The set of keys is an enum, so it
//      is closed at compile time. There is no string an attacker can supply that
//      names a type.
//
//   3. Falls back to the LEAST privileged screen on an unknown key, rather than
//      throwing. The platform's own refusal path is an uncaught
//      IllegalArgumentException from onCreate -- a correct allowlist on
//      PreferenceActivity stops the injection and leaves any app able to crash
//      the host on demand. See README section 5.4. This version cannot do that.
//
//   4. Keeps a session check IN THE DESTINATION. The route table protects the
//      route you thought about. The destination check protects every route,
//      including the one a colleague adds next quarter and the one the
//      FragmentManager takes during state restoration.
//
// WHAT IT DOES NOT BUY, stated plainly:
//
//   * It is still a client-side check in a client the device owner controls. It
//     stops one APP from making another app display something. It does not make
//     data safe that the server should not have sent. If AdminScreen renders a
//     full card number, the fix is on the server and this file is not it.
//   * It does not stop an attacker who can already run code in this process.
//   * It does nothing about what the screen writes to logs, saved state, or the
//     Recents snapshot. See README section 3.10.
//
// COMPILATION STATUS
//   PARSED, NOT LINKED, and the distinction is stated rather than implied.
//   Run through kotlinc 1.9.24 (the one Android Studio bundles) against
//   android-35's android.jar: ZERO syntax errors. Every diagnostic it produced
//   is an unresolved reference to androidx.preference, androidx.appcompat,
//   androidx.fragment or the generated R class -- none of which the no-Gradle
//   build in examples/build.sh can supply, and none of which is a defect in
//   this file. The Java examples that ARE fully buildable were built, installed
//   and driven on a device instead, and their measured output is in the README.
//
//   Command, so you can reproduce the same result:
//     AJ=$ANDROID_HOME/platforms/android-35/android.jar
//     kotlinc -nowarn -cp "$AJ" -d /tmp/out 04-hardening-a-settings-screen.kt
//
// AUTHORISED TESTING ONLY -- this is remediation guidance, not an attack tool.

package com.example.settings

import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import androidx.fragment.app.commit
import androidx.preference.PreferenceFragmentCompat

private const val TAG = "Settings"

// --------------------------------------------------------------------------- //
// The closed set of routes.
//
// This is the whole control. An enum cannot be extended by an Intent extra, a
// deep link, a push payload, or a string an attacker constructs. Adding a screen
// means editing this file, which means a code review, which is exactly the gate
// you want on "which screens can strangers open".
//
// Compare with the four allowlists in README section 5.3, every one of which is
// a PREDICATE over an attacker-controlled string. This is a LOOKUP in a set the
// attacker cannot extend.
// --------------------------------------------------------------------------- //
private enum class Route(val key: String, val requiresSession: Boolean) {
    GENERAL("general", requiresSession = false),
    NOTIFICATIONS("notifications", requiresSession = false),
    ABOUT("about", requiresSession = false),
    ACCOUNT("account", requiresSession = true);

    fun newFragment(): Fragment = when (this) {
        GENERAL -> GeneralFragment()
        NOTIFICATIONS -> NotificationsFragment()
        ABOUT -> AboutFragment()
        ACCOUNT -> AccountFragment()
    }

    companion object {
        /** Null means "not a route". It deliberately does not throw. */
        fun of(key: String?): Route? = values().firstOrNull { it.key == key }
    }
}

class SettingsActivity : AppCompatActivity() {

    companion object {
        /**
         * The public entry point. Note that this is a KEY, not a class name, and
         * that the constant is exported for callers to use -- a documented,
         * bounded parameter is not a weakness, an unbounded one is.
         */
        const val EXTRA_ROUTE = "com.example.settings.ROUTE"

        /** Convenience for in-app callers, so nobody hand-builds the Intent. */
        fun intent(from: android.content.Context, route: String) =
            Intent(from, SettingsActivity::class.java).putExtra(EXTRA_ROUTE, route)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        // The FragmentManager restores its own fragments before this line runs.
        // Adding one here as well would double it up, and on a rotation the user
        // would see two copies of the screen. This is the single most common
        // Fragment bug in production code and it has nothing to do with security
        // -- but the `return` is also what stops a restored state and a fresh
        // Intent from both being honoured, which does.
        if (savedInstanceState != null) return

        val requested = intent.getStringExtra(EXTRA_ROUTE)
        val route = Route.of(requested)

        if (route == null && requested != null) {
            // Observable refusal. A control nobody can see failing is a control
            // nobody knows is working. Do not include the raw value in a metric
            // label -- it is attacker-controlled and metric labels are a
            // cardinality bomb -- but do count the event.
            Log.w(TAG, "refused unknown settings route (length=${requested.length})")
        }

        supportFragmentManager.commit {
            setReorderingAllowed(true)
            replace(R.id.settings_container, (route ?: Route.GENERAL).newFragment())
        }
    }
}

// --------------------------------------------------------------------------- //
// The destination-side check.
//
// This is the layer people skip, and it is the one that survives the app
// growing a second host, a navigation library, a dynamic feature module, or a
// state restoration path that instantiates fragments without going through
// SettingsActivity.onCreate at all.
//
// Note it does not merely hide the UI. Hiding the UI leaves the fragment
// attached, its onCreate already run, its data already loaded, and its state
// already saved. Refuse to exist instead.
// --------------------------------------------------------------------------- //
class AccountFragment : PreferenceFragmentCompat() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!SessionStore.isAuthenticated()) {
            Log.w(TAG, "AccountFragment reached without a session; refusing")
            parentFragmentManager.beginTransaction()
                .remove(this)
                .commitAllowingStateLoss()
            requireActivity().finish()
            return
        }
    }

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.settings_account, rootKey)
    }
}

class GeneralFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) =
        setPreferencesFromResource(R.xml.settings_general, rootKey)
}

class NotificationsFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) =
        setPreferencesFromResource(R.xml.settings_notifications, rootKey)
}

class AboutFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) =
        setPreferencesFromResource(R.xml.settings_about, rootKey)
}

/** Stand-in for whatever the app really uses. The point is that it is asked. */
object SessionStore {
    @Volatile
    private var authenticated = false

    fun isAuthenticated(): Boolean = authenticated
    fun onAuthenticated() { authenticated = true }
    fun onLoggedOut() { authenticated = false }
}
