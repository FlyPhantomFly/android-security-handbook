// examples/05-enterprise-fragment-router.kt   [H4]
//
// A Fragment router for the scale at which a router is genuinely necessary:
// dozens of screens, several teams, and four sources of navigation -- in-app
// calls, deep links, push payloads and notification taps -- all arriving at one
// Activity.
//
// This is the file to copy if your app has a `when (screen) { ... }` in an
// exported Activity today. It keeps everything that made the router worth having
// and removes the property that made it a vulnerability: it never accepts a type
// name.
//
// THE FOUR THINGS A SMALLER EXAMPLE DOES NOT NEED
//
//   1. A SEALED route type. Adding a screen is a compile-time event, the `when`
//      is exhaustive, and R8 can prove which fragments are reachable -- which a
//      reflective loader prevents (see 42-R8 and README section 6.4).
//
//   2. AUTHORISATION DECLARED NEXT TO THE ROUTE, not scattered through the
//      destinations. "Which screens need a session?" becomes a question you
//      answer by reading one table instead of by grepping 200 fragments.
//
//   3. AN EXPLICIT EXTERNAL-ENTRY BOUNDARY. Every route carries allowExternal.
//      A route reached from an Intent is checked against it; the same route
//      reached from in-app navigation is not. This is the distinction an
//      exported host silently loses, and re-introducing it explicitly is the
//      single highest-value line in the file.
//
//   4. OBSERVABLE REFUSALS. Refusals are counted and logged with the route key.
//      A spike in "not externally reachable" is somebody probing you. A control
//      nobody can see failing is a control nobody knows is working.
//
// WHAT IS DELIBERATELY ABSENT
//
//   No Class.forName. No FragmentFactory fallback to super.instantiate(). No
//   allowlist of strings that has to be kept in step with a package layout. No
//   class names anywhere in the routing path. There is nothing for an attacker
//   to name, which is a stronger statement than "the names are checked".
//
// WHAT THIS STILL DOES NOT DO
//
//   * It is a client-side control. It stops another APP from driving your UI.
//     It does not protect data from the device owner, and it is not a substitute
//     for server-side authorisation on whatever the screen fetches.
//   * It does not protect the fragment from being constructed during STATE
//     RESTORATION, which goes through the FragmentManager and not through this
//     router. That is why AdminFragment below still checks the session itself.
//   * It says nothing about what a screen leaks to logs, saved state or the
//     Recents snapshot. See README section 3.10.
//
// COMPILATION STATUS
//   PARSED, NOT LINKED. Run through kotlinc 1.9.24 against android-35's
//   android.jar: ZERO syntax errors, and every remaining diagnostic is an
//   unresolved reference to androidx.fragment, androidx.appcompat or the
//   generated R class -- none of which the no-Gradle build in
//   examples/build.sh can supply. The Java examples that ARE fully buildable
//   were built, installed and driven on a device, and their measured output is
//   quoted in the README.
//
// AUTHORISED TESTING ONLY -- this is remediation guidance, not an attack tool.

package com.example.router

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import androidx.fragment.app.commit
import java.util.concurrent.atomic.AtomicLong

private const val TAG = "Router"

/** Where a navigation request came from. This is the trust boundary, named. */
enum class Origin {
    /** An Intent from outside this process: another app, a deep link, a notification. */
    EXTERNAL,

    /** A call from this app's own code, already past whatever gate applies. */
    INTERNAL,
}

/**
 * The route table.
 *
 * `sealed` matters: the `when` in [newFragment] is exhaustive, so adding a route
 * without giving it a fragment does not compile. That converts "we forgot to
 * wire up the new screen" from a runtime null into a build failure.
 */
sealed class Route(
    val key: String,
    /** May an Intent from outside this process reach this route? */
    val allowExternal: Boolean,
    /** Must there be an authenticated session? */
    val requiresSession: Boolean,
) {
    object Home : Route("home", allowExternal = true, requiresSession = false)
    object Search : Route("search", allowExternal = true, requiresSession = false)
    object Offers : Route("offers", allowExternal = true, requiresSession = false)
    object Profile : Route("profile", allowExternal = true, requiresSession = true)
    object Statements : Route("statements", allowExternal = true, requiresSession = true)

    // Internal-only. Reachable from in-app navigation, never from an Intent.
    object Admin : Route("admin", allowExternal = false, requiresSession = true)
    object DebugPanel : Route("debug", allowExternal = false, requiresSession = true)
    object KeyRotation : Route("keyrot", allowExternal = false, requiresSession = true)

    fun newFragment(): Fragment = when (this) {
        Home -> HomeFragment()
        Search -> SearchFragment()
        Offers -> OffersFragment()
        Profile -> ProfileFragment()
        Statements -> StatementsFragment()
        Admin -> AdminFragment()
        DebugPanel -> DebugPanelFragment()
        KeyRotation -> KeyRotationFragment()
    }

    companion object {
        val ALL: List<Route> = listOf(
            Home, Search, Offers, Profile, Statements, Admin, DebugPanel, KeyRotation,
        )

        /**
         * The list a CI test asserts against. If somebody flips allowExternal on
         * a route, this list changes and the test fails until the change is
         * reviewed. That is how a security property becomes a code review event
         * rather than a memory.
         */
        val EXTERNALLY_REACHABLE: List<String>
            get() = ALL.filter { it.allowExternal }.map { it.key }.sorted()
    }
}

/**
 * Resolution. Every refusal returns null and is counted; nothing throws, because
 * a throw from `onCreate` is a crash and a crash reachable by any app is its own
 * finding (README section 5.4).
 */
class RouteResolver(private val session: SessionSource) {

    private val refusals = AtomicLong()

    fun refusalCount(): Long = refusals.get()

    fun resolve(key: String?, origin: Origin): Route? {
        val route = Route.ALL.firstOrNull { it.key == key }
            ?: return refuse(key, "unknown route")

        if (origin == Origin.EXTERNAL && !route.allowExternal) {
            return refuse(key, "not externally reachable")
        }
        if (route.requiresSession && !session.isAuthenticated()) {
            return refuse(key, "no session")
        }
        return route
    }

    private fun refuse(key: String?, why: String): Route? {
        refusals.incrementAndGet()
        // The key is safe to log because it was compared against a closed set --
        // it is either one of ours or it is refused before it reaches here for
        // any other reason. Log its LENGTH, not its content, when it is unknown.
        val shown = if (Route.ALL.any { it.key == key }) key else "<unknown:${key?.length ?: 0}>"
        Log.w(TAG, "refused route=$shown reason=$why")
        return null
    }
}

/**
 * The single exported host.
 *
 * Everything external arrives here, and the only thing it can influence is a
 * key. Compare with examples/victim-app/FragmentHostActivity.java, which is the
 * same Activity accepting a class name.
 */
class RouterActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_ROUTE = "com.example.router.ROUTE"
        private const val QUERY_ROUTE = "r"

        /** In-app navigation goes through here, and is marked INTERNAL. */
        fun internalIntent(from: android.content.Context, route: Route) =
            Intent(from, RouterActivity::class.java)
                .putExtra(EXTRA_ROUTE, route.key)
                .putExtra(EXTRA_INTERNAL, true)

        /**
         * The internal marker is an ordinary extra and an attacker can set it.
         * It is therefore NOT the security control -- see the comment in
         * [originOf]. It exists only to avoid re-checking a session the caller
         * has already checked, and the route table is what actually decides.
         */
        private const val EXTRA_INTERNAL = "com.example.router.INTERNAL"

        private fun originOf(intent: Intent, callerIsUs: Boolean): Origin =
            if (callerIsUs && intent.getBooleanExtra(EXTRA_INTERNAL, false)) {
                Origin.INTERNAL
            } else {
                Origin.EXTERNAL
            }
    }

    private val resolver by lazy { RouteResolver(AppSession) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_router)

        // The FragmentManager has already restored whatever was attached.
        if (savedInstanceState != null) return

        val key = intent.getStringExtra(EXTRA_ROUTE) ?: routeFromDeepLink(intent.data)

        // callerIsUs: the ONLY trustworthy way to know a start came from this
        // application is that this Activity is not exported at all, or that the
        // caller was verified some other way. An Intent carries no caller
        // identity (26-Intent section 3.8), and Activity.getCallingActivity()
        // answers only when startActivityForResult was used
        // (30-Activities section 3.6). This host IS exported, so the honest
        // value here is `false` and every external request is treated as
        // external. The parameter exists so a NON-exported sibling host can pass
        // `true` without duplicating the table.
        val origin = originOf(intent, callerIsUs = false)

        val route = resolver.resolve(key, origin)
        if (route == null) {
            // Land on the least privileged screen rather than crashing or
            // finishing silently, so a mistyped in-app link is a bad UX and not
            // an outage, and so an attacker learns nothing from the difference.
            supportFragmentManager.commit {
                setReorderingAllowed(true)
                replace(R.id.router_container, Route.Home.newFragment())
            }
            return
        }

        supportFragmentManager.commit {
            setReorderingAllowed(true)
            replace(R.id.router_container, route.newFragment())
            addToBackStack(route.key)
        }
    }

    /**
     * A deep link contributes a KEY, exactly like the extra. It is the same
     * bounded parameter reached by a different road, which is the property the
     * vulnerable version loses: there, the URI query parameter was a class name.
     */
    private fun routeFromDeepLink(uri: Uri?): String? =
        uri?.getQueryParameter(QUERY_ROUTE)
}

// --------------------------------------------------------------------------- //
// Destinations.
//
// The router protects the routing path. The sensitive destinations protect
// themselves as well, because state restoration reconstructs fragments through
// the FragmentManager without consulting the router at all.
// --------------------------------------------------------------------------- //

class AdminFragment : Fragment() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!AppSession.isAuthenticated()) {
            Log.w(TAG, "AdminFragment constructed without a session; refusing")
            parentFragmentManager.beginTransaction().remove(this).commitAllowingStateLoss()
            requireActivity().finish()
        }
    }
}

class HomeFragment : Fragment()
class SearchFragment : Fragment()
class OffersFragment : Fragment()
class ProfileFragment : Fragment()
class StatementsFragment : Fragment()
class DebugPanelFragment : Fragment()
class KeyRotationFragment : Fragment()

interface SessionSource {
    fun isAuthenticated(): Boolean
}

object AppSession : SessionSource {
    @Volatile
    private var authenticated = false
    override fun isAuthenticated(): Boolean = authenticated
    fun onAuthenticated() { authenticated = true }
    fun onLoggedOut() { authenticated = false }
}

// --------------------------------------------------------------------------- //
// The CI test. This is the part that keeps the property true a year from now.
//
//   @Test fun externallyReachableRoutesAreApproved() {
//       assertEquals(
//           listOf("home", "offers", "profile", "search", "statements"),
//           Route.EXTERNALLY_REACHABLE
//       )
//   }
//
// Flipping allowExternal on any route now fails the build with a diff that names
// the route, which is a code review rather than a memory. Pair it with a
// DEX-level assertion in CI that no reflective Fragment loader appears with a
// non-constant argument, which catches a library reintroducing the primitive:
//
//   python3 -B ../scripts/fragment-injection-scan.py app-release.apk --quiet
//   # exits with no tier 1 output, or the build fails
// --------------------------------------------------------------------------- //
