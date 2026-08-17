// 47-Authentication/examples/02-HardenedLogin.kt
//
// PURPOSE
//   The corrected counterpart to 01-VulnerableLogin.java, defect for defect.
//   This is the shape a first-party username/password login should have on
//   Android when the backend is under the same organisation's control.
//
//   The governing principle, and the only one worth memorising:
//
//       THE CLIENT HOLDS A CREDENTIAL. IT DOES NOT HOLD A DECISION.
//
//   There is deliberately NO isLoggedIn() anywhere in this file. Offering an API
//   that appears to answer "am I authenticated?" on the device is the bug that
//   01 demonstrates; removing the question removes the class of defect.
//
// WHAT THIS FILE DOES NOT DO
//   It does not implement token storage - that is 49-KeyStore's job, and
//   CredentialStore below is an interface with a documented contract rather than
//   a reimplementation. It does not implement the token format - that is
//   46-Tokens. It does not implement pinning - that is 36-CertificatePinning.
//   Each is cited where it belongs.
//
// BUILD
//   Kotlin, coroutines, OkHttp. Part of the lab app in labs/authlab/.

package com.pentest.ch47.hardened

import android.app.Activity
import android.os.Bundle
import android.view.WindowManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

// ---------------------------------------------------------------------------
// Session state. Note that every value here is DERIVED FROM A SERVER RESPONSE.
// None of it is persisted as a decision.
// ---------------------------------------------------------------------------
sealed interface SessionState {
    /** No usable credential, or the server rejected the one we had. */
    data object Anonymous : SessionState

    /** The server confirmed the credential in this process lifetime. */
    data class Active(val profile: Profile) : SessionState

    /**
     * We hold a credential but could not reach the server.
     *
     * This state exists so that offline tolerance does not have to be built by
     * pretending the credential is valid. A UI may render cached, read-only
     * content in this state. It must NOT permit any mutation, any payment, or
     * any disclosure of data not already on the device.
     */
    data class Stale(val cachedProfile: Profile?) : SessionState
}

data class Profile(val userId: String, val displayName: String)

sealed interface ApiResult<out T> {
    data class Ok<T>(val value: T) : ApiResult<T>
    data object Unauthorized : ApiResult<Nothing>
    data object Offline : ApiResult<Nothing>
    data class Failed(val code: Int) : ApiResult<Nothing>
}

/**
 * Storage contract for the long-lived credential.
 *
 * The implementation belongs to 49-KeyStore. The contract that matters here:
 *
 *  - `write` must wrap the value with a hardware-backed key where one exists.
 *    That defeats an attacker who can READ FILES. See 49-KeyStore on the
 *    extraction-versus-use distinction: it does NOT defeat an attacker who can
 *    RUN CODE in this process, and no on-device storage can.
 *  - `clear` must be synchronous and must not fail silently.
 *  - Nothing in this interface ever returns a password. There is no password
 *    to return; see `login` below.
 */
interface CredentialStore {
    fun read(): String?
    fun write(refreshToken: String)
    fun clear()
}

interface AuthApi {
    suspend fun login(username: String, password: CharArray): ApiResult<LoginResponse>
    suspend fun verifyMfa(mfaToken: String, code: String): ApiResult<LoginResponse>
    suspend fun me(credential: String): ApiResult<Profile>
    suspend fun refresh(refreshToken: String): ApiResult<String>
    suspend fun revoke(refreshToken: String): ApiResult<Unit>
}

data class LoginResponse(
    val mfaRequired: Boolean,
    /**
     * When `mfaRequired` is true this is an MFA-scoped token that the server
     * accepts at exactly ONE endpoint. It is not a session credential and it
     * cannot be used as one - which is what makes the client's branch below
     * merely a UI decision rather than a security decision.
     */
    val token: String,
    val profile: Profile?
)

// ---------------------------------------------------------------------------
// The repository. This is the whole design.
// ---------------------------------------------------------------------------
class SessionRepository(
    private val api: AuthApi,
    private val store: CredentialStore
) {

    private var cachedProfile: Profile? = null

    /**
     * FIX for [V1] in 01-VulnerableLogin.java.
     *
     * There is no boolean to flip, because there is no boolean. The state is
     * recomputed from a server response every time it is needed. An attacker who
     * hooks this method can make it return Active - and gets a screen full of
     * data the server never sent, because every subsequent call still carries a
     * credential the server evaluates independently.
     */
    suspend fun currentSession(): SessionState = withContext(Dispatchers.IO) {
        val credential = store.read() ?: return@withContext SessionState.Anonymous
        when (val r = api.me(credential)) {
            is ApiResult.Ok -> {
                cachedProfile = r.value
                SessionState.Active(r.value)
            }
            ApiResult.Unauthorized -> {
                // The server has spoken. Drop the credential rather than
                // retrying with it - a credential the server rejects is not
                // going to start working.
                store.clear()
                SessionState.Anonymous
            }
            ApiResult.Offline      -> SessionState.Stale(cachedProfile)
            is ApiResult.Failed    -> SessionState.Stale(cachedProfile)
        }
    }

    /**
     * FIX for [V2] and [V5].
     *
     * The password arrives as a CharArray, is used exactly once, and is scrubbed
     * in a `finally` block so it is scrubbed on the exception path too. What is
     * PERSISTED is a refresh token: scoped to this service, revocable by this
     * service, and worthless anywhere else.
     *
     * Note the honest limit. Scrubbing is a defence-in-depth measure against a
     * memory-dumping attacker who already has code execution, and chapter 19
     * measured that Android neither zeroes freed memory nor quarantines it, so
     * residue outlives the scrub in copies we do not control (the Editable, any
     * String the IME made). It is still worth doing; it is not a control.
     */
    suspend fun login(username: String, password: CharArray): LoginOutcome {
        return try {
            when (val r = api.login(username, password)) {
                is ApiResult.Ok -> {
                    if (r.value.mfaRequired) {
                        LoginOutcome.MfaRequired(r.value.token)
                    } else {
                        store.write(r.value.token)
                        LoginOutcome.Success
                    }
                }
                // FIX for the enumeration oracle: ONE outcome for every rejection,
                // and the UI must not render a server-supplied error string here.
                ApiResult.Unauthorized -> LoginOutcome.Rejected
                ApiResult.Offline      -> LoginOutcome.Offline
                is ApiResult.Failed    -> LoginOutcome.Rejected
            }
        } finally {
            // Written as the ESCAPE \u0000, six ASCII characters, never as a raw
            // NUL byte. A literal control byte here is not valid Kotlin, makes the
            // file register as binary to grep, and is silently lost when a reader
            // copies the snippet off a rendered page. This repository once carried
            // 17 such bytes across 9 files, and the mistake is triggered most often
            // by writing ABOUT NUL bytes - which is exactly what this comment does.
            password.fill('\u0000')
        }
    }

    /**
     * FIX for [V7].
     *
     * This looks like the vulnerable version - a client-side branch - and the
     * difference is entirely on the server. The `mfaToken` is scoped to
     * `verify_mfa` and is rejected by every other endpoint, so an attacker who
     * skips this call holds a credential that can do nothing.
     *
     * The lesson generalises: AN INTERMEDIATE AUTHENTICATION STATE MUST BE
     * REPRESENTED BY A CREDENTIAL THAT CANNOT DO WHAT THE FINAL STATE CAN DO.
     */
    suspend fun completeMfa(mfaToken: String, code: String): LoginOutcome =
        when (val r = api.verifyMfa(mfaToken, code)) {
            is ApiResult.Ok -> {
                store.write(r.value.token)
                LoginOutcome.Success
            }
            ApiResult.Unauthorized -> LoginOutcome.Rejected
            ApiResult.Offline      -> LoginOutcome.Offline
            is ApiResult.Failed    -> LoginOutcome.Rejected
        }

    /**
     * FIX for [V3].
     *
     * Five things, and only the local clearing is on the device:
     *  1. tell the server, and treat failure AS A FAILURE;
     *  2. clear every local copy unconditionally;
     *  3. clear the WebView cookie jar, which is a separate store from OkHttp's;
     *  4. queue a retry if the server was unreachable - a logout with no network
     *     is otherwise permanently a client-side logout;
     *  5. clear anything that would let the next user infer the previous one.
     */
    suspend fun logout(pending: PendingRevocationQueue, ui: LogoutUiCleanup) {
        val credential = store.read()

        val revoked = credential?.let {
            when (api.revoke(it)) {
                is ApiResult.Ok -> true
                else -> false
            }
        } ?: true

        store.clear()
        cachedProfile = null
        ui.clearCookies()          // both CookieManager and the OkHttp CookieJar
        ui.evictHttpCache()
        ui.clearPrefilledIdentity()   // no "welcome back, alice@..." on the login screen

        if (!revoked && credential != null) {
            pending.enqueue(credential)
        }
    }
}

sealed interface LoginOutcome {
    data object Success : LoginOutcome
    data class MfaRequired(val mfaToken: String) : LoginOutcome
    /** Deliberately ONE outcome for every rejection reason. */
    data object Rejected : LoginOutcome
    data object Offline : LoginOutcome
}

interface PendingRevocationQueue { fun enqueue(credential: String) }

interface LogoutUiCleanup {
    fun clearCookies()
    fun evictHttpCache()
    fun clearPrefilledIdentity()
}

// ---------------------------------------------------------------------------
// The Activity. Two lines of it matter.
// ---------------------------------------------------------------------------
class HardenedLoginActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // FIX for [V4]. Set BEFORE the window content is created, so there is no
        // frame during which the screen is capturable and so the recents
        // thumbnail is covered from the start.
        //
        // It must be repeated on EVERY window that displays a credential or a
        // one-time code, including Dialogs, which have their own windows. Setting
        // it once in the login Activity and forgetting the "show my card number"
        // screen is the most common way this control is applied to the wrong
        // place. See README section 3.10 for what it does and does not stop.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        setContentView(/* R.layout.activity_login */ 0)
    }

    // The password is read as a CharArray and never becomes a String.
    //
    //   val editable = passwordField.text
    //   val chars = CharArray(editable.length)
    //   editable.getChars(0, editable.length, chars, 0)
    //   ... use chars ...
    //   editable.clear()
    //
    // The layout must declare, for the password field:
    //     android:inputType="textPassword"        - asks the IME not to learn it
    //     android:autofillHints="password"        - lets a password manager work
    // and must NOT declare importantForAutofill="no" on it, which breaks password
    // managers and measurably pushes users towards weaker passwords.
}
