/*
 * labs/ctf-app/EarlyProvider.java
 * ---------------------------------------------------------------------------
 * CH38 CTF target — the early hook.
 *
 * A ContentProvider that provides nothing. Its only purpose is that
 * ContentProvider.onCreate() is called by ActivityThread BEFORE
 * Application.onCreate(), which makes it the earliest Java-tier entry point an
 * app can reach without writing native code.
 *
 * This is not a trick invented for a lab. It is exactly how several analytics,
 * crash-reporting and anti-fraud SDKs bootstrap themselves without asking the
 * host app to change a line of code: declare a provider in the manifest, do
 * your work in onCreate, return true, and never serve a query.
 *
 * Chapter 38 section 3.12 has the full lifecycle ordering; chapter 27 owns
 * ContentProviders.
 *
 * AUTHORISED TESTING ONLY.
 * ---------------------------------------------------------------------------
 */

package com.pentest.ch38.ctf;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;

public class EarlyProvider extends ContentProvider {

    @Override
    public boolean onCreate() {
        // Runs before Application.onCreate and long before any Activity.
        // By the time a human sees a screen, the state word is already decided.
        if (getContext() != null) {
            Guard.sweep(getContext());
        }
        return true;
    }

    // Everything below is inert. The provider is not exported, serves nothing,
    // and exists only for its onCreate.

    @Override public Cursor query(Uri u, String[] p, String s, String[] a, String o) { return null; }
    @Override public String getType(Uri u) { return null; }
    @Override public Uri insert(Uri u, ContentValues v) { return null; }
    @Override public int delete(Uri u, String s, String[] a) { return 0; }
    @Override public int update(Uri u, ContentValues v, String s, String[] a) { return 0; }
}
