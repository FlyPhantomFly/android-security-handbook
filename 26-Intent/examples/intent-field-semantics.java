// examples/intent-field-semantics.java
//
// Example 9.1 from README.md, as compilable code: the four ways to address an
// Intent, and the two field-clearing traps that silently break resolution.
//
// This file deliberately contains no PUBLIC class, so it can carry a descriptive
// filename that does not match a class name. Compile it exactly as the deputy app
// is compiled:
//
//     javac -nowarn -source 8 -target 8 \
//           -bootclasspath "$SDK/platforms/android-35/android.jar" \
//           -cp "$SDK/platforms/android-35/android.jar" \
//           -d /tmp/out examples/intent-field-semantics.java
//
// Nothing here is vulnerable. It is the reference for "which addressing mode do I
// want, and why", which is the decision behind most of the fixes in this chapter.

package com.pentest.deputy;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.net.Uri;
import android.util.Log;

class IntentFieldSemantics {

    private static final String TAG = "FIELDS";

    // ------------------------------------------------------------------ (1)
    /**
     * FULLY IMPLICIT. The system resolves against every installed app's filters
     * and may show a chooser. This is the only one of the four modes an attacker
     * can interpose on.
     *
     * Note that Context.startActivity ADDS android.intent.category.DEFAULT to an
     * implicit Intent. A target filter that does not declare DEFAULT can never
     * match, no matter how well its action and data line up. That single rule
     * accounts for most "my am start does not work" confusion.
     */
    static void implicitSend(Activity ctx) {
        Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com/a"));
        Log.i(TAG, "implicit: component=" + i.getComponent() + " package=" + i.getPackage());
        ctx.startActivity(i);
    }

    // ------------------------------------------------------------------ (2)
    /**
     * PACKAGE-RESTRICTED. Resolution still happens -- action, categories and data
     * are all still matched -- but only against filters belonging to the named
     * package. No other app can win.
     *
     * This is the cheapest sufficient fix for most implicit-Intent leaks: the code
     * keeps its "ask the platform which component" shape, and stops broadcasting
     * to the world. For a broadcast carrying anything sensitive,
     * setPackage(getPackageName()) is the one-line remediation.
     */
    static void packageRestrictedSend(Activity ctx) {
        Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com/a"));
        i.setPackage("com.android.chrome");
        ctx.startActivity(i);
    }

    // ------------------------------------------------------------------ (3)
    /**
     * FULLY EXPLICIT, by ComponentName. mComponent is non-null, so NO matching
     * happens at all: no filter is consulted, CATEGORY_DEFAULT is irrelevant, and
     * the target does not need an <intent-filter> element.
     *
     * The component's `exported` state and `permission` ARE still enforced, by
     * system_server. Explicit does not mean unchecked; it means unmatched.
     */
    static void explicitSendByName(Activity ctx) {
        Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com/a"));
        i.setComponent(new ComponentName("com.android.chrome",
                "com.google.android.apps.chrome.Main"));
        ctx.startActivity(i);
    }

    // ------------------------------------------------------------------ (4)
    /**
     * FULLY EXPLICIT, by class. The idiomatic in-app form, and the one to
     * recommend whenever the sender genuinely knows the target.
     */
    static void explicitSendByClass(Activity ctx) {
        ctx.startActivity(new Intent(ctx, DetailActivity.class));
    }

    // ------------------------------------------------------------ the traps

    /**
     * TRAP 1 -- setData and setType each NULL the other field.
     *
     * The two were originally alternative descriptions of the same thing, and the
     * API still behaves that way. A filter requiring BOTH a scheme and a MIME type
     * can therefore never be matched by an Intent built like `bad` below, and
     * there is no error anywhere: resolution simply returns nothing.
     */
    static void dataTypeTrap() {
        Intent bad = new Intent(Intent.ACTION_VIEW);
        bad.setData(Uri.parse("content://com.example.docs/1"));
        bad.setType("application/pdf");
        Log.w(TAG, "after setData+setType, data = " + bad.getData());   // null

        Intent good = new Intent(Intent.ACTION_VIEW);
        good.setDataAndType(Uri.parse("content://com.example.docs/1"), "application/pdf");
        Log.i(TAG, "after setDataAndType, data = " + good.getData()
                + " type = " + good.getType());                          // both set
    }

    /**
     * TRAP 2 -- an extra can BE an Intent, because Intent implements Parcelable.
     *
     * This is not a bug in itself; it is the mechanism the platform uses for
     * chooser flows and trampolines. It is also, exactly, the intent-redirection
     * primitive. Seeing it written down once makes RedirectorActivity.java obvious.
     */
    static Intent nestOne() {
        Intent inner = new Intent(Intent.ACTION_VIEW, Uri.parse("https://inner.example/"));
        Intent outer = new Intent("com.pentest.deputy.ROUTE");
        outer.putExtra("next", inner);         // an Intent inside an Intent
        return outer;
    }

    /**
     * TRAP 3 -- the selector. A second Intent used ONLY for resolution, while the
     * outer Intent's action and data are what actually gets delivered.
     *
     * It exists so a caller can say "resolve this as if it were a browser request,
     * but deliver this data". It is rare, poorly understood, and worth recognising
     * because it appears in `intent:` URIs as SEL and can steer resolution in ways
     * a code reviewer does not expect. setSelector requires the outer Intent to
     * have no package and no component.
     */
    static void selectorExample(Activity ctx) {
        Intent target = new Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com/a"));
        Intent selector = new Intent(Intent.ACTION_VIEW);
        selector.addCategory(Intent.CATEGORY_BROWSABLE);
        selector.setData(Uri.fromParts("https", "", null));
        target.setSelector(selector);
        ctx.startActivity(target);
    }
}
