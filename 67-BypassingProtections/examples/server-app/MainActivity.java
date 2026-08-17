/*
 * examples/server-app/MainActivity.java
 *
 * The control group. Same checks, different owner of the decision.
 *
 * WHAT TO COMPARE
 *   Put this file next to ../guarded-app/MainActivity.java and diff the flow:
 *
 *     guarded-app                        server-app
 *     -----------                        ----------
 *     Guard.evaluate() -> Verdict        collect() -> signal report
 *     Guard.enforce(v)                   POST the report, receive an answer
 *     Vault.open(v) decrypts locally     the response body IS the secret
 *
 *   In the guarded app there are four hookable points between the checks and
 *   the secret, and the secret is in the APK the whole time. Here there are
 *   none, because there is nothing on this side of the wire to hook that
 *   changes what the server does - and the secret is not in the APK at all.
 *
 * WHAT THIS IS NOT
 *   It is NOT a claim that server-side decisions are unbreakable. They are
 *   breakable in a completely different way: by lying convincingly on the
 *   wire, by replaying a good answer, or by finding that the server trusts the
 *   client's self-report. This app lies to itself in exactly one place on
 *   purpose (see the FORGE button) so you can see how far that gets you, and
 *   ../server.py logs the forgery rather than falling for it.
 *
 * SETUP
 *   # host
 *   python3 -B server.py            # listens on 127.0.0.1:8767
 *   adb reverse tcp:8767 tcp:8767   # device 127.0.0.1:8767 -> host
 *
 *   Remove the tunnel when you finish: adb reverse --remove tcp:8767
 */
package com.pentest.ch67.server;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.graphics.Typeface;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Debug;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;

public class MainActivity extends Activity {

    private static final String TAG = "CH67Server";
    private static final String ENDPOINT = "http://127.0.0.1:8767/unlock";

    private TextView out;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (12 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("CH67 Server-Decided");
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setTextSize(20);
        root.addView(title);

        Button honest = new Button(this);
        honest.setText("Ask the server (honest report)");
        root.addView(honest);

        Button forge = new Button(this);
        forge.setText("Ask the server (forged clean report)");
        root.addView(forge);

        out = new TextView(this);
        out.setTypeface(Typeface.MONOSPACE);
        out.setTextSize(10);
        out.setTextIsSelectable(true);
        ScrollView sv = new ScrollView(this);
        sv.addView(out);
        root.addView(sv);
        setContentView(root);

        append("The secret is NOT in this APK. Search for it if you like.");
        append("");

        honest.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { ask(collect()); }
        });

        forge.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                /*
                 * This is the attacker's move, implemented by the app itself so
                 * that you can watch the server's reaction without writing a
                 * hook first. It is the honest question: what happens when the
                 * client simply lies?
                 *
                 * The answer, in server.py, is that the server does not care
                 * what the client says about itself. It cares about the nonce
                 * it issued and about the account. A self-report is telemetry.
                 */
                ask("debugger.jdwp=false;build.debuggable=false;"
                        + "debugger.tracerpid=0;frida.port27042=false;forged=true");
            }
        });
    }

    /** The same reads as the guarded app, formatted as a self-report. */
    private String collect() {
        StringBuilder sb = new StringBuilder();
        sb.append("debugger.jdwp=").append(Debug.isDebuggerConnected()).append(';');

        boolean dbg = false;
        try {
            ApplicationInfo ai = getApplicationInfo();
            dbg = (ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        } catch (Throwable ignored) { }
        sb.append("build.debuggable=").append(dbg).append(';');

        sb.append("debugger.tracerpid=").append(tracerPid()).append(';');
        sb.append("frida.port27042=").append(portOpen(27042)).append(';');
        sb.append("forged=false");
        return sb.toString();
    }

    private static int tracerPid() {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader("/proc/self/status"));
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    return Integer.parseInt(line.substring(10).trim());
                }
            }
        } catch (Throwable ignored) {
        } finally {
            if (r != null) try { r.close(); } catch (Throwable ignored) { }
        }
        return -1;
    }

    private static boolean portOpen(int port) {
        Socket s = null;
        try {
            s = new Socket();
            s.connect(new InetSocketAddress("127.0.0.1", port), 250);
            return true;
        } catch (Throwable t) {
            return false;
        } finally {
            if (s != null) try { s.close(); } catch (Throwable ignored) { }
        }
    }

    private void ask(final String report) {
        append("--- POST " + ENDPOINT);
        append("    body: " + report);
        new AsyncTask<Void, Void, String>() {
            @Override protected String doInBackground(Void... ignored) {
                HttpURLConnection c = null;
                try {
                    c = (HttpURLConnection) new URL(ENDPOINT).openConnection();
                    c.setRequestMethod("POST");
                    c.setDoOutput(true);
                    c.setConnectTimeout(3000);
                    c.setReadTimeout(3000);
                    OutputStream os = c.getOutputStream();
                    os.write(report.getBytes("UTF-8"));
                    os.close();

                    int code = c.getResponseCode();
                    InputStream is = (code >= 400) ? c.getErrorStream() : c.getInputStream();
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    byte[] buf = new byte[4096];
                    int n;
                    while (is != null && (n = is.read(buf)) > 0) bos.write(buf, 0, n);
                    return "HTTP " + code + "\n" + bos.toString("UTF-8");
                } catch (Throwable t) {
                    return "request failed: " + t
                            + "\n(is server.py running, and did you run"
                            + " `adb reverse tcp:8767 tcp:8767`?)";
                } finally {
                    if (c != null) c.disconnect();
                }
            }
            @Override protected void onPostExecute(String s) { append(s); append(""); }
        }.execute();
    }

    private void append(String s) {
        out.append(s);
        out.append("\n");
        Log.i(TAG, s);
    }
}
