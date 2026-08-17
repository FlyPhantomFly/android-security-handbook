// 55-MobSF/scripts/lead-liveness.js
//
// PURPOSE
//   Answer the one question a MobSF report cannot: "did this finding's code actually run?"
//   You paste in the class/method pairs the report cited, drive the app, and ask for a
//   summary. Every lead is reported as EXECUTED (with the first caller stack), NOT SEEN,
//   or ABSENT.
//
//   This is the runtime half of stage 7. 52-StaticAnalysis' validate-lead.sh builds a
//   static caller closure and is honest when the frontier explodes; this settles the same
//   question from the other end, for the leads where reachability decides the severity.
//
// USAGE
//   frida -U -f com.example.target -l scripts/lead-liveness.js --no-pause
//   # drive the app: log in, press the buttons, fire the deep links, then in the REPL:
//   rpc.exports.summary().then(console.log)
//
//   Attach to something already running instead:
//   frida -U -n "App Name" -l scripts/lead-liveness.js
//
//   Fire a lead deliberately, from another terminal, and watch it light up:
//   adb shell am start -a android.intent.action.VIEW -d 'ctfapp://open/admin?ref=debug'
//
// REQUIREMENTS
//   frida-server running on the device (root), and frida-tools on the host.
//   Nothing else. No MobSF instance is needed - you paste the leads in by hand, which is
//   deliberate: it forces you to decide which leads reachability actually decides.
//
// WHAT THIS WILL NOT TELL YOU
//   * That a lead which did NOT fire is dead code. It tells you only that it did not fire
//     IN THIS SESSION. Reflection, a feature flag, a server response, a code path you did
//     not exercise, or a root check that took a different branch all produce the same
//     output. The summary prints that sentence so it cannot be forgotten.
//   * That a lead which DID fire is a vulnerability. Execution answers question 2 of
//     52's four. Questions 3 and 4 - who can reach it, and what it gets them - are yours.
//   * Anything about code that is not loaded. A class the report cited that is not in the
//     process is itself a result: either you analysed a different artefact, or the class
//     ships in a split, or the code is loaded dynamically.
//   * Whether your session was live at all. If NOTHING fired, suspect the session before
//     you suspect the app: 51-DynamicAnalysis measured a run where a permission dialog
//     absorbed the launch and all nine capture channels went silent, producing a report
//     identical to a well-behaved app doing nothing wrong.

'use strict';

// ---------------------------------------------------------------------------
// 1. Paste the leads here.
//
//    Use the names that are in the DEX, not the names the source used to have.
//    On an R8-processed build that means 'b.h' and 'm.e', not 'RetrofitClient'
//    and 'CertificatePinner' - 42-R8 explains why, and lab 03 measures it.
//
//    The examples below are the leads from this chapter's worked example.
// ---------------------------------------------------------------------------
const LEADS = [
    { clazz: 'org.android.cmpen.WebViewActivity',   method: 'onCreate' },
    { clazz: 'org.android.cmpen.FlagProvider',      method: 'query'    },
    { clazz: 'org.android.cmpen.LeakyFileProvider', method: 'openFile' },
    { clazz: 'org.android.cmpen.DeepLinkActivity',  method: 'onCreate' },
    { clazz: 'B.g',                                 method: 'a'        },
];

// Print the first N frames of the caller stack on the first hit. Question 3 of the
// four is "who can reach it", and the stack is the cheapest partial answer.
const STACK_FRAMES = 6;

// ---------------------------------------------------------------------------

const state = {};   // key -> { count, armed, overloads, absentReason }

function key(lead) { return lead.clazz + '.' + lead.method; }

function callerStack() {
    try {
        const Log = Java.use('android.util.Log');
        const Exception = Java.use('java.lang.Exception');
        return Log.getStackTraceString(Exception.$new())
                  .split('\n').slice(1, 1 + STACK_FRAMES).join('\n');
    } catch (e) {
        return '    (stack unavailable: ' + e + ')';
    }
}

Java.perform(function () {
    console.log('');
    console.log('=== lead-liveness: arming ' + LEADS.length + ' lead(s) ===');

    LEADS.forEach(function (lead) {
        const k = key(lead);
        state[k] = { count: 0, armed: false, overloads: 0, absentReason: null };

        let cls;
        try {
            cls = Java.use(lead.clazz);
        } catch (e) {
            state[k].absentReason = 'class not loaded';
            console.log('[!] ABSENT  ' + k);
            console.log('        The class is not in this process. That is a RESULT, not a');
            console.log('        failure: check you analysed the same artefact the device is');
            console.log('        running, and whether the code ships in a split or is loaded');
            console.log('        at runtime. See 55-MobSF README section 3.13.');
            return;
        }

        if (!cls[lead.method]) {
            state[k].absentReason = 'method not found on the class';
            console.log('[!] ABSENT  ' + k + '  -- the class exists, the method does not');
            return;
        }

        const overloads = cls[lead.method].overloads;
        if (!overloads || !overloads.length) {
            state[k].absentReason = 'no overloads';
            console.log('[!] ABSENT  ' + k + '  -- no overloads');
            return;
        }

        overloads.forEach(function (ovl) {
            ovl.implementation = function () {
                const st = state[k];
                st.count += 1;
                if (st.count === 1) {
                    console.log('');
                    console.log('[+] FIRED   ' + k);
                    console.log(callerStack());
                }
                return ovl.apply(this, arguments);
            };
        });

        state[k].armed = true;
        state[k].overloads = overloads.length;
        console.log('[ ] armed   ' + k + '  (' + overloads.length + ' overload(s))');
    });

    console.log('');
    console.log('Now drive the application. Then: rpc.exports.summary().then(console.log)');
    console.log('');
});

rpc.exports = {
    // Call after you have exercised the app.
    summary: function () {
        const lines = [];
        let executed = 0, notSeen = 0, absent = 0;

        lines.push('');
        lines.push('================ LEAD LIVENESS ================');
        Object.keys(state).forEach(function (k) {
            const st = state[k];
            if (st.absentReason) {
                absent += 1;
                lines.push('ABSENT   ' + String('-').padStart(6) + '  ' + k +
                           '   (' + st.absentReason + ')');
            } else if (st.count > 0) {
                executed += 1;
                lines.push('EXECUTED ' + String(st.count).padStart(6) + '  ' + k);
            } else {
                notSeen += 1;
                lines.push('NOT SEEN ' + String(0).padStart(6) + '  ' + k);
            }
        });
        lines.push('-----------------------------------------------');
        lines.push('executed ' + executed + '   not seen ' + notSeen + '   absent ' + absent);
        lines.push('');

        if (executed === 0) {
            lines.push('*** NOTHING FIRED. Suspect the SESSION before the application. ***');
            lines.push('    Check the app is actually in the foreground and alive:');
            lines.push('      adb shell pidof <pkg>');
            lines.push('      adb shell dumpsys activity activities | grep mResumedActivity');
            lines.push('    A void run and a clean negative produce identical reports.');
            lines.push('');
        }

        lines.push('"NOT SEEN" means NOT SEEN IN THIS SESSION. It is not evidence of dead');
        lines.push('code. Reflection, a feature flag, a server response, a branch you did not');
        lines.push('exercise, or a root check that took the other path all look the same from');
        lines.push('here. Never write "unreachable" on the strength of this output; write');
        lines.push('"not observed during dynamic testing", and say what you exercised.');
        lines.push('');
        lines.push('"EXECUTED" answers question 2 of 52-StaticAnalysis section 3.7 and');
        lines.push('nothing else. Who can reach it, and what reaching it gets them, are');
        lines.push('still yours to establish.');
        lines.push('===============================================');
        return lines.join('\n');
    },

    // Reset the counters without reloading, so you can measure one flow at a time.
    reset: function () {
        Object.keys(state).forEach(function (k) { state[k].count = 0; });
        return 'counters reset';
    },

    // Current counts, for scripting.
    counts: function () {
        const out = {};
        Object.keys(state).forEach(function (k) {
            out[k] = state[k].absentReason ? null : state[k].count;
        });
        return out;
    }
};
