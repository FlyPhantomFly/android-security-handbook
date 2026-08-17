// frida -U -f com.victim.app -l scripts/hook-grant-laundering.js
// Flags any Intent that is both taken from an extra and then started.
Java.perform(function () {
  var Intent = Java.use("android.content.Intent");
  var Activity = Java.use("android.app.Activity");

  var tainted = {};   // identityHashCode -> true

  Intent.getParcelableExtra.overload("java.lang.String")
    .implementation = function (name) {
      var v = this.getParcelableExtra(name);
      if (v !== null && v.$className === "android.content.Intent") {
        tainted[Java.cast(v, Intent).hashCode()] = name;
        console.log("[taint] Intent read from extra '" + name + "': " + v.toString());
      }
      return v;
    };

  Activity.startActivity.overload("android.content.Intent")
    .implementation = function (i) {
      var h = i.hashCode();
      if (tainted[h]) {
        console.log("[!!] REDIRECTION: intent from extra '" + tainted[h]
          + "' is being started: " + i.toString()
          + "  flags=0x" + i.getFlags().toString(16));
      }
      return this.startActivity(i);
    };

  Activity.setResult.overload("int", "android.content.Intent")
    .implementation = function (code, data) {
      if (data !== null) {
        var f = data.getFlags();
        if ((f & 0x00000003) !== 0) {   // READ or WRITE grant flags
          console.log("[!!] setResult carries URI grant flags 0x" + f.toString(16)
            + " data=" + data.getDataString());
        }
      }
      return this.setResult(code, data);
    };
});
