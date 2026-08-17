// frida -U -f com.example.docs -l scripts/hook-openfile.js
// Shows the URI requested and the absolute file finally opened.
Java.perform(function () {
  var CP = Java.use("android.content.ContentProvider");
  var File = Java.use("java.io.File");
  var PFD = Java.use("android.os.ParcelFileDescriptor");

  CP.openFile.overload("android.net.Uri", "java.lang.String")
    .implementation = function (uri, mode) {
      console.log("[openFile] uri=" + uri.toString() + " mode=" + mode);
      return this.openFile(uri, mode);
    };

  PFD.open.overload("java.io.File", "int").implementation = function (f, m) {
    console.log("[PFD.open] " + f.getAbsolutePath()
      + "  canonical=" + f.getCanonicalPath() + "  mode=" + m);
    return this.open(f, m);
  };
});
