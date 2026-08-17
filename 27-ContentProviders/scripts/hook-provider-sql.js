// frida -U -f com.example.notes -l scripts/hook-provider-sql.js
// Prints the exact SQL string every provider query compiles.
Java.perform(function () {
  var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

  SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;")
    .implementation = function (sql, args) {
      console.log("[rawQuery] " + sql);
      if (args !== null) { console.log("    args=" + JSON.stringify(args)); }
      return this.rawQuery(sql, args);
    };

  SQLiteDatabase.query.overload("boolean", "java.lang.String", "[Ljava.lang.String;",
      "java.lang.String", "[Ljava.lang.String;", "java.lang.String", "java.lang.String",
      "java.lang.String", "java.lang.String", "android.os.CancellationSignal")
    .implementation = function (d, table, cols, sel, selArgs, group, having, order, limit, cs) {
      console.log("[query] table=" + table
        + " cols=" + (cols === null ? "*" : cols.join(","))
        + " sel=" + sel + " order=" + order + " limit=" + limit);
      return this.query(d, table, cols, sel, selArgs, group, having, order, limit, cs);
    };
});
