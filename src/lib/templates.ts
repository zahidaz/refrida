export const TEMPLATES: Record<string, { label: string; code: string }> = {
  hello: {
    label: "Hello World",
    code: `send("Hello from Frida!");
send("PID: " + Process.id);
send("Arch: " + Process.arch);
send("Platform: " + Process.platform);
send("Page size: " + Process.pageSize);`,
  },
  "hook-native": {
    label: "Hook Native Function",
    code: `const addr = Module.findExportByName(null, "open");
if (addr) {
  Interceptor.attach(addr, {
    onEnter(args) {
      this.path = args[0].readUtf8String();
    },
    onLeave(retval) {
      send({ syscall: "open", path: this.path, fd: retval.toInt32() });
    }
  });
  send("Hooked open() at " + addr);
} else {
  send("Function not found");
}`,
  },
  stalker: {
    label: "Stalker Trace",
    code: `const mainThread = Process.enumerateThreads()[0];
Stalker.follow(mainThread.id, {
  events: { call: true },
  onCallSummary(summary) {
    const entries = Object.entries(summary)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 20);
    send({ topCalls: entries.map(([addr, count]) => {
      const mod = Process.findModuleByAddress(ptr(addr));
      return { address: addr, count, module: mod ? mod.name : "unknown" };
    })});
    Stalker.unfollow(mainThread.id);
  }
});
send("Stalker tracing thread " + mainThread.id + "...");`,
  },
  "ssl-pinning-bypass": {
    label: "SSL Pinning Bypass (iOS)",
    code: `if (ObjC.available) {
  var resolver = new ApiResolver("objc");
  resolver.enumerateMatches("-[NSURLSessionDelegate URLSession:didReceiveChallenge:completionHandler:]").forEach(function(match) {
    Interceptor.attach(match.address, {
      onEnter: function(args) {
        this.completion = new ObjC.Block(args[4]);
      },
      onLeave: function(retval) {
        var NSURLCredential = ObjC.classes.NSURLCredential;
        var challenge = new ObjC.Object(this.args ? this.args[3] : ptr(0));
        try {
          var serverTrust = challenge.protectionSpace().serverTrust();
          var credential = NSURLCredential.credentialForTrust_(serverTrust);
          this.completion.implementation(0, credential);
        } catch(e) {}
      }
    });
    send("Hooked: " + match.name);
  });
  var SSLSetSessionOption = Module.findExportByName(null, "SSLSetSessionOption");
  if (SSLSetSessionOption) {
    Interceptor.attach(SSLSetSessionOption, {
      onEnter: function(args) { args[1] = ptr(0); },
    });
    send("Hooked SSLSetSessionOption");
  }
  send("SSL pinning bypass active");
} else {
  send("ObjC runtime not available");
}`,
  },
  "ssl-pinning-bypass-android": {
    label: "SSL Pinning Bypass (Android)",
    code: `Java.perform(function() {
  var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
  TrustManagerImpl.checkTrustedRecursive.implementation = function() {
    send("Bypassed checkTrustedRecursive");
    return Java.use("java.util.ArrayList").$new();
  };
  try {
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var TrustManager = Java.registerClass({
      name: "com.frida.TrustManager",
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function(chain, authType) {},
        checkServerTrusted: function(chain, authType) {},
        getAcceptedIssuers: function() { return []; },
      }
    });
    var ctx = SSLContext.getInstance("TLS");
    ctx.init(null, [TrustManager.$new()], null);
    SSLContext.getInstance.overload("java.lang.String").implementation = function(type) {
      return ctx;
    };
    send("SSL context patched");
  } catch(e) {
    send("Partial bypass: " + e.message);
  }
  send("SSL pinning bypass active");
});`,
  },
  "objc-observer": {
    label: "ObjC Method Observer (iOS)",
    code: `if (ObjC.available) {
  var target = "NSURLSession";
  var methods = ObjC.classes[target].$ownMethods;
  methods.forEach(function(method) {
    try {
      var impl = ObjC.classes[target][method].implementation;
      Interceptor.attach(impl, {
        onEnter: function(args) {
          send("[" + target + " " + method + "]");
        }
      });
    } catch(e) {}
  });
  send("Observing " + methods.length + " methods on " + target);
} else {
  send("ObjC runtime not available");
}`,
  },
  "java-hook": {
    label: "Hook Java Method (Android)",
    code: `Java.perform(function() {
  var Activity = Java.use("android.app.Activity");
  Activity.onCreate.overload("android.os.Bundle").implementation = function(bundle) {
    send("Activity.onCreate: " + this.getClass().getName());
    this.onCreate(bundle);
  };
  var Log = Java.use("android.util.Log");
  Log.d.overload("java.lang.String", "java.lang.String").implementation = function(tag, msg) {
    send({ tag: tag, msg: msg });
    return this.d(tag, msg);
  };
  send("Hooks installed");
});`,
  },
  "anti-debug": {
    label: "Anti-Debug Bypass",
    code: `var ptrace = Module.findExportByName(null, "ptrace");
if (ptrace) {
  Interceptor.attach(ptrace, {
    onEnter: function(args) {
      this.request = args[0].toInt32();
    },
    onLeave: function(retval) {
      if (this.request === 31) {
        send("ptrace(PT_DENY_ATTACH) bypassed");
        retval.replace(ptr(0));
      }
    }
  });
  send("ptrace hooked");
}
var sysctl = Module.findExportByName(null, "sysctl");
if (sysctl) {
  Interceptor.attach(sysctl, {
    onEnter: function(args) { this.mib = args[0]; this.old = args[2]; },
    onLeave: function(retval) {
      try {
        var mib1 = this.mib.readInt();
        var mib2 = this.mib.add(4).readInt();
        if (mib1 === 1 && mib2 === 14) {
          var flags = this.old.add(32).readInt();
          if (flags & 0x800) {
            this.old.add(32).writeInt(flags & ~0x800);
            send("sysctl P_TRACED flag removed");
          }
        }
      } catch(e) {}
    }
  });
  send("sysctl hooked");
}
var getppid = Module.findExportByName(null, "getppid");
if (getppid) {
  Interceptor.replace(getppid, new NativeCallback(function() { return 1; }, "int", []));
  send("getppid spoofed to 1");
}
send("Anti-debug bypass active");`,
  },
  "crypto-trace": {
    label: "Crypto Function Tracer",
    code: `var hooks = [
  { lib: null, name: "CCCrypt" },
  { lib: null, name: "CC_MD5" },
  { lib: null, name: "CC_SHA1" },
  { lib: null, name: "CC_SHA256" },
  { lib: null, name: "EVP_EncryptInit_ex" },
  { lib: null, name: "EVP_DecryptInit_ex" },
  { lib: null, name: "AES_encrypt" },
  { lib: null, name: "AES_decrypt" },
];
hooks.forEach(function(h) {
  var addr = Module.findExportByName(h.lib, h.name);
  if (addr) {
    Interceptor.attach(addr, {
      onEnter: function(args) {
        send({
          func: h.name,
          caller: Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n"),
        });
      }
    });
    send("Hooked " + h.name);
  }
});
send("Crypto tracer active");`,
  },
  "network-trace": {
    label: "Network Calls Tracer",
    code: `["connect", "send", "recv", "sendto", "recvfrom", "SSL_read", "SSL_write"].forEach(function(name) {
  var addr = Module.findExportByName(null, name);
  if (addr) {
    Interceptor.attach(addr, {
      onEnter: function(args) {
        var info = { func: name, fd: args[0].toInt32() };
        if (name === "connect") {
          try {
            var sa = args[1];
            var family = sa.add(1).readU8();
            if (family === 2) {
              info.ip = sa.add(4).readU8()+"."+sa.add(5).readU8()+"."+sa.add(6).readU8()+"."+sa.add(7).readU8();
              info.port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
            }
          } catch(e) {}
        }
        send(info);
      }
    });
  }
});
send("Network tracer active");`,
  },
  "jailbreak-detect-bypass": {
    label: "Jailbreak Detection Bypass (iOS)",
    code: `if (ObjC.available) {
  var paths = [
    "/Applications/Cydia.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/bin/bash",
    "/usr/sbin/sshd",
    "/etc/apt",
    "/private/var/lib/apt/",
    "/usr/bin/ssh",
  ];
  var access = Module.findExportByName(null, "access");
  var stat = Module.findExportByName(null, "stat");
  [access, stat].filter(Boolean).forEach(function(addr) {
    Interceptor.attach(addr, {
      onEnter: function(args) {
        try {
          var path = args[0].readUtf8String();
          if (paths.some(function(p) { return path && path.indexOf(p) !== -1; })) {
            this.bypass = true;
            send("Bypass check for: " + path);
          }
        } catch(e) {}
      },
      onLeave: function(retval) {
        if (this.bypass) retval.replace(ptr(-1));
      }
    });
  });
  var NSFileManager = ObjC.classes.NSFileManager;
  Interceptor.attach(NSFileManager["- fileExistsAtPath:"].implementation, {
    onEnter: function(args) {
      var path = new ObjC.Object(args[2]).toString();
      if (paths.some(function(p) { return path.indexOf(p) !== -1; })) {
        this.bypass = true;
        send("NSFileManager bypass: " + path);
      }
    },
    onLeave: function(retval) {
      if (this.bypass) retval.replace(ptr(0));
    }
  });
  var forkAddr = Module.findExportByName(null, "fork");
  if (forkAddr) {
    Interceptor.replace(forkAddr, new NativeCallback(function() { return -1; }, "int", []));
    send("fork() disabled");
  }
  send("Jailbreak detection bypass active");
} else {
  send("ObjC runtime not available");
}`,
  },
  "root-detect-bypass": {
    label: "Root Detection Bypass (Android)",
    code: `Java.perform(function() {
  var RootPaths = [
    "/system/app/Superuser.apk",
    "/sbin/su",
    "/system/bin/su",
    "/system/xbin/su",
    "/data/local/xbin/su",
    "/data/local/bin/su",
    "/system/sd/xbin/su",
    "/data/local/su",
    "/su/bin/su",
    "/system/bin/.ext/.su",
    "/system/usr/we-need-root/su-backup",
  ];
  var File = Java.use("java.io.File");
  File.exists.implementation = function() {
    var path = this.getAbsolutePath();
    if (RootPaths.indexOf(path) !== -1) {
      send("Root check bypass: " + path);
      return false;
    }
    return this.exists();
  };
  try {
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
      if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
        send("Blocked exec: " + cmd);
        throw Java.use("java.io.IOException").$new("Not found");
      }
      return this.exec(cmd);
    };
  } catch(e) {}
  var Build = Java.use("android.os.Build");
  Build.TAGS.value = "release-keys";
  send("Root detection bypass active");
});`,
  },
  "keychain-dump": {
    label: "Keychain Dump (iOS)",
    code: `if (ObjC.available) {
  var NSMutableDictionary = ObjC.classes.NSMutableDictionary;
  var query = NSMutableDictionary.alloc().init();
  var kSecClass = ObjC.classes.__NSCFString.alloc().initWithString_("class");
  query.setObject_forKey_(ObjC.classes.__NSCFString.alloc().initWithString_("genp"), kSecClass);
  query.setObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true), ObjC.classes.__NSCFString.alloc().initWithString_("r_Data"));
  query.setObject_forKey_(ObjC.classes.__NSCFString.alloc().initWithString_("m_LimitAll"), ObjC.classes.__NSCFString.alloc().initWithString_("m_Limit"));
  query.setObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true), ObjC.classes.__NSCFString.alloc().initWithString_("r_Attributes"));
  var SecItemCopyMatching = new NativeFunction(
    Module.findExportByName("Security", "SecItemCopyMatching"), "int", ["pointer", "pointer"]
  );
  var resultPtr = Memory.alloc(Process.pointerSize);
  var status = SecItemCopyMatching(query.handle, resultPtr);
  if (status === 0) {
    var results = new ObjC.Object(resultPtr.readPointer());
    send("Found " + results.count() + " keychain items");
    for (var i = 0; i < results.count(); i++) {
      var item = results.objectAtIndex_(i);
      send(item.toString());
    }
  } else {
    send("SecItemCopyMatching returned: " + status);
  }
} else {
  send("ObjC runtime not available");
}`,
  },
  "shared-prefs": {
    label: "SharedPreferences Dump (Android)",
    code: `Java.perform(function() {
  var context = null;
  Java.choose("android.app.ActivityThread", {
    onMatch: function(instance) {
      context = instance.getApplication().getApplicationContext();
    },
    onComplete: function() {}
  });
  if (!context) { send("No context found"); return; }
  var File = Java.use("java.io.File");
  var prefsDir = new File(context.getFilesDir().getParent() + "/shared_prefs");
  if (prefsDir.exists()) {
    var files = prefsDir.listFiles();
    for (var i = 0; i < files.length; i++) {
      var name = files[i].getName().replace(".xml", "");
      var prefs = context.getSharedPreferences(name, 0);
      var all = prefs.getAll();
      var entries = {};
      var it = all.entrySet().iterator();
      while (it.hasNext()) {
        var entry = it.next();
        entries[entry.getKey().toString()] = entry.getValue() ? entry.getValue().toString() : null;
      }
      send({ file: name, entries: entries });
    }
  }
  send("SharedPreferences dump complete");
});`,
  },
  "backtrace": {
    label: "Function Call Backtrace",
    code: `var targetFunc = Module.findExportByName(null, "malloc");
if (targetFunc) {
  Interceptor.attach(targetFunc, {
    onEnter: function(args) {
      var size = args[0].toInt32();
      if (size > 1024) {
        send({
          func: "malloc",
          size: size,
          backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .join("\\n")
        });
      }
    }
  });
  send("Tracing large malloc() calls (>1KB)...");
} else {
  send("malloc not found");
}`,
  },
};
