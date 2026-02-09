export const TEMPLATES: Record<string, { label: string; code: string }> = {
  hello: {
    label: "Hello World",
    code: `send("Hello from Frida!");`,
  },
  modules: {
    label: "Enumerate Modules",
    code: `Process.enumerateModules().forEach(m => {
  send({ name: m.name, base: m.base.toString(), size: m.size });
});`,
  },
  exports: {
    label: "Enumerate Exports",
    code: `const target = Process.enumerateModules()[0];
send("Exports for " + target.name + ":");
target.enumerateExports().slice(0, 50).forEach(e => {
  send({ type: e.type, name: e.name, address: e.address.toString() });
});`,
  },
  "classes-ios": {
    label: "ObjC Classes (iOS)",
    code: `if (ObjC.available) {
  const classes = ObjC.classes;
  const names = Object.keys(classes).slice(0, 100);
  send({ count: Object.keys(classes).length, sample: names });
} else {
  send("ObjC runtime not available");
}`,
  },
  "classes-android": {
    label: "Java Classes (Android)",
    code: `Java.perform(() => {
  Java.enumerateLoadedClasses({
    onMatch(name) { send(name); },
    onComplete() { send("--- done ---"); }
  });
});`,
  },
  "hook-func": {
    label: "Hook Native Function",
    code: `const addr = Module.findExportByName("libfoo.so", "target_func");
if (addr) {
  Interceptor.attach(addr, {
    onEnter(args) {
      send("target_func called, arg0: " + args[0]);
    },
    onLeave(retval) {
      send("target_func returned: " + retval);
    }
  });
  send("Hooked target_func at " + addr);
} else {
  send("Function not found");
}`,
  },
  "hook-objc": {
    label: "Hook ObjC Method (iOS)",
    code: `if (ObjC.available) {
  const className = "NSURLSession";
  const methodName = "- dataTaskWithRequest:completionHandler:";
  const hook = ObjC.classes[className][methodName];
  Interceptor.attach(hook.implementation, {
    onEnter(args) {
      const req = new ObjC.Object(args[2]);
      send({
        method: req.HTTPMethod().toString(),
        url: req.URL().absoluteString().toString()
      });
    }
  });
  send("Hooked " + className + " " + methodName);
} else {
  send("ObjC runtime not available");
}`,
  },
  "hook-java": {
    label: "Hook Java Method (Android)",
    code: `Java.perform(() => {
  const Activity = Java.use("android.app.Activity");
  Activity.onCreate.overload("android.os.Bundle").implementation = function(bundle) {
    send("Activity.onCreate: " + this.getClass().getName());
    this.onCreate(bundle);
  };
  send("Hooked Activity.onCreate");
});`,
  },
  intercept: {
    label: "Interceptor Attach",
    code: `const openPtr = Module.findExportByName(null, "open");
Interceptor.attach(openPtr, {
  onEnter(args) {
    this.path = args[0].readUtf8String();
  },
  onLeave(retval) {
    send({ syscall: "open", path: this.path, fd: retval.toInt32() });
  }
});
send("Intercepting open() calls...");`,
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
  "memory-scan": {
    label: "Memory Scan",
    code: `const mod = Process.enumerateModules()[0];
const pattern = "48 65 6c 6c 6f";
Memory.scan(mod.base, mod.size, pattern, {
  onMatch(address, size) {
    send({ found: address.toString(), preview: address.readUtf8String(32) });
  },
  onComplete() {
    send("Scan complete");
  }
});
send("Scanning " + mod.name + " for pattern...");`,
  },
  rpc: {
    label: "RPC Exports",
    code: `rpc.exports = {
  add(a, b) { return a + b; },
  getModules() {
    return Process.enumerateModules().map(m => ({
      name: m.name, base: m.base.toString(), size: m.size
    }));
  },
  readMemory(addr, size) {
    return ptr(addr).readByteArray(size);
  }
};`,
  },
};
