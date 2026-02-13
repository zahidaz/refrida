function escapeStr(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

export function enumerateModulesScript(): string {
  return `
var mods = Process.enumerateModules();
for (var i = 0; i < mods.length; i++) {
  var m = mods[i];
  send({ name: m.name, base: m.base.toString(), size: m.size, path: m.path });
}
send({ type: "__done__" });
`;
}

export function enumerateExportsScript(moduleName: string): string {
  return `
var mod = Process.findModuleByName("${escapeStr(moduleName)}");
if (mod) {
  var exps = mod.enumerateExports();
  for (var i = 0; i < exps.length; i++) {
    var e = exps[i];
    send({ type: e.type, name: e.name, address: e.address.toString() });
  }
}
send({ type: "__done__" });
`;
}

export function enumerateImportsScript(moduleName: string): string {
  return `
var mod = Process.findModuleByName("${escapeStr(moduleName)}");
if (mod) {
  var imps = mod.enumerateImports();
  for (var i = 0; i < imps.length; i++) {
    var e = imps[i];
    send({ type: e.type || "", name: e.name, module: e.module || "", address: (e.address || ptr(0)).toString() });
  }
}
send({ type: "__done__" });
`;
}

export function enumerateSymbolsScript(moduleName: string): string {
  return `
var mod = Process.findModuleByName("${escapeStr(moduleName)}");
if (mod) {
  var syms = mod.enumerateSymbols();
  for (var i = 0; i < syms.length; i++) {
    var s = syms[i];
    send({ name: s.name, address: s.address.toString(), type: s.type || "", isGlobal: s.isGlobal });
  }
}
send({ type: "__done__" });
`;
}

export function enumerateRangesScript(moduleName: string): string {
  return `
var mod = Process.findModuleByName("${escapeStr(moduleName)}");
if (mod) {
  var base = mod.base;
  var limit = base.add(mod.size);
  var ranges = Process.enumerateRanges("---");
  for (var i = 0; i < ranges.length; i++) {
    var r = ranges[i];
    var rBase = r.base;
    var rEnd = rBase.add(r.size);
    if (rBase.compare(limit) < 0 && rEnd.compare(base) > 0) {
      send({ base: r.base.toString(), size: r.size, protection: r.protection });
    }
  }
}
send({ type: "__done__" });
`;
}

export function dumpModuleScript(moduleName: string): string {
  return `
var mod = Process.findModuleByName("${escapeStr(moduleName)}");
if (mod) {
  var CHUNK = 65536;
  var base = mod.base;
  var remaining = mod.size;
  var offset = 0;
  while (remaining > 0) {
    var n = Math.min(CHUNK, remaining);
    try {
      var buf = base.add(offset).readByteArray(n);
      if (buf) {
        var arr = new Uint8Array(buf);
        var result = [];
        for (var i = 0; i < arr.length; i++) result.push(arr[i]);
        send({ offset: offset, bytes: result });
      }
    } catch(e) {
      send({ offset: offset, bytes: [], error: e.message });
    }
    offset += n;
    remaining -= n;
  }
}
send({ type: "__done__" });
`;
}

export function readMemoryScript(address: string, size: number): string {
  return `
try {
  var addr = ptr("${escapeStr(address)}");
  var buf = addr.readByteArray(${size});
  if (buf) {
    var arr = new Uint8Array(buf);
    var result = [];
    for (var i = 0; i < arr.length; i++) result.push(arr[i]);
    send({ bytes: result, address: addr.toString() });
  } else {
    send({ type: "__utility_error__", message: "Could not read memory" });
  }
} catch(e) {
  send({ type: "__utility_error__", message: e.message });
}
send({ type: "__done__" });
`;
}

export function writeMemoryScript(address: string, bytes: number[]): string {
  return `
try {
  var addr = ptr("${escapeStr(address)}");
  var buf = new Uint8Array([${bytes.join(",")}]);
  addr.writeByteArray(buf.buffer);
  send({ ok: true, address: addr.toString(), count: buf.length });
} catch(e) {
  send({ type: "__utility_error__", message: e.message });
}
send({ type: "__done__" });
`;
}

export function searchMemoryScript(pattern: string, isHex: boolean): string {
  if (isHex) {
    const hexPattern = pattern.replace(/\s+/g, " ").trim();
    return `
try {
  var ranges = Process.enumerateRanges("r--");
  var found = 0;
  for (var i = 0; i < ranges.length && found < 500; i++) {
    var r = ranges[i];
    try {
      var matches = Memory.scanSync(r.base, r.size, "${escapeStr(hexPattern)}");
      for (var j = 0; j < matches.length && found < 500; j++) {
        var m = matches[j];
        var ctx = [];
        try {
          var buf = m.address.readByteArray(32);
          if (buf) { var a = new Uint8Array(buf); for (var k = 0; k < a.length; k++) ctx.push(a[k]); }
        } catch(e2) {}
        var mod = Process.findModuleByAddress(m.address);
        send({ address: m.address.toString(), size: m.size, context: ctx, module: mod ? mod.name : null });
        found++;
      }
    } catch(e) {}
  }
} catch(e) {
  send({ type: "__utility_error__", message: e.message });
}
send({ type: "__done__" });
`;
  }
  const escaped = escapeStr(pattern);
  return `
try {
  var ranges = Process.enumerateRanges("r--");
  var needle = [];
  var str = "${escaped}";
  for (var i = 0; i < str.length; i++) needle.push(str.charCodeAt(i).toString(16).padStart(2, "0"));
  var hexPattern = needle.join(" ");
  var found = 0;
  for (var i = 0; i < ranges.length && found < 500; i++) {
    var r = ranges[i];
    try {
      var matches = Memory.scanSync(r.base, r.size, hexPattern);
      for (var j = 0; j < matches.length && found < 500; j++) {
        var m = matches[j];
        var ctx = [];
        try {
          var buf = m.address.readByteArray(64);
          if (buf) { var a = new Uint8Array(buf); for (var k = 0; k < a.length; k++) ctx.push(a[k]); }
        } catch(e2) {}
        var mod = Process.findModuleByAddress(m.address);
        send({ address: m.address.toString(), size: m.size, context: ctx, module: mod ? mod.name : null });
        found++;
      }
    } catch(e) {}
  }
} catch(e) {
  send({ type: "__utility_error__", message: e.message });
}
send({ type: "__done__" });
`;
}

export function disassembleScript(address: string, count: number): string {
  return `
try {
  var addr = ptr("${escapeStr(address)}");
  var cursor = addr;
  for (var i = 0; i < ${count}; i++) {
    var insn = Instruction.parse(cursor);
    var bytes = [];
    try {
      var buf = insn.address.readByteArray(insn.size);
      if (buf) { var a = new Uint8Array(buf); for (var j = 0; j < a.length; j++) bytes.push(a[j]); }
    } catch(e2) {}
    send({
      address: insn.address.toString(),
      mnemonic: insn.mnemonic,
      opStr: insn.opStr,
      size: insn.size,
      bytes: bytes
    });
    cursor = insn.next;
  }
} catch(e) {
  send({ type: "__utility_error__", message: e.message });
}
send({ type: "__done__" });
`;
}

export function apiResolverScript(query: string): string {
  return `
try {
  var resolver = new ApiResolver("module");
  var matches = resolver.enumerateMatches("${escapeStr(query)}");
  var count = Math.min(matches.length, 500);
  for (var i = 0; i < count; i++) {
    var m = matches[i];
    var mod = Process.findModuleByAddress(m.address);
    send({ name: m.name, address: m.address.toString(), module: mod ? mod.name : null });
  }
  if (matches.length > 500) send({ truncated: true, total: matches.length });
} catch(e) {
  send({ type: "__utility_error__", message: e.message });
}
send({ type: "__done__" });
`;
}

export function stringDumpScript(moduleName: string, minLength: number): string {
  return `
try {
  var mod = Process.findModuleByName("${escapeStr(moduleName)}");
  if (!mod) { send({ type: "__utility_error__", message: "Module not found" }); send({ type: "__done__" }); }
  else {
    var ranges = Process.enumerateRanges("r--");
    var base = mod.base;
    var limit = base.add(mod.size);
    var strings = [];
    for (var ri = 0; ri < ranges.length; ri++) {
      var r = ranges[ri];
      if (r.base.compare(limit) >= 0 || r.base.add(r.size).compare(base) <= 0) continue;
      try {
        var buf = r.base.readByteArray(r.size);
        if (!buf) continue;
        var arr = new Uint8Array(buf);
        var current = "";
        var startOff = 0;
        for (var i = 0; i < arr.length; i++) {
          var b = arr[i];
          if (b >= 0x20 && b <= 0x7e) {
            if (current.length === 0) startOff = i;
            current += String.fromCharCode(b);
          } else {
            if (current.length >= ${minLength}) {
              strings.push({ value: current, address: r.base.add(startOff).toString(), offset: startOff });
              if (strings.length >= 200) { send({ batch: strings }); strings = []; }
            }
            current = "";
          }
        }
        if (current.length >= ${minLength}) {
          strings.push({ value: current, address: r.base.add(startOff).toString(), offset: startOff });
        }
      } catch(e) {}
    }
    if (strings.length > 0) send({ batch: strings });
  }
} catch(e) {
  send({ type: "__utility_error__", message: e.message });
}
send({ type: "__done__" });
`;
}

export function networkMonitorScript(): string {
  return `
try {
  var hooks = [];
  function tryHook(name, cb) {
    try {
      var addr = Module.findGlobalExportByName(name);
      if (addr) { hooks.push(Interceptor.attach(addr, cb)); }
    } catch(e) {}
  }
  function readPreview(buf, len) {
    var preview = [];
    try { var b = buf.readByteArray(Math.min(len, 128)); if (b) { var a = new Uint8Array(b); for (var i=0;i<a.length;i++) preview.push(a[i]); } } catch(e) {}
    return preview;
  }
  tryHook("connect", {
    onEnter: function(args) {
      try {
        this.fd = args[0].toInt32();
        var sa = args[1];
        var family = sa.add(1).readU8();
        if (family === 2) {
          var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
          var ip = sa.add(4).readU8()+"."+sa.add(5).readU8()+"."+sa.add(6).readU8()+"."+sa.add(7).readU8();
          this.info = { ip: ip, port: port };
        }
      } catch(e) {}
    },
    onLeave: function(retval) {
      try { if (this.info) send({ event: "connect", fd: this.fd, ip: this.info.ip, port: this.info.port, result: retval.toInt32(), ts: Date.now() }); } catch(e) {}
    }
  });
  tryHook("send", {
    onEnter: function(args) {
      try {
        var fd = args[0].toInt32();
        var len = args[2].toInt32();
        send({ event: "send", fd: fd, length: len, preview: readPreview(args[1], len), ts: Date.now() });
      } catch(e) {}
    }
  });
  tryHook("recv", {
    onEnter: function(args) { try { this.fd = args[0].toInt32(); this.buf = args[1]; } catch(e) {} },
    onLeave: function(retval) {
      try {
        var n = retval.toInt32();
        if (n > 0) send({ event: "recv", fd: this.fd, length: n, preview: readPreview(this.buf, n), ts: Date.now() });
      } catch(e) {}
    }
  });
  tryHook("recvfrom", {
    onEnter: function(args) { try { this.fd = args[0].toInt32(); this.buf = args[1]; } catch(e) {} },
    onLeave: function(retval) {
      try {
        var n = retval.toInt32();
        if (n > 0) send({ event: "recvfrom", fd: this.fd, length: n, preview: readPreview(this.buf, n), ts: Date.now() });
      } catch(e) {}
    }
  });
  tryHook("sendto", {
    onEnter: function(args) {
      try {
        var fd = args[0].toInt32();
        var len = args[2].toInt32();
        send({ event: "sendto", fd: fd, length: len, preview: readPreview(args[1], len), ts: Date.now() });
      } catch(e) {}
    }
  });
  send({ event: "__started__", fd: 0, ts: Date.now() });
} catch(e) {
  send({ type: "__utility_error__", message: e.message || String(e) });
}
`;
}

export function fileMonitorScript(): string {
  return `
try {
  var hooks = [];
  function tryHook(name, cb) {
    try {
      var addr = Module.findGlobalExportByName(name);
      if (addr) { hooks.push(Interceptor.attach(addr, cb)); }
    } catch(e) {}
  }
  var fdPaths = {};
  tryHook("open", {
    onEnter: function(args) { try { this.path = args[0].readUtf8String(); this.flags = args[1].toInt32(); } catch(e) {} },
    onLeave: function(retval) {
      try {
        var fd = retval.toInt32();
        if (fd >= 0 && this.path) { fdPaths[fd] = this.path; send({ event: "open", fd: fd, path: this.path, flags: this.flags, ts: Date.now() }); }
      } catch(e) {}
    }
  });
  tryHook("openat", {
    onEnter: function(args) { try { this.path = args[1].readUtf8String(); this.flags = args[2].toInt32(); } catch(e) {} },
    onLeave: function(retval) {
      try {
        var fd = retval.toInt32();
        if (fd >= 0 && this.path) { fdPaths[fd] = this.path; send({ event: "open", fd: fd, path: this.path, flags: this.flags, ts: Date.now() }); }
      } catch(e) {}
    }
  });
  tryHook("read", {
    onEnter: function(args) { try { this.fd = args[0].toInt32(); } catch(e) {} },
    onLeave: function(retval) {
      try {
        var n = retval.toInt32();
        if (n > 0) send({ event: "read", fd: this.fd, length: n, path: fdPaths[this.fd] || null, ts: Date.now() });
      } catch(e) {}
    }
  });
  tryHook("write", {
    onEnter: function(args) {
      try {
        var fd = args[0].toInt32();
        var len = args[2].toInt32();
        send({ event: "write", fd: fd, length: len, path: fdPaths[fd] || null, ts: Date.now() });
      } catch(e) {}
    }
  });
  tryHook("close", {
    onEnter: function(args) {
      try {
        var fd = args[0].toInt32();
        var path = fdPaths[fd] || null;
        if (path) { send({ event: "close", fd: fd, path: path, ts: Date.now() }); delete fdPaths[fd]; }
      } catch(e) {}
    }
  });
  send({ event: "__started__", fd: 0, ts: Date.now() });
} catch(e) {
  send({ type: "__utility_error__", message: e.message || String(e) });
}
`;
}

export function stalkerTraceScript(threadId: string, eventTypes: Record<string, boolean>): string {
  const evCall = eventTypes.call !== false;
  const evRet = !!eventTypes.ret;
  const evExec = !!eventTypes.exec;
  const evBlock = !!eventTypes.block;
  const evCompile = !!eventTypes.compile;

  return `
try {
  var tid = ${threadId || "Process.getCurrentThreadId()"};
  var batch = [];
  var flushTimer = null;

  function flushBatch() {
    if (batch.length === 0) return;
    for (var i = 0; i < batch.length; i++) {
      send(batch[i]);
    }
    batch = [];
  }

  function queueEvent(ev) {
    batch.push(ev);
    if (batch.length >= 50) {
      flushBatch();
    } else if (!flushTimer) {
      flushTimer = setTimeout(function() {
        flushTimer = null;
        flushBatch();
      }, 100);
    }
  }

  function resolveAddr(addr) {
    var p = ptr(addr);
    var mod = Process.findModuleByAddress(p);
    var sym = null;
    try { sym = DebugSymbol.fromAddress(p).name; } catch(e) {}
    return { module: mod ? mod.name : null, symbol: sym || null };
  }

  Stalker.follow(tid, {
    events: {
      call: ${evCall},
      ret: ${evRet},
      exec: ${evExec},
      block: ${evBlock},
      compile: ${evCompile}
    },
    onReceive: function(rawEvents) {
      var parsed = Stalker.parse(rawEvents, { stringify: false, annotate: true });
      for (var i = 0; i < parsed.length; i++) {
        var ev = parsed[i];
        var evType = ev[0];
        var from = ev[1];
        var info = resolveAddr(from);
        var entry = {
          type: evType,
          address: from.toString(),
          module: info.module,
          symbol: info.symbol,
          ts: Date.now()
        };
        if (ev[2] !== undefined) {
          entry.target = ev[2].toString();
        }
        queueEvent(entry);
      }
    }
  });

  send({ event: "__started__" });
} catch(e) {
  send({ type: "__utility_error__", message: e.message || String(e) });
}
`;
}

export function processInfoScript(): string {
  return `
try {
  var threads = Process.enumerateThreads();
  var modules = Process.enumerateModules();
  var ranges = Process.enumerateRanges("---");
  var totalMapped = 0;
  for (var i = 0; i < ranges.length; i++) totalMapped += ranges[i].size;
  var mm = Process.mainModule;
  send({
    pid: Process.id,
    arch: Process.arch,
    platform: Process.platform,
    pageSize: Process.pageSize,
    pointerSize: Process.pointerSize,
    mainModule: { name: mm.name, base: mm.base.toString(), size: mm.size, path: mm.path },
    threadCount: threads.length,
    moduleCount: modules.length,
    rangeCount: ranges.length,
    totalMappedSize: totalMapped,
    currentThreadId: Process.getCurrentThreadId()
  });
} catch(e) {
  send({ type: "__utility_error__", message: e.message || String(e) });
}
send({ type: "__done__" });
`;
}

export function enumerateThreadsScript(): string {
  return `
try {
  var threads = Process.enumerateThreads();
  for (var i = 0; i < threads.length; i++) {
    var t = threads[i];
    var ctx = t.context;
    send({
      id: t.id,
      state: t.state,
      pc: ctx.pc ? ctx.pc.toString() : null,
      sp: ctx.sp ? ctx.sp.toString() : null
    });
  }
} catch(e) {
  send({ type: "__utility_error__", message: e.message || String(e) });
}
send({ type: "__done__" });
`;
}

export function enumerateEnvVarsScript(): string {
  return `
try {
  var platform = Process.platform;
  var found = false;

  function sendPair(s) {
    var eq = s.indexOf("=");
    if (eq > 0) {
      send({ key: s.substring(0, eq), value: s.substring(eq + 1) });
    }
  }

  function readEnvironPointer(envp) {
    if (!envp || envp.isNull()) return false;
    var idx = 0;
    while (idx < 10000) {
      var entry = envp.add(idx * Process.pointerSize).readPointer();
      if (entry.isNull()) break;
      try {
        var s = entry.readUtf8String();
        if (s) sendPair(s);
      } catch(e2) {}
      idx++;
    }
    return idx > 0;
  }

  if (platform === "windows") {
    var kernel32 = Process.findModuleByName("kernel32.dll");
    var getEnvW = kernel32 ? kernel32.findExportByName("GetEnvironmentStringsW") : null;
    var freeEnvW = kernel32 ? kernel32.findExportByName("FreeEnvironmentStringsW") : null;
    if (getEnvW && freeEnvW) {
      var GetEnvironmentStringsW = new NativeFunction(getEnvW, "pointer", []);
      var FreeEnvironmentStringsW = new NativeFunction(freeEnvW, "int", ["pointer"]);
      var block = GetEnvironmentStringsW();
      if (!block.isNull()) {
        var offset = 0;
        while (true) {
          var s = block.add(offset).readUtf16String();
          if (!s || s.length === 0) break;
          sendPair(s);
          offset += (s.length + 1) * 2;
        }
        FreeEnvironmentStringsW(block);
        found = true;
      }
    }
  }

  if (!found && platform === "darwin") {
    try {
      if (typeof ObjC !== "undefined" && ObjC.available) {
        var env = ObjC.classes.NSProcessInfo.processInfo().environment();
        var keys = env.allKeys();
        var count = keys.count().valueOf();
        for (var ki = 0; ki < count; ki++) {
          var k = keys.objectAtIndex_(ki).toString();
          var v = env.objectForKey_(keys.objectAtIndex_(ki)).toString();
          send({ key: k, value: v });
        }
        found = true;
      }
    } catch(e4) {}
    if (!found) {
      var nsGetEnviron = Module.findGlobalExportByName("_NSGetEnviron");
      if (nsGetEnviron) {
        var getEnvironFn = new NativeFunction(nsGetEnviron, "pointer", []);
        var envpPtr = getEnvironFn();
        if (!envpPtr.isNull()) {
          found = readEnvironPointer(envpPtr.readPointer());
        }
      }
    }
  }

  if (!found) {
    var procEnv = null;
    try {
      var openFn = new NativeFunction(Module.findGlobalExportByName("fopen"), "pointer", ["pointer", "pointer"]);
      var readFn = new NativeFunction(Module.findGlobalExportByName("fread"), "int", ["pointer", "int", "int", "pointer"]);
      var closeFn = new NativeFunction(Module.findGlobalExportByName("fclose"), "int", ["pointer"]);
      var pathBuf = Memory.allocUtf8String("/proc/self/environ");
      var modeBuf = Memory.allocUtf8String("r");
      var fp = openFn(pathBuf, modeBuf);
      if (!fp.isNull()) {
        var buf = Memory.alloc(65536);
        var n = readFn(buf, 1, 65536, fp);
        closeFn(fp);
        if (n > 0) {
          var raw = buf.readByteArray(n);
          var bytes = new Uint8Array(raw);
          var str = "";
          for (var i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
          var pairs = str.split("\\0");
          for (var j = 0; j < pairs.length; j++) {
            if (pairs[j].length > 0) sendPair(pairs[j]);
          }
          found = true;
        }
      }
    } catch(e3) {}
  }

  if (!found) {
    var environSym = Module.findGlobalExportByName("environ");
    if (environSym) {
      readEnvironPointer(environSym.readPointer());
    }
  }
} catch(e) {
  send({ type: "__utility_error__", message: e.message || String(e) });
}
send({ type: "__done__" });
`;
}

export function scanFileSignaturesScript(): string {
  return `
try {
  var sigs = {
    "PNG":    "89 50 4E 47 0D 0A 1A 0A",
    "JPEG":   "FF D8 FF",
    "GIF":    "47 49 46 38",
    "PDF":    "25 50 44 46",
    "ZIP":    "50 4B 03 04",
    "ELF":    "7F 45 4C 46",
    "MachO":  "CF FA ED FE",
    "PE":     "4D 5A 90 00",
    "SQLite": "53 51 4C 69 74 65",
    "DEX":    "64 65 78 0A",
    "BPLIST": "62 70 6C 69 73 74",
    "PEM":    "2D 2D 2D 2D 2D 42 45 47 49 4E",
    "GZIP":   "1F 8B 08",
    "BZ2":    "42 5A 68",
    "7Z":     "37 7A BC AF 27 1C",
    "OGG":    "4F 67 67 53",
    "FLAC":   "66 4C 61 43",
    "RIFF":   "52 49 46 46"
  };
  var ranges = Process.enumerateRanges("r--");
  var count = 0;
  for (var i = 0; i < ranges.length; i++) {
    var r = ranges[i];
    if (r.size < 4 || r.size > 100 * 1024 * 1024) continue;
    for (var sigName in sigs) {
      try {
        var matches = Memory.scanSync(r.base, r.size, sigs[sigName]);
        for (var j = 0; j < matches.length; j++) {
          var addr = matches[j].address;
          var mod = null;
          try { mod = Process.findModuleByAddress(addr); } catch(e) {}
          send({
            fileType: sigName,
            address: addr.toString(),
            module: mod ? mod.name : null,
            offset: mod ? "0x" + addr.sub(mod.base).toString(16) : null
          });
          count++;
          if (count > 5000) break;
        }
      } catch(e) {}
      if (count > 5000) break;
    }
    if (count > 5000) break;
  }
} catch(e) {
  send({ type: "__utility_error__", message: e.message || String(e) });
}
send({ type: "__done__" });
`;
}

export function dumpFileFromMemoryScript(address: string, maxSize: number): string {
  return `
try {
  var addr = ptr("${escapeStr(address)}");
  var maxSz = ${maxSize};
  var data = addr.readByteArray(maxSz);
  if (data) {
    var bytes = new Uint8Array(data);
    var chunk = [];
    for (var i = 0; i < bytes.length; i++) {
      chunk.push(bytes[i]);
      if (chunk.length >= 4096) {
        send({ offset: i - chunk.length + 1, bytes: chunk });
        chunk = [];
      }
    }
    if (chunk.length > 0) {
      send({ offset: bytes.length - chunk.length, bytes: chunk });
    }
  }
} catch(e) {
  send({ type: "__utility_error__", message: e.message || String(e) });
}
send({ type: "__done__" });
`;
}

export function evalScript(code: string): string {
  return `
try {
  var __r = (function() { ${code} })();
  if (__r !== undefined) send(__r);
} catch(e) {
  send({ type: "__utility_error__", message: e.message, stack: e.stack });
}
send({ type: "__done__" });
`;
}
