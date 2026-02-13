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
      var addr = Module.findExportByName(null, name);
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
      var addr = Module.findExportByName(null, name);
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
