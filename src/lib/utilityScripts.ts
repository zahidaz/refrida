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
