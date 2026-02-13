import { describe, it, expect } from "vitest";
import {
  enumerateModulesScript,
  enumerateExportsScript,
  enumerateImportsScript,
  enumerateSymbolsScript,
  enumerateRangesScript,
  dumpModuleScript,
  readMemoryScript,
  writeMemoryScript,
  searchMemoryScript,
  disassembleScript,
  apiResolverScript,
  stringDumpScript,
  networkMonitorScript,
  fileMonitorScript,
  stalkerTraceScript,
  processInfoScript,
  enumerateThreadsScript,
  enumerateEnvVarsScript,
  scanFileSignaturesScript,
  dumpFileFromMemoryScript,
  evalScript,
} from "@/lib/utilityScripts.ts";

describe("utilityScripts", () => {
  describe("enumerateModulesScript", () => {
    it("generates script that enumerates modules and sends done", () => {
      const script = enumerateModulesScript();
      expect(script).toContain("Process.enumerateModules()");
      expect(script).toContain('send({ type: "__done__" })');
    });
  });

  describe("enumerateExportsScript", () => {
    it("embeds module name in script", () => {
      const script = enumerateExportsScript("libc.so");
      expect(script).toContain('"libc.so"');
      expect(script).toContain("enumerateExports()");
      expect(script).toContain("__done__");
    });

    it("escapes special characters in module name", () => {
      const script = enumerateExportsScript('mod"with"quotes');
      expect(script).toContain('mod\\"with\\"quotes');
    });
  });

  describe("enumerateImportsScript", () => {
    it("generates valid import enumeration script", () => {
      const script = enumerateImportsScript("libfoo.dylib");
      expect(script).toContain('"libfoo.dylib"');
      expect(script).toContain("enumerateImports()");
    });
  });

  describe("enumerateSymbolsScript", () => {
    it("generates valid symbol enumeration script", () => {
      const script = enumerateSymbolsScript("libSystem.B.dylib");
      expect(script).toContain('"libSystem.B.dylib"');
      expect(script).toContain("enumerateSymbols()");
    });
  });

  describe("enumerateRangesScript", () => {
    it("generates valid range enumeration script", () => {
      const script = enumerateRangesScript("libtest.so");
      expect(script).toContain('"libtest.so"');
      expect(script).toContain("enumerateRanges");
    });
  });

  describe("dumpModuleScript", () => {
    it("generates chunked dump script", () => {
      const script = dumpModuleScript("app_main");
      expect(script).toContain('"app_main"');
      expect(script).toContain("readByteArray");
      expect(script).toContain("CHUNK");
    });
  });

  describe("readMemoryScript", () => {
    it("embeds address and size", () => {
      const script = readMemoryScript("0x1000", 256);
      expect(script).toContain('"0x1000"');
      expect(script).toContain("256");
      expect(script).toContain("readByteArray");
    });
  });

  describe("writeMemoryScript", () => {
    it("embeds address and byte array", () => {
      const script = writeMemoryScript("0x2000", [0x41, 0x42, 0x43]);
      expect(script).toContain('"0x2000"');
      expect(script).toContain("65,66,67");
      expect(script).toContain("writeByteArray");
    });
  });

  describe("searchMemoryScript", () => {
    it("generates hex pattern search for hex mode", () => {
      const script = searchMemoryScript("FF 00 AA", true);
      expect(script).toContain("FF 00 AA");
      expect(script).toContain("Memory.scanSync");
    });

    it("converts string to hex pattern for string mode", () => {
      const script = searchMemoryScript("hello", false);
      expect(script).toContain("Memory.scanSync");
      expect(script).toContain("charCodeAt");
    });
  });

  describe("disassembleScript", () => {
    it("embeds address and instruction count", () => {
      const script = disassembleScript("0x1000", 50);
      expect(script).toContain('"0x1000"');
      expect(script).toContain("50");
      expect(script).toContain("Instruction.parse");
    });
  });

  describe("apiResolverScript", () => {
    it("embeds query string", () => {
      const script = apiResolverScript("exports:*!open*");
      expect(script).toContain("exports:*!open*");
      expect(script).toContain("ApiResolver");
    });
  });

  describe("stringDumpScript", () => {
    it("embeds module name and min length", () => {
      const script = stringDumpScript("libtest.so", 4);
      expect(script).toContain('"libtest.so"');
      expect(script).toContain("4");
    });
  });

  describe("networkMonitorScript", () => {
    it("hooks network functions", () => {
      const script = networkMonitorScript();
      expect(script).toContain('"connect"');
      expect(script).toContain('"send"');
      expect(script).toContain('"recv"');
      expect(script).toContain("__started__");
    });
  });

  describe("fileMonitorScript", () => {
    it("hooks file operations", () => {
      const script = fileMonitorScript();
      expect(script).toContain('"open"');
      expect(script).toContain('"read"');
      expect(script).toContain('"write"');
      expect(script).toContain('"close"');
      expect(script).toContain("__started__");
    });
  });

  describe("stalkerTraceScript", () => {
    it("configures event types correctly", () => {
      const script = stalkerTraceScript("123", {
        call: true,
        ret: false,
        exec: true,
        block: false,
        compile: false,
      });
      expect(script).toContain("call: true");
      expect(script).toContain("ret: false");
      expect(script).toContain("exec: true");
      expect(script).toContain("block: false");
      expect(script).toContain("compile: false");
      expect(script).toContain("Stalker.follow");
    });

    it("uses current thread when threadId is empty", () => {
      const script = stalkerTraceScript("", { call: true });
      expect(script).toContain("Process.getCurrentThreadId()");
    });

    it("uses provided threadId", () => {
      const script = stalkerTraceScript("456", { call: true });
      expect(script).toContain("var tid = 456");
    });
  });

  describe("processInfoScript", () => {
    it("gathers process metadata", () => {
      const script = processInfoScript();
      expect(script).toContain("Process.id");
      expect(script).toContain("Process.arch");
      expect(script).toContain("Process.platform");
      expect(script).toContain("Process.pageSize");
      expect(script).toContain("Process.pointerSize");
      expect(script).toContain("Process.mainModule");
      expect(script).toContain("enumerateThreads");
      expect(script).toContain("enumerateModules");
      expect(script).toContain("enumerateRanges");
    });
  });

  describe("enumerateThreadsScript", () => {
    it("enumerates threads with context", () => {
      const script = enumerateThreadsScript();
      expect(script).toContain("enumerateThreads()");
      expect(script).toContain("context");
      expect(script).toContain("ctx.pc");
      expect(script).toContain("ctx.sp");
    });
  });

  describe("enumerateEnvVarsScript", () => {
    it("handles multiple platforms", () => {
      const script = enumerateEnvVarsScript();
      expect(script).toContain("Process.platform");
      expect(script).toContain("windows");
      expect(script).toContain("darwin");
      expect(script).toContain("GetEnvironmentStringsW");
      expect(script).toContain("_NSGetEnviron");
      expect(script).toContain("/proc/self/environ");
    });
  });

  describe("scanFileSignaturesScript", () => {
    it("contains known file signatures", () => {
      const script = scanFileSignaturesScript();
      expect(script).toContain("89 50 4E 47");
      expect(script).toContain("FF D8 FF");
      expect(script).toContain("25 50 44 46");
      expect(script).toContain("50 4B 03 04");
      expect(script).toContain("7F 45 4C 46");
      expect(script).toContain("Memory.scanSync");
    });
  });

  describe("dumpFileFromMemoryScript", () => {
    it("embeds address and max size", () => {
      const script = dumpFileFromMemoryScript("0x5000", 65536);
      expect(script).toContain('"0x5000"');
      expect(script).toContain("65536");
      expect(script).toContain("readByteArray");
    });
  });

  describe("evalScript", () => {
    it("wraps code in IIFE", () => {
      const script = evalScript("return 42");
      expect(script).toContain("return 42");
      expect(script).toContain("(function()");
    });
  });
});
