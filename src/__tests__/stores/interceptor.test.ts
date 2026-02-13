import { describe, it, expect, beforeEach } from "vitest";
import { useInterceptorStore } from "@/stores/interceptor.ts";

describe("interceptor store", () => {
  beforeEach(() => {
    useInterceptorStore.setState({
      target: { type: "export", moduleName: "", exportName: "", address: "" },
      logArgs: true,
      argCount: 3,
      logReturn: true,
      modifyReturn: false,
      returnValue: "",
      customOnEnter: "",
      customOnLeave: "",
      mode: "insert",
      liveActive: false,
      liveError: null,
    });
  });

  describe("generateCode", () => {
    it("generates export target code", () => {
      useInterceptorStore.getState().setTarget({
        type: "export",
        moduleName: "libc.so",
        exportName: "malloc",
      });
      const code = useInterceptorStore.getState().generateCode();
      expect(code).toContain('Module.findExportByName("libc.so", "malloc")');
      expect(code).toContain("Interceptor.attach");
    });

    it("generates address target code", () => {
      useInterceptorStore.getState().setTarget({
        type: "address",
        address: "0x1000",
      });
      const code = useInterceptorStore.getState().generateCode();
      expect(code).toContain('ptr("0x1000")');
    });

    it("generates export without module (null)", () => {
      useInterceptorStore.getState().setTarget({
        type: "export",
        moduleName: "",
        exportName: "open",
      });
      const code = useInterceptorStore.getState().generateCode();
      expect(code).toContain('Module.findExportByName(null, "open")');
    });

    it("includes onEnter with args logging", () => {
      useInterceptorStore.getState().setTarget({
        type: "export",
        exportName: "test",
      });
      useInterceptorStore.getState().setConfig({ logArgs: true, argCount: 2 });
      const code = useInterceptorStore.getState().generateCode();
      expect(code).toContain("onEnter");
      expect(code).toContain("args[0]");
      expect(code).toContain("args[1]");
      expect(code).not.toContain("args[2]");
    });

    it("includes onLeave with return logging", () => {
      useInterceptorStore.getState().setTarget({ type: "export", exportName: "test" });
      useInterceptorStore.getState().setConfig({ logReturn: true });
      const code = useInterceptorStore.getState().generateCode();
      expect(code).toContain("onLeave");
      expect(code).toContain("retval.toString()");
    });

    it("includes return value modification", () => {
      useInterceptorStore.getState().setTarget({ type: "export", exportName: "test" });
      useInterceptorStore.getState().setConfig({
        modifyReturn: true,
        returnValue: "0x1",
      });
      const code = useInterceptorStore.getState().generateCode();
      expect(code).toContain("retval.replace");
      expect(code).toContain("0x1");
    });

    it("includes custom onEnter code", () => {
      useInterceptorStore.getState().setTarget({ type: "export", exportName: "test" });
      useInterceptorStore.getState().setConfig({
        logArgs: false,
        customOnEnter: 'send("custom enter");',
      });
      const code = useInterceptorStore.getState().generateCode();
      expect(code).toContain('send("custom enter")');
    });

    it("includes custom onLeave code", () => {
      useInterceptorStore.getState().setTarget({ type: "export", exportName: "test" });
      useInterceptorStore.getState().setConfig({
        logReturn: false,
        customOnLeave: 'send("custom leave");',
      });
      const code = useInterceptorStore.getState().generateCode();
      expect(code).toContain('send("custom leave")');
    });

    it("escapes special characters in module name", () => {
      useInterceptorStore.getState().setTarget({
        type: "export",
        moduleName: 'lib"test.so',
        exportName: "func",
      });
      const code = useInterceptorStore.getState().generateCode();
      expect(code).toContain('lib\\"test.so');
    });

    it("sends started event", () => {
      useInterceptorStore.getState().setTarget({ type: "export", exportName: "test" });
      const code = useInterceptorStore.getState().generateCode();
      expect(code).toContain("__started__");
    });
  });

  describe("quickHook", () => {
    it("sets target and switches to live mode", () => {
      useInterceptorStore.getState().quickHook("libc.so", "malloc", "0x1000");
      const state = useInterceptorStore.getState();
      expect(state.target.moduleName).toBe("libc.so");
      expect(state.target.exportName).toBe("malloc");
      expect(state.target.address).toBe("0x1000");
      expect(state.mode).toBe("live");
    });
  });

  describe("setTarget", () => {
    it("merges partial target", () => {
      useInterceptorStore.getState().setTarget({ moduleName: "new.so" });
      expect(useInterceptorStore.getState().target.moduleName).toBe("new.so");
      expect(useInterceptorStore.getState().target.type).toBe("export");
    });
  });
});
