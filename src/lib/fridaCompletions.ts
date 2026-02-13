import type { languages } from "monaco-editor";

type Suggestion = languages.CompletionItem;
type Kind = languages.CompletionItemKind;

let kinds: Record<string, Kind> | null = null;

function k(): Record<string, Kind> {
  if (kinds) return kinds;
  const m = window.monaco as { languages: { CompletionItemKind: Record<string, Kind> } } | undefined;
  if (!m) return {} as Record<string, Kind>;
  kinds = m.languages.CompletionItemKind;
  return kinds;
}

function fn(label: string, detail: string, insert: string): Partial<Suggestion> {
  return { label, kind: k().Function, detail, insertText: insert, insertTextRules: 4 };
}

function prop(label: string, detail: string): Partial<Suggestion> {
  return { label, kind: k().Property, detail, insertText: label };
}

function cls(label: string, detail: string): Partial<Suggestion> {
  return { label, kind: k().Class, detail, insertText: label };
}

export function getFridaCompletions(): Partial<Suggestion>[] {
  return [
    cls("Process", "Current process"),
    fn("Process.enumerateModules()", "List loaded modules", "Process.enumerateModules()"),
    fn("Process.enumerateThreads()", "List threads", "Process.enumerateThreads()"),
    fn("Process.findModuleByName(name)", "Find module by name", "Process.findModuleByName(${1:name})"),
    fn("Process.findModuleByAddress(addr)", "Find module by address", "Process.findModuleByAddress(${1:addr})"),
    prop("Process.id", "Process ID"),
    prop("Process.arch", "CPU architecture"),
    prop("Process.platform", "Operating system"),
    prop("Process.mainModule", "Main module"),

    cls("Module", "Module operations"),
    fn("Module.findGlobalExportByName(name)", "Find global export address", "Module.findGlobalExportByName(${1:\"name\"})"),
    fn("Module.findBaseAddress(name)", "Find module base", "Module.findBaseAddress(${1:\"name\"})"),

    cls("Memory", "Memory operations"),
    fn("Memory.scan(addr, size, pattern, callbacks)", "Scan memory for pattern", "Memory.scan(${1:addr}, ${2:size}, ${3:\"pattern\"}, {\n  onMatch(address, size) {\n    ${4}\n  },\n  onComplete() {}\n})"),
    fn("Memory.alloc(size)", "Allocate memory", "Memory.alloc(${1:size})"),
    fn("Memory.copy(dst, src, n)", "Copy memory", "Memory.copy(${1:dst}, ${2:src}, ${3:n})"),

    cls("Interceptor", "Function interception"),
    fn("Interceptor.attach(target, callbacks)", "Attach to function", "Interceptor.attach(${1:target}, {\n  onEnter(args) {\n    ${2}\n  },\n  onLeave(retval) {\n    ${3}\n  }\n})"),
    fn("Interceptor.replace(target, replacement)", "Replace function", "Interceptor.replace(${1:target}, ${2:replacement})"),
    fn("Interceptor.detachAll()", "Detach all hooks", "Interceptor.detachAll()"),

    cls("Stalker", "Code tracing"),
    fn("Stalker.follow(threadId, options)", "Start tracing thread", "Stalker.follow(${1:threadId}, {\n  events: { call: true },\n  onCallSummary(summary) {\n    ${2}\n  }\n})"),
    fn("Stalker.unfollow(threadId)", "Stop tracing", "Stalker.unfollow(${1:threadId})"),

    cls("NativeFunction", "Call native functions"),
    fn("new NativeFunction(addr, ret, args)", "Create native function wrapper", "new NativeFunction(${1:addr}, ${2:'void'}, [${3}])"),

    cls("NativeCallback", "Create native callbacks"),
    fn("new NativeCallback(func, ret, args)", "Create callback for native code", "new NativeCallback(${1:func}, ${2:'void'}, [${3}])"),

    fn("send(message)", "Send message to host", "send(${1:message})"),
    fn("recv(callback)", "Receive message from host", "recv(${1:callback})"),
    fn("ptr(s)", "Create NativePointer", "ptr(${1:\"0x0\"})"),
    prop("NULL", "Null pointer"),

    cls("ObjC", "Objective-C runtime (iOS/macOS)"),
    prop("ObjC.available", "Check if ObjC runtime is loaded"),
    prop("ObjC.classes", "All loaded ObjC classes"),
    fn("ObjC.choose(specifier, callbacks)", "Enumerate ObjC objects on heap", "ObjC.choose(${1:ObjC.classes.NSString}, {\n  onMatch(instance) {\n    ${2}\n  },\n  onComplete() {}\n})"),

    cls("Java", "Java/Android runtime"),
    prop("Java.available", "Check if Java VM is loaded"),
    fn("Java.perform(fn)", "Run on Java thread", "Java.perform(() => {\n  ${1}\n})"),
    fn("Java.use(className)", "Get Java class wrapper", "Java.use(${1:\"className\"})"),
    fn("Java.choose(className, callbacks)", "Enumerate Java instances", "Java.choose(${1:\"className\"}, {\n  onMatch(instance) {\n    ${2}\n  },\n  onComplete() {}\n})"),
    fn("Java.enumerateLoadedClasses(callbacks)", "List loaded Java classes", "Java.enumerateLoadedClasses({\n  onMatch(name) {\n    ${1}\n  },\n  onComplete() {}\n})"),

    cls("rpc", "RPC exports"),
    prop("rpc.exports", "Define RPC-callable functions"),
  ];
}

declare global {
  interface Window {
    monaco?: {
      KeyMod: { CtrlCmd: number };
      KeyCode: { Enter: number };
      languages: { CompletionItemKind: Record<string, Kind> };
    };
  }
}
