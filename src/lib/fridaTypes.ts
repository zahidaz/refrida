export const FRIDA_TYPE_DEFS = `
declare function send(message: any, data?: ArrayBuffer | number[] | null): void;
declare function recv(type: string, callback: (message: any, data: ArrayBuffer | null) => void): void;
declare function ptr(s: string | number): NativePointer;
declare function int64(v: string | number): Int64;
declare function uint64(v: string | number): UInt64;
declare const NULL: NativePointer;

interface Int64 {
  add(rhs: number | Int64): Int64;
  sub(rhs: number | Int64): Int64;
  and(rhs: number | Int64): Int64;
  or(rhs: number | Int64): Int64;
  xor(rhs: number | Int64): Int64;
  shr(n: number): Int64;
  shl(n: number): Int64;
  not(): Int64;
  compare(rhs: number | Int64): number;
  toNumber(): number;
  toString(radix?: number): string;
}

interface UInt64 {
  add(rhs: number | UInt64): UInt64;
  sub(rhs: number | UInt64): UInt64;
  and(rhs: number | UInt64): UInt64;
  or(rhs: number | UInt64): UInt64;
  xor(rhs: number | UInt64): UInt64;
  shr(n: number): UInt64;
  shl(n: number): UInt64;
  not(): UInt64;
  compare(rhs: number | UInt64): number;
  toNumber(): number;
  toString(radix?: number): string;
}

interface NativePointer {
  add(v: number | NativePointer): NativePointer;
  sub(v: number | NativePointer): NativePointer;
  and(v: number | NativePointer): NativePointer;
  or(v: number | NativePointer): NativePointer;
  xor(v: number | NativePointer): NativePointer;
  shr(n: number): NativePointer;
  shl(n: number): NativePointer;
  not(): NativePointer;
  compare(v: number | NativePointer): number;
  isNull(): boolean;
  equals(v: NativePointer): boolean;
  toInt32(): number;
  toUInt32(): number;
  toString(radix?: number): string;
  toMatchPattern(): string;
  readPointer(): NativePointer;
  writePointer(v: NativePointer): NativePointer;
  readS8(): number;
  readU8(): number;
  readS16(): number;
  readU16(): number;
  readS32(): number;
  readU32(): number;
  readS64(): Int64;
  readU64(): UInt64;
  readFloat(): number;
  readDouble(): number;
  writeS8(v: number): NativePointer;
  writeU8(v: number): NativePointer;
  writeS16(v: number): NativePointer;
  writeU16(v: number): NativePointer;
  writeS32(v: number): NativePointer;
  writeU32(v: number): NativePointer;
  writeS64(v: Int64 | number): NativePointer;
  writeU64(v: UInt64 | number): NativePointer;
  writeFloat(v: number): NativePointer;
  writeDouble(v: number): NativePointer;
  readByteArray(length: number): ArrayBuffer | null;
  writeByteArray(bytes: ArrayBuffer | number[]): NativePointer;
  readCString(size?: number): string | null;
  readUtf8String(size?: number): string | null;
  readUtf16String(size?: number): string | null;
  readAnsiString(size?: number): string | null;
  writeUtf8String(str: string): NativePointer;
  writeUtf16String(str: string): NativePointer;
  writeAnsiString(str: string): NativePointer;
}

interface InvocationContext {
  returnAddress: NativePointer;
  context: CpuContext;
  threadId: number;
  depth: number;
}

interface InvocationArgs {
  [index: number]: NativePointer;
}

interface InvocationReturnValue extends NativePointer {
  replace(v: NativePointer | number): void;
}

interface CpuContext {
  [reg: string]: NativePointer;
}

declare namespace Process {
  const id: number;
  const arch: string;
  const platform: string;
  const pageSize: number;
  const pointerSize: number;
  const codeSigningPolicy: string;
  const mainModule: ModuleInfo;
  function getCurrentThreadId(): number;
  function enumerateThreads(): ThreadInfo[];
  function findModuleByName(name: string): ModuleInfo | null;
  function findModuleByAddress(address: NativePointer): ModuleInfo | null;
  function getModuleByName(name: string): ModuleInfo;
  function getModuleByAddress(address: NativePointer): ModuleInfo;
  function enumerateModules(): ModuleInfo[];
  function findRangeByAddress(address: NativePointer): RangeDetails | null;
  function enumerateRanges(protection: string): RangeDetails[];
  function enumerateMallocRanges(): RangeDetails[];
  function setExceptionHandler(callback: (details: any) => boolean): void;
}

interface ThreadInfo {
  id: number;
  state: string;
  context: CpuContext;
}

interface ModuleInfo {
  name: string;
  base: NativePointer;
  size: number;
  path: string;
  enumerateImports(): ModuleImportDetails[];
  enumerateExports(): ModuleExportDetails[];
  enumerateSymbols(): ModuleSymbolDetails[];
  enumerateRanges(protection: string): RangeDetails[];
  findExportByName(name: string): NativePointer | null;
  getExportByName(name: string): NativePointer;
}

interface ModuleExportDetails {
  type: string;
  name: string;
  address: NativePointer;
}

interface ModuleImportDetails {
  type: string;
  name: string;
  module: string;
  address: NativePointer;
}

interface ModuleSymbolDetails {
  isGlobal: boolean;
  type: string;
  section?: { id: string; protection: string };
  name: string;
  address: NativePointer;
  size?: number;
}

interface RangeDetails {
  base: NativePointer;
  size: number;
  protection: string;
  file?: { path: string; offset: number; size: number };
}

declare namespace Module {
  function load(name: string): ModuleInfo;
  function findBaseAddress(name: string): NativePointer | null;
  function getBaseAddress(name: string): NativePointer;
  function findExportByName(moduleName: string | null, exportName: string): NativePointer | null;
  function getExportByName(moduleName: string | null, exportName: string): NativePointer;
}

declare namespace Memory {
  function scan(address: NativePointer, size: number, pattern: string, callbacks: MemoryScanCallbacks): void;
  function scanSync(address: NativePointer, size: number, pattern: string): MemoryScanMatch[];
  function alloc(size: number): NativePointer;
  function copy(dst: NativePointer, src: NativePointer, n: number): void;
  function dup(address: NativePointer, size: number): NativePointer;
  function protect(address: NativePointer, size: number, protection: string): boolean;
  function patchCode(address: NativePointer, size: number, apply: (code: NativePointer) => void): void;
}

interface MemoryScanCallbacks {
  onMatch: (address: NativePointer, size: number) => string | void;
  onError?: (reason: string) => void;
  onComplete: () => void;
}

interface MemoryScanMatch {
  address: NativePointer;
  size: number;
}

declare namespace Interceptor {
  function attach(target: NativePointer, callbacksOrProbe: InvocationCallbacks | ((args: InvocationArgs) => void)): InvocationListener;
  function detachAll(): void;
  function replace(target: NativePointer, replacement: NativePointer, data?: NativePointer): void;
  function revert(target: NativePointer): void;
  function flush(): void;
}

interface InvocationCallbacks {
  onEnter?: (this: InvocationContext, args: InvocationArgs) => void;
  onLeave?: (this: InvocationContext, retval: InvocationReturnValue) => void;
}

interface InvocationListener {
  detach(): void;
}

declare namespace Stalker {
  function follow(threadId?: number, options?: StalkerOptions): void;
  function unfollow(threadId?: number): void;
  function invalidate(address: NativePointer): void;
  function addCallProbe(address: NativePointer, callback: (args: InvocationArgs) => void): number;
  function removeCallProbe(id: number): void;
  function parse(events: ArrayBuffer, options?: { stringify?: boolean; annotate?: boolean }): any[];
  function flush(): void;
  function garbageCollect(): void;
  const trustThreshold: number;
  const queueCapacity: number;
  const queueDrainInterval: number;
}

interface StalkerOptions {
  events?: {
    call?: boolean;
    ret?: boolean;
    exec?: boolean;
    block?: boolean;
    compile?: boolean;
  };
  onReceive?: (events: ArrayBuffer) => void;
  onCallSummary?: (summary: Record<string, number>) => void;
  transform?: (iterator: any) => void;
}

declare class NativeFunction {
  constructor(address: NativePointer, retType: string, argTypes: string[], abi?: string);
  apply(thisArg: NativePointer | null, args: (NativePointer | number)[]): NativePointer;
  call(thisArg: NativePointer | null, ...args: (NativePointer | number)[]): NativePointer;
}

declare class NativeCallback {
  constructor(func: (...args: any[]) => any, retType: string, argTypes: string[], abi?: string);
}

declare class ApiResolver {
  constructor(type: string);
  enumerateMatches(query: string): ApiResolverMatch[];
}

interface ApiResolverMatch {
  name: string;
  address: NativePointer;
}

declare namespace DebugSymbol {
  function fromAddress(address: NativePointer): DebugSymbolDetails;
  function fromName(name: string): DebugSymbolDetails;
  function getFunctionByName(name: string): NativePointer;
  function findFunctionsNamed(name: string): NativePointer[];
  function findFunctionsMatching(glob: string): NativePointer[];
  function load(path: string): void;
}

interface DebugSymbolDetails {
  address: NativePointer;
  name: string | null;
  moduleName: string | null;
  fileName: string | null;
  lineNumber: number | null;
  column: number | null;
  toString(): string;
}

declare namespace ObjC {
  const available: boolean;
  const api: any;
  const classes: Record<string, ObjCObject>;
  const protocols: Record<string, any>;
  const mainQueue: NativePointer;
  function choose(specifier: any, callbacks: { onMatch: (instance: ObjCObject) => string | void; onComplete: () => void }): void;
  function registerProxy(properties: any): any;
  function registerClass(properties: any): any;
  function registerProtocol(properties: any): any;
  function bind(obj: any, data: any): any;
  function unbind(obj: any): void;
  function getBoundData(obj: any): any;
  function implement(method: any, fn: Function): any;
  function selector(name: string): NativePointer;
  function selectorAsString(sel: NativePointer): string;
}

interface ObjCObject {
  handle: NativePointer;
  $className: string;
  $moduleName: string;
  $protocols: Record<string, any>;
  $ownMethods: string[];
  $methods: string[];
  $super: ObjCObject;
  $class: ObjCObject;
  class(): ObjCObject;
  toString(): string;
  toJSON(): string;
  equals(other: ObjCObject): boolean;
  [method: string]: any;
}

declare namespace Java {
  const available: boolean;
  const androidVersion: string;
  function perform(fn: () => void): void;
  function performNow(fn: () => void): void;
  function use(className: string): JavaWrapper;
  function choose(className: string, callbacks: { onMatch: (instance: JavaWrapper) => string | void; onComplete: () => void }): void;
  function cast(handle: any, klass: JavaWrapper): JavaWrapper;
  function enumerateLoadedClasses(callbacks: { onMatch: (name: string) => string | void; onComplete: () => void }): void;
  function enumerateLoadedClassesSync(): string[];
  function enumerateClassLoaders(callbacks: { onMatch: (loader: any) => string | void; onComplete: () => void }): void;
  function enumerateClassLoadersSync(): any[];
  function openClassFile(filePath: string): any;
  function registerClass(spec: any): JavaWrapper;
  function deoptimizeEverything(): void;
  function retain(obj: JavaWrapper): JavaWrapper;
  const classFactory: any;
}

interface JavaWrapper {
  $className: string;
  $dispose(): void;
  class: {
    getName(): string;
    getDeclaredMethods(): any[];
    getDeclaredFields(): any[];
  };
  [method: string]: any;
}

declare class CModule {
  constructor(source: string, symbols?: Record<string, NativePointer>);
  dispose(): void;
  [symbol: string]: NativePointer;
}

declare namespace Thread {
  function backtrace(context?: CpuContext, backtracer?: any): NativePointer[];
  function sleep(delay: number): void;
}

declare const Backtracer: {
  ACCURATE: any;
  FUZZY: any;
};

declare function hexdump(target: NativePointer | ArrayBuffer, options?: { offset?: number; length?: number; header?: boolean; ansi?: boolean }): string;
declare function setTimeout(func: () => void, delay: number): any;
declare function setInterval(func: () => void, interval: number): any;
declare function clearTimeout(id: any): void;
declare function clearInterval(id: any): void;
declare function gc(): void;
`;
