<div align="center">

<picture>
  <img src=".github/banner.svg" alt="reFrida" width="800">
</picture>

<br><br>

**A full-featured instrumentation IDE for [Frida](https://frida.re/) that runs entirely in your browser.**

<br>

[![Open reFrida](https://img.shields.io/badge/Open_reFrida-f59e0b?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJ3aGl0ZSI+PHBhdGggZD0iTTEyIDJMMiA3bDEwIDUgMTAtNS0xMC01ek0yIDE3bDEwIDUgMTAtNS0xMC01LTEwIDV6TTIgMTJsMTAgNSAxMC01LTEwLTUtMTAgNXoiLz48L3N2Zz4=&logoColor=white)](https://zahidaz.github.io/refrida/)
[![License](https://img.shields.io/github/license/zahidaz/refrida?style=for-the-badge&color=555)](LICENSE.md)
[![GitHub Stars](https://img.shields.io/github/stars/zahidaz/refrida?style=for-the-badge&color=555)](https://github.com/zahidaz/refrida)

<br>

![React](https://img.shields.io/badge/React_19-61DAFB?style=flat-square&logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white)
![Tailwind](https://img.shields.io/badge/Tailwind_CSS-06B6D4?style=flat-square&logo=tailwindcss&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-646CFF?style=flat-square&logo=vite&logoColor=white)
![Vitest](https://img.shields.io/badge/Tested_with_Vitest-6E9F18?style=flat-square&logo=vitest&logoColor=white)

</div>

<br>

> Start `frida-server` on any device, open reFrida in your browser, and you have a full instrumentation IDE.
> No installs. No CLI. Just a URL.

<br>

## Getting Started

```
1. Run frida-server on your target device
   $ frida-server --listen=0.0.0.0:27042

2. Open reFrida in any browser
   https://zahidaz.github.io/refrida/

3. Enter the server address and hit Connect

4. Pick a process, write a script, hit Run
```

Bookmark a pre-filled URL to skip the setup next time:

```
https://zahidaz.github.io/refrida/?host=192.168.1.5:27042&tls=enabled
```

<br>

## Features

<table>
<tr>
<td width="50%" valign="top">

### Script Editor
<sup><code>JavaScript</code> <code>TypeScript</code> <code>Monaco</code></sup>

A full Monaco-powered code editor with syntax highlighting, IntelliSense, multiple tabs, and built-in Frida script templates. Write scripts in JavaScript or TypeScript (auto-transpiled before injection). Save your scripts to a local library, import/export `.js` files, and switch between QJS, V8, or default runtimes.

</td>
<td width="50%" valign="top">

### Process Browser
<sup><code>Real-time</code> <code>Auto-refresh</code></sup>

See every process and app running on the target device. Filter by name or PID, sort by any column, auto-refresh the list in real time, kill processes, or spawn new ones by identifier. Quick-attach to any process with a single click.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### Module Browser
<sup><code>Exports</code> <code>Imports</code> <code>Symbols</code> <code>Dump</code></sup>

Explore loaded modules in the attached process. Expand any module to inspect its exports, imports, symbols, and memory ranges. Search across modules, filter details, and dump full module binaries to disk.

</td>
<td width="50%" valign="top">

### Hex Viewer
<sup><code>Read</code> <code>Write</code> <code>Search</code> <code>Inspect</code></sup>

Read and inspect raw memory with a classic hex editor view. Navigate to any address, view hex + ASCII side by side, search for hex patterns or ASCII strings, edit bytes in place, and write changes back to memory.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### Disassembler
<sup><code>ARM</code> <code>ARM64</code> <code>x86</code> <code>x86_64</code></sup>

Disassemble native code at any memory address. View instructions with their mnemonics, operands, and raw bytes. Click on an export or symbol to jump directly to its disassembly. Continue disassembling forward seamlessly.

</td>
<td width="50%" valign="top">

### Interceptor Builder
<sup><code>Visual</code> <code>No-code</code> <code>Live preview</code></sup>

Build `Interceptor.attach()` hooks visually. Pick a target by export name or raw address, configure argument logging, return value modification, and add custom `onEnter`/`onLeave` code. Preview the generated script and inject it live.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### Stalker Trace
<sup><code>Call</code> <code>Ret</code> <code>Exec</code> <code>Block</code></sup>

Trace thread execution with Frida's Stalker engine. Select a thread, choose event types, and watch the trace stream in real time. Filter events by module or search by address and symbol.

</td>
<td width="50%" valign="top">

### Network & File Monitors
<sup><code>Live</code> <code>Network</code> <code>File I/O</code></sup>

Monitor network activity (connect, send, recv, close) and file operations (open, read, write, close) in real time. Each event shows fd, addresses, ports, data previews, and timestamps.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### Memory Search
<sup><code>String</code> <code>Hex</code> <code>API</code></sup>

Search process memory for strings, hex byte patterns, or resolve API symbols. Results show matched addresses with module context. Click any result to jump to the hex viewer or disassembler.

</td>
<td width="50%" valign="top">

### File Scanner
<sup><code>18+ formats</code> <code>Magic bytes</code> <code>Dump</code></sup>

Scan process memory for embedded files by detecting magic byte signatures. Identifies PNG, JPEG, PDF, ZIP, ELF, Mach-O, PE, SQLite, DEX, certificates, and more. Dump any detected file directly from memory.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### Process Info
<sup><code>Threads</code> <code>Env vars</code> <code>Details</code></sup>

View detailed process information: architecture, platform, main module, thread count, mapped memory. Browse all threads with their state and registers. View environment variables with search filtering.

</td>
<td width="50%" valign="top">

### REPL
<sup><code>Interactive</code> <code>History</code></sup>

An interactive JavaScript console for quick one-off evaluations in the attached process. Supports command history with up/down arrow navigation.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### Console
<sup><code>Filter</code> <code>JSON tree</code> <code>Export</code></sup>

Rich output console with log level filtering, per-run isolation, inline JSON expansion with a collapsible tree viewer, click-to-copy, full-text search, and export to `.txt`, `.json`, or `.csv`.

</td>
<td width="50%" valign="top">

### Snippet Library
<sup><code>Community</code> <code>One-click load</code></sup>

Browse and load community Frida snippets from [frida-snippets](https://github.com/iddoeldor/frida-snippets) directly within the IDE. Search, preview, and inject any snippet with one click.

</td>
</tr>
</table>

<br>

**Plus:** Crash Reporter with automatic capture and history | Bookmarks for quick address navigation | Connection sharing via URL parameters | Server connection history | Dark & light themes | Mobile-friendly responsive layout | Command palette (`Ctrl+P`) | Full menu bar

<br>

## Keyboard Shortcuts

| Action | Shortcut |
|--------|----------|
| Run script | `Ctrl + Enter` |
| Open file | `Ctrl + O` |
| Save to library | `Ctrl + S` |
| New tab | `Ctrl + T` |
| Close tab | `Ctrl + W` |
| Command palette | `Ctrl + P` |
| Toggle side panel | `Ctrl + B` |
| Toggle console | `` Ctrl + ` `` |
| Clear console | `Ctrl + Shift + K` |

<br>

## URL Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `host` | `127.0.0.1:27042` | frida-server address |
| `tls` | `disabled` | `disabled`, `enabled`, or `auto` |
| `token` | | Authentication token |

<br>

## Platform Support

reFrida works with frida-server on any platform Frida supports:

![Android](https://img.shields.io/badge/Android-3DDC84?style=flat-square&logo=android&logoColor=white)
![iOS](https://img.shields.io/badge/iOS-000000?style=flat-square&logo=apple&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat-square&logo=linux&logoColor=black)
![macOS](https://img.shields.io/badge/macOS-000000?style=flat-square&logo=apple&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D4?style=flat-square&logo=windows&logoColor=white)

<br>

## Self-Host

reFrida is a static site. Clone it, build it, deploy it wherever you want.

```bash
git clone https://github.com/zahidaz/refrida.git
cd refrida
pnpm install
pnpm build
```

The `dist/` folder is your deployable output. Serve it with any static file server, or run `pnpm dev` for local development.

<br>

---

<div align="center">

<sub><a href="LICENSE.md">MIT License</a> · Made by <a href="https://github.com/zahidaz">@zahidaz</a></sub>

</div>
