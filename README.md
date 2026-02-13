<h1 align="center">reFrida</h1>

<p align="center">
  <strong>Browser-based IDE for <a href="https://frida.re/">Frida</a></strong><br>
  Attach to processes, run scripts, inspect results — no installation required.
</p>

<p align="center">
  <a href="https://zahidaz.github.io/refrida/"><img src="https://img.shields.io/badge/Open_App-Live-22d3ee?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Live App"></a>
</p>

---

### Quick Start

```bash
frida-server --listen=0.0.0.0:27042
```

Then open **[zahidaz.github.io/refrida](https://zahidaz.github.io/refrida/)** and connect.

---

### Features

| | |
|---|---|
| **IDE Layout** | VS Code-style activity bar, resizable side panel, bottom console, status bar |
| **Command Palette** | Ctrl+P quick access to all actions |
| **Processes & Applications** | Browse, filter, sort, auto-refresh, kill |
| **Spawn Mode** | Spawn by identifier, auto-attach, resume |
| **Script Editor** | Monaco editor with 12 built-in templates, tabs, save/load library |
| **Runtime Selector** | Default / QJS / V8 per script |
| **Console** | Search, level filter, click-to-copy, collapsible JSON, export as .txt/.json/.csv |
| **Device Info** | OS, architecture, device name badges on connect |
| **Light / Dark Mode** | Toggle or follows system preference |
| **Zero Install** | Static site, works from any web server |

---

### Self-Host

```bash
git clone https://github.com/zahidaz/refrida.git
cd refrida
pnpm install
pnpm dev
```

---

### License

[MIT](LICENSE.md)
