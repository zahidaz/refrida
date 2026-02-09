<p align="center">
  <img src="https://frida.re/img/logotype.svg" alt="Frida" width="120">
</p>

<h1 align="center">Frida Web</h1>

<p align="center">
  <strong>A browser-based GUI for <a href="https://frida.re/">Frida</a></strong><br>
  Attach to processes, run scripts, inspect results — no installation required.
</p>

<p align="center">
  <a href="https://zahidaz.github.io/frida-web/"><img src="https://img.shields.io/badge/Open_App-Live-22d3ee?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Live App"></a>
</p>

<p align="center">
  <a href="https://github.com/zahidaz/frida-web/actions"><img src="https://img.shields.io/github/actions/workflow/status/zahidaz/frida-web/pages.yml?label=deploy&style=flat-square" alt="Deploy"></a>
  <a href="https://github.com/zahidaz/frida-web/blob/main/LICENSE.md"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT"></a>
</p>

---

### Quick Start

```bash
frida-server --listen=0.0.0.0:27042
```

Then open **[zahidaz.github.io/frida-web](https://zahidaz.github.io/frida-web/)** and connect.

---

### Features

| | |
|---|---|
| **Processes & Applications** | Browse, filter, sort, auto-refresh, kill |
| **Spawn Mode** | Spawn by identifier, auto-attach, resume |
| **Script Editor** | CodeMirror with 12 built-in templates, tabs, save/load library, drag-drop import |
| **Runtime Selector** | Default / QJS / V8 per script |
| **Console** | Search, level filter, click-to-copy, collapsible JSON, export as .txt/.json/.csv |
| **Device Info** | OS, architecture, device name badges on connect |
| **Resizable Panels** | Drag to resize sidebar, editor, and console |
| **Light / Dark Mode** | Toggle or follows system preference |
| **Keyboard Shortcuts** | `Enter` connect, `Ctrl+Enter` run, `Ctrl+Shift+K` clear console |
| **Zero Install** | Static site, all deps via CDN, works from `file://` |

---

### Self-Host

```bash
git clone https://github.com/zahidaz/frida-web.git
cd frida-web
npx serve app
```

---

### License

[MIT](LICENSE.md)
