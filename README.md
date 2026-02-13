<h1 align="center">reFrida</h1>

<p align="center">
  A browser-based IDE for <a href="https://frida.re/">frida-server</a>.<br>
  Attach to processes. Run instrumentation scripts. See results instantly.
</p>

<p align="center">
  <a href="https://zahidaz.github.io/refrida/"><img src="https://img.shields.io/badge/Open_App-f59e0b?style=for-the-badge" alt="Open App"></a>
  &nbsp;
  <a href="https://github.com/zahidaz/refrida"><img src="https://img.shields.io/github/license/zahidaz/refrida?style=for-the-badge&color=555" alt="License"></a>
</p>

---

Point your frida-server at a network interface and open reFrida in a browser — that's it. No local tools, no CLI, no setup beyond a running Frida instance.

```bash
frida-server --listen=0.0.0.0:27042
```

Then visit **[zahidaz.github.io/refrida](https://zahidaz.github.io/refrida/)** or self-host your own.

---

### What it does

- Full IDE layout — activity bar, resizable panels, tabbed editor, integrated console
- Monaco-powered script editor with 12 built-in Frida templates
- Process and application browser with search, sort, auto-refresh, and kill
- Spawn mode with resume support
- Per-run console output — filter logs by script execution, search, export
- Runtime selector — Default, QJS, or V8 per script
- URL parameters — bookmark `?host=192.168.1.5:27042&tls=enabled` for instant connect
- Command palette (Ctrl+P) for keyboard-driven workflows
- Dark and light themes

---

### URL parameters

Pre-fill connection settings for quick access or bookmarks:

| Parameter | Default | Example |
|-----------|---------|---------|
| `host` | `127.0.0.1:27042` | `?host=10.0.0.2:27042` |
| `tls` | `disabled` | `?tls=enabled` |
| `token` | — | `?token=mytoken` |

---

### Self-host

```bash
git clone https://github.com/zahidaz/refrida.git
cd refrida
pnpm install
pnpm dev
```

Production build:

```bash
pnpm build     # outputs to dist/
pnpm preview   # preview locally
```

The output is a static site — deploy it anywhere.

---

### Built with

[React](https://react.dev/) ·
[TypeScript](https://www.typescriptlang.org/) ·
[Vite](https://vite.dev/) ·
[Tailwind CSS](https://tailwindcss.com/) ·
[Monaco Editor](https://microsoft.github.io/monaco-editor/) ·
[Zustand](https://zustand.docs.pmnd.rs/) ·
[frida-web-client-browserify](https://github.com/zahidaz/frida-web-client-browserify)

---

<sub>[MIT License](LICENSE.md) · Made by <a href="https://github.com/zahidaz">@zahidaz</a></sub>
