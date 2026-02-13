<div align="center">

<picture>
  <img src=".github/banner.svg" alt="reFrida" width="800">
</picture>

<br><br>

[![Open reFrida](https://img.shields.io/badge/Open_reFrida-f59e0b?style=for-the-badge)](https://zahidaz.github.io/refrida/)
[![License](https://img.shields.io/github/license/zahidaz/refrida?style=for-the-badge&color=555)](LICENSE.md)
[![GitHub Stars](https://img.shields.io/github/stars/zahidaz/refrida?style=for-the-badge&color=555)](https://github.com/zahidaz/refrida)

</div>

<br>

> Start `frida-server` on any device, open reFrida in your browser, and you have a full instrumentation IDE. No installs. No CLI. Just a URL.

<br>

## How it works

```
1. Run frida-server on your target device
   $ frida-server --listen=0.0.0.0:27042

2. Open reFrida in any browser
   https://zahidaz.github.io/refrida/

3. Enter the server address and hit Connect

4. Pick a process, write a script, hit Run
```

You can also bookmark a pre-filled URL to skip the setup next time:

```
https://zahidaz.github.io/refrida/?host=192.168.1.5:27042&tls=enabled
```

<br>

## What you get

### Script Editor
A Monaco-powered editor with syntax highlighting, multiple tabs, and 12 built-in Frida templates. Write your instrumentation scripts, save them to a local library, or import `.js` files. Switch between QJS, V8, or the default runtime per script.

### Process Browser
See every process and application running on the target. Search by name or PID, sort by any column, auto-refresh the list, kill processes, or spawn new ones by identifier.

### Integrated Console
Output appears the moment your script runs. Filter by log level (info, warning, error, system) or by individual script run. Expand JSON objects inline, click any line to copy, search through output, or export everything as `.txt`, `.json`, or `.csv`.

### IDE Layout
A familiar VS Code-style workspace with an activity bar, resizable side panel, tabbed editor, and bottom console. Resize panels by dragging. Collapse or expand them. Use Ctrl+P to open the command palette for quick access to every action.

### Connection Sharing
Connection settings sync to the URL as you type. Share a link with `?host=`, `?tls=`, and `?token=` parameters and the recipient opens reFrida ready to connect. Great for team setups or device-specific bookmarks.

### Themes
Dark and light mode with a single click. The interface uses a warm amber palette inspired by Frida's own branding.

<br>

## Keyboard shortcuts

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

## Self-host

reFrida is a static site. Clone it, build it, deploy it wherever you want.

```bash
git clone https://github.com/zahidaz/refrida.git
cd refrida
pnpm install
pnpm build
```

The `dist/` folder is your deployable output. Or run `pnpm dev` for local development.

<br>

## URL parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `host` | `127.0.0.1:27042` | frida-server address |
| `tls` | `disabled` | `disabled`, `enabled`, or `auto` |
| `token` | | Authentication token |

<br>

---

<sub><a href="LICENSE.md">MIT License</a> · Made by <a href="https://github.com/zahidaz">@zahidaz</a></sub>
