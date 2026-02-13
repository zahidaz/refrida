<h1 align="center">reFrida</h1>

<p align="center">
  Frida, in your browser.
</p>

<p align="center">
  <a href="https://zahidaz.github.io/refrida/"><img src="https://img.shields.io/badge/Open_reFrida-f59e0b?style=for-the-badge" alt="Open reFrida"></a>
</p>

---

reFrida is a browser-based IDE for [Frida](https://frida.re/). It connects to a running frida-server over the network and gives you everything you need to instrument processes — a script editor, a process browser, an integrated console — all without installing anything locally.

Open it. Connect. Start hacking.

---

### At a glance

**Write scripts** in a full-featured editor with syntax highlighting, tabs, and 12 built-in Frida templates to get you started fast.

**Browse processes** running on the target device — search, filter, sort, kill, or spawn new ones.

**See output immediately** in a console that filters by script run, supports JSON expansion, click-to-copy, search, and export.

**Share connections** by bookmarking a URL like `?host=192.168.1.5:27042` — opens reFrida pre-configured and ready to connect.

**Work your way** with a VS Code-style layout, command palette, keyboard shortcuts, resizable panels, and dark/light themes.

---

### Getting started

Start frida-server on your target:

```
frida-server --listen=0.0.0.0:27042
```

Then open **[zahidaz.github.io/refrida](https://zahidaz.github.io/refrida/)**, enter the address, and connect.

---

### Run your own instance

```
git clone https://github.com/zahidaz/refrida.git
cd refrida
pnpm install
pnpm dev
```

`pnpm build` produces a static site you can deploy anywhere.

---

<sub>[MIT License](LICENSE.md) · <a href="https://github.com/zahidaz">@zahidaz</a></sub>
