import Modal from "@/components/ui/Modal.tsx";
import { useLayoutStore } from "@/stores/layout.ts";

const VERSION = "1.0.0";

const links = [
  {
    icon: "fa-brands fa-github",
    label: "GitHub Repository",
    url: "https://github.com/zahidaz/refrida",
  },
  {
    icon: "fa-solid fa-bug",
    label: "Report an Issue",
    url: "https://github.com/zahidaz/refrida/issues",
  },
  {
    icon: "fa-solid fa-book",
    label: "Frida Documentation",
    url: "https://frida.re/docs/home/",
  },
  {
    icon: "fa-solid fa-user",
    label: "Author — @zahidaz",
    url: "https://github.com/zahidaz",
  },
];

export default function AboutDialog() {
  const setAboutOpen = useLayoutStore((s) => s.setAboutOpen);

  return (
    <Modal onClose={() => setAboutOpen(false)}>
      <div
        className="rounded-lg border p-6 w-[360px] flex flex-col items-center gap-4"
        style={{
          background: "var(--bg-primary)",
          borderColor: "var(--border)",
        }}
      >
        <div className="flex flex-col items-center gap-1">
          <span
            className="text-2xl font-bold tracking-tight"
            style={{ color: "var(--accent)" }}
          >
            reFrida
          </span>
          <span
            className="text-xs"
            style={{ color: "var(--text-muted)" }}
          >
            v{VERSION}
          </span>
        </div>

        <p
          className="text-xs text-center leading-relaxed"
          style={{ color: "var(--text-secondary)" }}
        >
          Browser-based IDE for{" "}
          <a
            href="https://frida.re"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: "var(--accent)" }}
          >
            frida-server
          </a>
          . Connect to a Frida instance over WebSocket, attach to processes,
          and run instrumentation scripts — all from your browser.
        </p>

        <div className="w-full flex flex-col gap-1">
          {links.map((link) => (
            <a
              key={link.url}
              href={link.url}
              target="_blank"
              rel="noopener noreferrer"
              className="hover-row flex items-center gap-2.5 px-3 py-1.5 rounded text-xs"
              style={{ color: "var(--text-secondary)" }}
            >
              <i
                className={`${link.icon} w-4 text-center`}
                style={{ color: "var(--text-muted)" }}
              />
              {link.label}
            </a>
          ))}
        </div>

        <div
          className="text-[10px] pt-1"
          style={{ color: "var(--text-muted)" }}
        >
          MIT License &middot; &copy; {new Date().getFullYear()} reFrida contributors
        </div>
      </div>
    </Modal>
  );
}
