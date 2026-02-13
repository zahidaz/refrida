import { useConnectionStore } from "@/stores/connection.ts";
import { useProcessesStore } from "@/stores/processes.ts";
import { useLayoutStore } from "@/stores/layout.ts";
import Modal from "@/components/ui/Modal.tsx";

export default function ConnectionDialog() {
  const {
    serverUrl,
    setServerUrl,
    tls,
    setTls,
    authToken,
    setAuthToken,
    connected,
    busy,
    connect,
    disconnect,
  } = useConnectionStore();
  const setProcesses = useProcessesStore((s) => s.setProcesses);
  const refreshApplications = useProcessesStore((s) => s.refreshApplications);
  const { setConnectionDialogOpen, setProcessPickerOpen } = useLayoutStore();

  function close() {
    setConnectionDialogOpen(false);
  }

  async function handleConnect() {
    const processes = await connect();
    if (processes) {
      setProcesses(processes);
      refreshApplications();
      close();
      setProcessPickerOpen(true);
    }
  }

  function handleDisconnect() {
    disconnect();
    close();
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter" && !connected && !busy) {
      handleConnect();
    }
  }

  return (
    <Modal
      onClose={close}
      className="rounded-lg border p-5 w-full max-w-96"
      style={{
        background: "var(--bg-primary)",
        borderColor: "var(--border)",
      }}
    >
      <div className="flex items-center justify-between mb-4">
        <span
          className="text-sm font-semibold"
          style={{ color: "var(--text-primary)" }}
        >
          {connected ? "Connection" : "Connect to Server"}
        </span>
        <button
          onClick={close}
          className="text-sm px-1"
          style={{ color: "var(--text-muted)" }}
        >
          <i className="fa-solid fa-xmark" />
        </button>
      </div>

      <div className="flex flex-col gap-3">
        <div>
          <label
            className="block text-xs mb-1"
            style={{ color: "var(--text-secondary)" }}
          >
            Server Address
          </label>
          <input
            type="text"
            value={serverUrl}
            onChange={(e) => setServerUrl(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="host:port"
            disabled={connected}
            className="text-xs px-2.5 py-1.5 rounded border outline-none w-full"
            style={{
              background: "var(--bg-input)",
              borderColor: "var(--border)",
              color: "var(--text-primary)",
            }}
            autoFocus
          />
        </div>

        <div className="flex gap-2">
          <div className="flex-1">
            <label
              className="block text-xs mb-1"
              style={{ color: "var(--text-secondary)" }}
            >
              TLS
            </label>
            <select
              value={tls}
              onChange={(e) => setTls(e.target.value)}
              disabled={connected}
              className="text-xs px-2 py-1.5 rounded border outline-none w-full"
              style={{
                background: "var(--bg-input)",
                borderColor: "var(--border)",
                color: "var(--text-primary)",
              }}
            >
              <option value="disabled">Off</option>
              <option value="enabled">On</option>
              <option value="auto">Auto</option>
            </select>
          </div>
          <div className="flex-1">
            <label
              className="block text-xs mb-1"
              style={{ color: "var(--text-secondary)" }}
            >
              Auth Token
            </label>
            <input
              type="password"
              value={authToken}
              onChange={(e) => setAuthToken(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Optional"
              disabled={connected}
              className="text-xs px-2.5 py-1.5 rounded border outline-none w-full"
              style={{
                background: "var(--bg-input)",
                borderColor: "var(--border)",
                color: "var(--text-primary)",
              }}
            />
          </div>
        </div>

        {!connected ? (
          <button
            onClick={handleConnect}
            disabled={busy}
            className={`text-xs px-3 py-2 rounded font-medium text-white w-full ${busy ? "loading" : ""}`}
            style={{ background: "var(--accent)" }}
          >
            Connect
          </button>
        ) : (
          <button
            onClick={handleDisconnect}
            className="text-xs px-3 py-2 rounded font-medium text-white bg-red-600 hover:bg-red-700 w-full"
          >
            Disconnect
          </button>
        )}
      </div>
    </Modal>
  );
}
