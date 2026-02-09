import { useConnectionStore } from "@/stores/connection.ts";
import { useSessionStore } from "@/stores/session.ts";

export default function SpawnBar() {
  const { spawnTarget, setSpawnTarget, spawnProcess, resumeProcess } =
    useConnectionStore();
  const { attachToProcess, attachedPid } = useSessionStore();

  async function handleSpawn() {
    const pid = await spawnProcess();
    if (pid !== null) {
      await attachToProcess(pid, spawnTarget.trim());
    }
  }

  return (
    <div
      className="flex items-center gap-1 px-2 py-1.5 border-t"
      style={{ borderColor: "var(--border)" }}
    >
      <input
        type="text"
        value={spawnTarget}
        onChange={(e) => setSpawnTarget(e.target.value)}
        placeholder="Spawn identifier..."
        className="text-xs px-2 py-1 rounded border outline-none flex-1"
        style={{
          background: "var(--bg-input)",
          borderColor: "var(--border)",
          color: "var(--text-primary)",
        }}
        onKeyDown={(e) => e.key === "Enter" && handleSpawn()}
      />
      <button
        onClick={handleSpawn}
        disabled={!spawnTarget.trim()}
        className="text-xs px-2 py-1 rounded font-medium text-white bg-cyan-600 hover:bg-cyan-700 disabled:opacity-40"
      >
        Spawn
      </button>
      {attachedPid && (
        <button
          onClick={() => resumeProcess(attachedPid)}
          className="text-xs px-2 py-1 rounded font-medium text-white bg-green-600 hover:bg-green-700"
        >
          Resume
        </button>
      )}
    </div>
  );
}
