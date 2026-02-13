import { create } from "zustand";
import { runUtilityScript } from "@/lib/utilityRunner.ts";
import { disassembleScript } from "@/lib/utilityScripts.ts";

export interface Instruction {
  address: string;
  mnemonic: string;
  opStr: string;
  size: number;
  bytes: number[];
}

export interface AsmTabState {
  address: string;
  count: number;
  instructions: Instruction[];
  currentAddress: string;
  selectedIndex: number | null;
  loading: boolean;
  error: string | null;
}

const DEFAULT_ASM_STATE: AsmTabState = {
  address: "",
  count: 100,
  instructions: [],
  currentAddress: "",
  selectedIndex: null,
  loading: false,
  error: null,
};

interface DisasmState {
  tabStates: Record<string, AsmTabState>;
  getTabState: (tabId: string) => AsmTabState;
  setAddress: (tabId: string, address: string) => void;
  setCount: (tabId: string, count: number) => void;
  setSelectedIndex: (tabId: string, index: number | null) => void;
  disassemble: (tabId: string) => Promise<void>;
  disassembleAt: (tabId: string, addr: string) => Promise<void>;
  continueForward: (tabId: string) => Promise<void>;
  removeTab: (tabId: string) => void;
  reset: () => void;
}

function updateTab(set: (fn: (s: DisasmState) => Partial<DisasmState>) => void, tabId: string, patch: Partial<AsmTabState>) {
  set((s) => ({
    tabStates: {
      ...s.tabStates,
      [tabId]: { ...(s.tabStates[tabId] ?? DEFAULT_ASM_STATE), ...patch },
    },
  }));
}

export const useDisasmStore = create<DisasmState>((set, get) => ({
  tabStates: {},

  getTabState: (tabId) => get().tabStates[tabId] ?? DEFAULT_ASM_STATE,

  setAddress: (tabId, address) => updateTab(set, tabId, { address }),
  setCount: (tabId, count) => updateTab(set, tabId, { count }),
  setSelectedIndex: (tabId, selectedIndex) => updateTab(set, tabId, { selectedIndex }),

  disassemble: (tabId) => {
    const ts = get().getTabState(tabId);
    return get().disassembleAt(tabId, ts.address);
  },

  disassembleAt: async (tabId, addr) => {
    const trimmed = addr.trim();
    if (!trimmed) return;
    const ts = get().getTabState(tabId);
    updateTab(set, tabId, { loading: true, error: null });
    const result = await runUtilityScript<Instruction>(
      disassembleScript(trimmed, ts.count),
      `disasm:${trimmed}`,
    );
    if (result.error) {
      updateTab(set, tabId, { loading: false, error: result.error, instructions: [] });
    } else {
      updateTab(set, tabId, {
        loading: false,
        instructions: result.data,
        currentAddress: trimmed,
        address: trimmed,
        selectedIndex: null,
      });
    }
  },

  continueForward: async (tabId) => {
    const ts = get().getTabState(tabId);
    if (ts.instructions.length === 0) return;
    const last = ts.instructions[ts.instructions.length - 1];
    const nextAddr = "0x" + (BigInt(last.address) + BigInt(last.size)).toString(16);
    updateTab(set, tabId, { loading: true, error: null });
    const result = await runUtilityScript<Instruction>(
      disassembleScript(nextAddr, ts.count),
      `disasm:${nextAddr}`,
    );
    if (result.error) {
      updateTab(set, tabId, { loading: false, error: result.error });
    } else {
      updateTab(set, tabId, {
        loading: false,
        instructions: [...ts.instructions, ...result.data],
      });
    }
  },

  removeTab: (tabId) => {
    set((s) => {
      const { [tabId]: _, ...rest } = s.tabStates;
      return { tabStates: rest };
    });
  },

  reset: () => set({ tabStates: {} }),
}));
