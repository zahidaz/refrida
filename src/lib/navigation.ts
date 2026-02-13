import { useScriptsStore } from "@/stores/scripts.ts";

export function navigateToMemory(address: string) {
  const store = useScriptsStore.getState();
  const active = store.getActiveTab();
  const getCurrentContent = () => active?.content ?? "";
  store.openHexTab(address, getCurrentContent);
}
