import { describe, it, expect, beforeEach } from "vitest";
import { useConnectionStore } from "@/stores/connection.ts";

describe("connection store", () => {
  beforeEach(() => {
    useConnectionStore.setState({
      serverUrl: "127.0.0.1:27042",
      tls: "disabled",
      authToken: "",
      connected: false,
      busy: false,
      deviceInfo: null,
      spawnTarget: "",
    });
  });

  describe("setServerUrl", () => {
    it("updates server URL", () => {
      useConnectionStore.getState().setServerUrl("192.168.1.1:27042");
      expect(useConnectionStore.getState().serverUrl).toBe("192.168.1.1:27042");
    });
  });

  describe("setTls", () => {
    it("updates TLS setting", () => {
      useConnectionStore.getState().setTls("enabled");
      expect(useConnectionStore.getState().tls).toBe("enabled");
    });
  });

  describe("setAuthToken", () => {
    it("updates auth token", () => {
      useConnectionStore.getState().setAuthToken("my-secret-token");
      expect(useConnectionStore.getState().authToken).toBe("my-secret-token");
    });
  });

  describe("setSpawnTarget", () => {
    it("updates spawn target", () => {
      useConnectionStore.getState().setSpawnTarget("com.example.app");
      expect(useConnectionStore.getState().spawnTarget).toBe("com.example.app");
    });
  });

  describe("connect guard", () => {
    it("returns null when busy", async () => {
      useConnectionStore.setState({ busy: true });
      const result = await useConnectionStore.getState().connect();
      expect(result).toBeNull();
    });

    it("returns null when host is empty", async () => {
      useConnectionStore.setState({ serverUrl: "  " });
      const result = await useConnectionStore.getState().connect();
      expect(result).toBeNull();
    });
  });

  describe("disconnect", () => {
    it("resets connected state", () => {
      useConnectionStore.setState({ connected: true, deviceInfo: { os: "linux" }, spawnTarget: "test" });
      useConnectionStore.getState().disconnect();
      const state = useConnectionStore.getState();
      expect(state.connected).toBe(false);
      expect(state.deviceInfo).toBeNull();
      expect(state.spawnTarget).toBe("");
    });
  });

  describe("getClient", () => {
    it("returns null when not connected", () => {
      expect(useConnectionStore.getState().getClient()).toBeNull();
    });
  });
});
