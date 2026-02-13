import { create } from "zustand";
import { getItem, setItem } from "@/lib/storage.ts";
import toast from "react-hot-toast";

const STORAGE_KEY = "refrida-bookmarks";

export interface Bookmark {
  id: string;
  label: string;
  address: string;
  type: "hex" | "asm";
  module?: string;
  created: string;
}

interface BookmarksState {
  bookmarks: Bookmark[];
  load: () => void;
  add: (bookmark: Omit<Bookmark, "id" | "created">) => void;
  remove: (id: string) => void;
  rename: (id: string, label: string) => void;
}

function generateId(): string {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

export const useBookmarksStore = create<BookmarksState>((set, get) => ({
  bookmarks: [],

  load: () => {
    set({ bookmarks: getItem<Bookmark[]>(STORAGE_KEY, []) });
  },

  add: (bookmark) => {
    const entry: Bookmark = {
      ...bookmark,
      id: generateId(),
      created: new Date().toISOString(),
    };
    const bookmarks = [...get().bookmarks, entry];
    set({ bookmarks });
    setItem(STORAGE_KEY, bookmarks);
    toast.success(`Bookmarked ${bookmark.label}`, { duration: 1500 });
  },

  remove: (id) => {
    const bookmarks = get().bookmarks.filter((b) => b.id !== id);
    set({ bookmarks });
    setItem(STORAGE_KEY, bookmarks);
    toast.success("Bookmark removed", { duration: 1500 });
  },

  rename: (id, label) => {
    const bookmarks = get().bookmarks.map((b) =>
      b.id === id ? { ...b, label } : b,
    );
    set({ bookmarks });
    setItem(STORAGE_KEY, bookmarks);
  },
}));
