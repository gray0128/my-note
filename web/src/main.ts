import { createLocalApiClient } from "./api";
import { MyNoteApp } from "./app";

const root = document.getElementById("app");
if (root) {
  const app = new MyNoteApp(root, createLocalApiClient());
  void app.start().catch((err) => {
    root.textContent = `Failed to connect to local my-note daemon: ${err instanceof Error ? err.message : String(err)}`;
  });
}
