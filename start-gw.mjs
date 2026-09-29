const d = await import("./src/daemon.js");
await d.startDaemon(47860, "127.0.0.1");
