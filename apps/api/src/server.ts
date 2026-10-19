import { app } from "./app.js";
import { config } from "./config.js";
import { pool } from "./db/pool.js";
import { startRotationWorker } from "./key-lifecycle.js";
const stopRotation = startRotationWorker();
const server = app.listen(config.PORT, () =>
  console.log(`WorkSphere API listening on ${config.PORT}`),
);
process.on("SIGTERM", () =>
  server.close(() => {
    stopRotation();
    void pool.end();
  }),
);
