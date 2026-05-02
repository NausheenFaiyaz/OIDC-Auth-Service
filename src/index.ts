import { createServer } from "node:http"
import 'dotenv/config';
import createApplication from "./app/app.js";
import { ensureDatabaseSchema } from "./db/config.js";

const startServer = async () => {
    await ensureDatabaseSchema();
    const server = createServer(createApplication())
    const PORT = process?.env?.PORT;
    server.listen(PORT, () => {
        console.log("Server is running at PORT", PORT)
    })
}

startServer().catch((error) => {
    console.error("Failed to start server", error);
    process.exit(1);
});
