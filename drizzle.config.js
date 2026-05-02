import dotenv from 'dotenv';
import { defineConfig } from 'drizzle-kit';
dotenv.config({ path: '.env', override: true });
export default defineConfig({
    out: './drizzle',
    schema: './src/db/schema.ts',
    dialect: 'postgresql',
    dbCredentials: {
        url: process.env.DATABASE_URL,
    },
});
//# sourceMappingURL=drizzle.config.js.map
