import 'dotenv/config';
import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
export const db = drizzle(process.env.DATABASE_URL!);

export const ensureDatabaseSchema = async () => {
    await db.execute(sql.raw(`
        ALTER TABLE "oauth_clients"
        ADD COLUMN IF NOT EXISTS "owner_user_id" integer;
    `));

    await db.execute(sql.raw(`
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname = 'oauth_clients_owner_user_id_users_id_fk'
            ) THEN
                ALTER TABLE "oauth_clients"
                ADD CONSTRAINT "oauth_clients_owner_user_id_users_id_fk"
                FOREIGN KEY ("owner_user_id") REFERENCES "users"("id") ON DELETE CASCADE;
            END IF;
        END
        $$;
    `));

    await db.execute(sql.raw(`
        CREATE TABLE IF NOT EXISTS "authorization_codes" (
            "code" text PRIMARY KEY,
            "client_id" varchar(255) NOT NULL,
            "redirect_uri" text NOT NULL,
            "user_id" integer NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
            "expires_at" timestamp with time zone NOT NULL,
            "created_at" timestamp with time zone DEFAULT now() NOT NULL
        );
    `));

    await db.execute(sql.raw(`
        ALTER TABLE "authorization_codes"
        ADD COLUMN IF NOT EXISTS "consumed_at" timestamp with time zone;
    `));

    await db.execute(sql.raw(`
        CREATE INDEX IF NOT EXISTS "authorization_codes_expires_at_idx"
        ON "authorization_codes" ("expires_at");
    `));
};
