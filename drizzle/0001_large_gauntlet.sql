ALTER TABLE "authorization_codes" ADD COLUMN "code_challenge" text;--> statement-breakpoint
ALTER TABLE "authorization_codes" ADD COLUMN "code_challenge_method" varchar(10);