import { eq } from "drizzle-orm"
import { db } from "../../../db/config.js"
import { users } from "../../../db/schema.js"
import ApiError from "./ApiError.js"
import jwt, { type SignOptions } from "jsonwebtoken"
import fs from "node:fs"
import path from "node:path"

const privateKeyPath = path.resolve(process.cwd(), "cert", "private.pem")
const normalizePem = (value: string) => value.replace(/\\n/g, "\n").trim()

const getPrivateKey = () => {
    const envPrivateKey = process.env.JWT_PRIVATE_KEY
    if (envPrivateKey && envPrivateKey.trim().length > 0) {
        return normalizePem(envPrivateKey)
    }

    try {
        return fs.readFileSync(privateKeyPath, "utf8")
    } catch {
        throw ApiError.internal("Private key is not defined")
    }
}

export const generateTokens = async (userId: number) => {
    try {
        const user = await db.select().from(users).where(eq(users.id, userId))

        if (!user || user.length === 0) {
            throw ApiError.notFound("User not found")
        }

        const currentUser = user[0]!
        const privateKey = getPrivateKey()

        const accessExpiry = process.env.ACCESS_TOKEN_EXPIRY ?? "15m"
        const refreshExpiry = process.env.REFRESH_TOKEN_EXPIRY ?? "7d"

        const accessToken = jwt.sign(
            {
                id: currentUser.id,
                email: currentUser.email,
                name: currentUser.name
            },
            privateKey,
            {
                algorithm: "RS256",
                expiresIn: accessExpiry
            } as SignOptions
        )

        const refreshToken = jwt.sign(
            {
                id: currentUser.id
            },
            privateKey,
            {
                algorithm: "RS256",
                expiresIn: refreshExpiry
            } as SignOptions
        )

        await db
            .update(users)
            .set({ refreshToken })
            .where(eq(users.id, userId))

        return { accessToken, refreshToken }

    } catch (error: unknown) {
        console.error(error)

        if (error instanceof ApiError) {
            throw error
        }

        throw ApiError.internal("Something went wrong while generating tokens")
    }
}

export const generateIdToken = (
    user: { id: number; email: string; name: string },
    issuer: string,
    audience: string
) => {
    const privateKey = getPrivateKey();

    return jwt.sign(
        {
            sub: String(user.id),
            email: user.email,
            name: user.name
        },
        privateKey,
        {
            algorithm: "RS256",
            issuer,
            audience,
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY ?? "15m"
        } as SignOptions
    );
};
