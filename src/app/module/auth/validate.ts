import { z } from "zod"

const authClientFields = {
    clientId: z.string().uuid(),
    redirectUri: z.string().url().optional(),
    state: z.string().max(2048).optional(),
    codeChallenge: z.string().min(43).max(128).optional(),
    codeChallengeMethod: z.enum(["S256", "plain"]).optional()
}

export const userSignup = z.object({
    name: z.string().min(5).max(100),
    email: z.string().email().max(322),
    password: z.string().min(5).max(64),
    ...authClientFields
});

export const userLogin = z.object({
    email: z.string().email().max(322),
    password: z.string().min(5).max(64),
    ...authClientFields
})

export const dashboardLogin = z.object({
    email: z.string().email().max(322),
    password: z.string().min(5).max(64)
})


export const oAuthClientRegister = z.object({
    applicationName: z.string().min(3).max(255),
    contactEmail: z.string().email().max(322),
    applicationUrl: z.string().url(),
    redirectUrl: z.string().url()
})

export const oAuthClientUpdate = z.object({
    applicationName: z.string().min(3).max(255),
    contactEmail: z.string().email().max(322),
    applicationUrl: z.string().url(),
    redirectUrl: z.string().url()
})

export const dashboardSignup = z.object({
    name: z.string().min(3).max(100),
    email: z.string().email().max(322),
    password: z.string().min(5).max(64)
})

export const tokenExchange = z.union([
    z.object({
        code: z.string(),
        clientId: z.string(),
        clientSecret: z.string().optional(),
        grantType: z.literal("authorization_code").optional(),
        redirectUri: z.string().url().optional(),
        codeVerifier: z.string().min(43).max(128).optional(),
        refreshToken: z.string().optional()
    }),
    z.object({
        clientId: z.string(),
        clientSecret: z.string().optional(),
        grantType: z.literal("refresh_token"),
        refreshToken: z.string(),
        code: z.string().optional(),
        redirectUri: z.string().url().optional(),
        codeVerifier: z.string().min(43).max(128).optional()
    })
])
