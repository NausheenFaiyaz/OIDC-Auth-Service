import { type Request, type Response } from "express";
import fs from "node:fs";
import path from "node:path";
import { createPublicKey } from "node:crypto";
import {
    dashboardSigninService,
    dashboardSignupService,
    deleteOAuthClientService,
    exchangeAuthorizationCodeService,
    getOAuthClientService,
    getProjectsForUserService,
    registerOAuthClientService,
    signinService,
    signupService,
    updateOAuthClientService,
    userInfoService
} from "./services.js";
import ApiError from "../../common/utils/ApiError.js";
import ApiResponse from "../../common/utils/ApiResponse.js";
import {
    dashboardLogin,
    dashboardSignup,
    oAuthClientRegister,
    oAuthClientUpdate,
    tokenExchange,
    userLogin,
    userSignup
} from "./validate.js";
import { type AuthenticatedRequest } from "./middleware.js";

const publicDir = path.resolve(process.cwd(), "public");

const getRequestValue = (value: unknown) => {
    if (typeof value === "string") {
        return value;
    }

    if (Array.isArray(value) && typeof value[0] === "string") {
        return value[0];
    }

    return undefined;
};

const getBody = (req: Request) => (req.body && typeof req.body === "object" ? req.body as Record<string, unknown> : {});

const getBasicClientCredentials = (authorizationHeader?: string) => {
    if (!authorizationHeader?.startsWith("Basic ")) {
        return null;
    }

    const encodedCredentials = authorizationHeader.slice(6).trim();

    try {
        const decodedCredentials = Buffer.from(encodedCredentials, "base64").toString("utf8");
        const separatorIndex = decodedCredentials.indexOf(":");

        if (separatorIndex <= 0) {
            return null;
        }

        const clientId = decodedCredentials.slice(0, separatorIndex).trim();
        const clientSecret = decodedCredentials.slice(separatorIndex + 1).trim();

        if (!clientId || !clientSecret) {
            return null;
        }

        return { clientId, clientSecret };
    } catch {
        return null;
    }
};

const getAuthorizationPayload = (req: Request) => {
    const body = getBody(req);

    return {
        clientId: getRequestValue(body.clientId) ?? getRequestValue(body.client_id) ?? getRequestValue(req.query.client_id),
        redirectUri: getRequestValue(body.redirectUri) ?? getRequestValue(body.redirect_uri) ?? getRequestValue(req.query.redirect_uri),
        state: getRequestValue(body.state) ?? getRequestValue(req.query.state),
        codeChallenge: getRequestValue(body.codeChallenge) ?? getRequestValue(body.code_challenge) ?? getRequestValue(req.query.code_challenge),
        codeChallengeMethod: getRequestValue(body.codeChallengeMethod) ?? getRequestValue(body.code_challenge_method) ?? getRequestValue(req.query.code_challenge_method)
    };
};

const sendPublicPage = (res: Response, fileName: string) => {
    res.sendFile(path.resolve(publicDir, fileName));
};

const requireUserId = (req: AuthenticatedRequest) => {
    const userId = req.user?.id;

    if (!userId) {
        throw ApiError.unauthorized("Invalid access token");
    }

    return userId;
};

export const dashboardPage = (_: Request, res: Response) => {
    sendPublicPage(res, "dashboard.html");
};

export const landingPage = (_: Request, res: Response) => {
    sendPublicPage(res, "index.html");
};

export const registerClientPage = (_: Request, res: Response) => {
    sendPublicPage(res, "client-register.html");
};

export const userRegisterPage = async (req: Request, res: Response) => {
    const { clientId, redirectUri } = getAuthorizationPayload(req);

    if (clientId) {
        await getOAuthClientService(clientId, redirectUri);
    }

    sendPublicPage(res, "signup.html");
};

export const userLoginPage = async (req: Request, res: Response) => {
    const { clientId, redirectUri } = getAuthorizationPayload(req);

    if (clientId) {
        await getOAuthClientService(clientId, redirectUri);
    }

    sendPublicPage(res, "signin.html");
};

export const getClientMeta = async (req: Request, res: Response) => {
    const { clientId, redirectUri } = getAuthorizationPayload(req);

    if (!clientId) {
        throw ApiError.badRequest("client_id is required");
    }

    const response = await getOAuthClientService(clientId, redirectUri);
    return ApiResponse.ok(res, "Client loaded successfully", response);
};

export const dashboardSignupController = async (req: Request, res: Response) => {
    const result = await dashboardSignup.safeParseAsync(req.body);

    if (!result.success) {
        throw ApiError.badRequest("Validation Error");
    }

    const { email, name, password } = result.data;
    const response = await dashboardSignupService(email, name, password);
    return ApiResponse.created(res, "User account created successfully", response);
};

export const dashboardSigninController = async (req: Request, res: Response) => {
    const result = await dashboardLogin.safeParseAsync(req.body);

    if (!result.success) {
        throw ApiError.badRequest("Validation Error");
    }

    const { email, password } = result.data;
    const response = await dashboardSigninService(email, password);
    return ApiResponse.ok(res, "User signed in successfully", response);
};

export const getDashboardProjectsController = async (req: AuthenticatedRequest, res: Response) => {
    const response = await getProjectsForUserService(requireUserId(req));
    return ApiResponse.ok(res, "Projects fetched successfully", response);
};

export const registerOAuthClient = async (req: AuthenticatedRequest, res: Response) => {
    const result = await oAuthClientRegister.safeParseAsync(req.body);

    if (!result.success) {
        throw ApiError.badRequest("Validation Error");
    }

    const { applicationName, applicationUrl, contactEmail, redirectUrl } = result.data;
    const response = await registerOAuthClientService(
        requireUserId(req),
        applicationName,
        contactEmail,
        applicationUrl,
        redirectUrl
    );

    return ApiResponse.created(res, "OAuth client registered successfully", response);
};

export const updateOAuthClient = async (req: AuthenticatedRequest, res: Response) => {
    const result = await oAuthClientUpdate.safeParseAsync(req.body);

    if (!result.success) {
        throw ApiError.badRequest("Validation Error");
    }

    const clientId = getRequestValue(req.params.clientId);

    if (!clientId) {
        throw ApiError.badRequest("clientId is required");
    }

    const response = await updateOAuthClientService(requireUserId(req), clientId, result.data);
    return ApiResponse.ok(res, "Project updated successfully", response);
};

export const deleteOAuthClient = async (req: AuthenticatedRequest, res: Response) => {
    const clientId = getRequestValue(req.params.clientId);

    if (!clientId) {
        throw ApiError.badRequest("clientId is required");
    }

    const response = await deleteOAuthClientService(requireUserId(req), clientId);
    return ApiResponse.ok(res, "Project deleted successfully", response);
};

export const signup = async (req: Request, res: Response) => {
    const authorizationPayload = getAuthorizationPayload(req);

    if (!authorizationPayload.clientId) {
        return dashboardSignupController(req, res);
    }

    const payload = {
        ...req.body,
        ...authorizationPayload
    };
    const result = await userSignup.safeParseAsync(payload);

    if (!result.success) {
        throw ApiError.badRequest("Validation Error");
    }

    const { clientId, email, name, password, redirectUri, state, codeChallenge, codeChallengeMethod } = result.data;
    const response = await signupService(email, name, password, {
        clientId,
        redirectUri,
        state,
        ...(codeChallenge ? { codeChallenge } : {}),
        ...(codeChallengeMethod ? { codeChallengeMethod } : {})
    });

    return ApiResponse.created(res, "User created successfully", response);
};

export const signin = async (req: Request, res: Response) => {
    const authorizationPayload = getAuthorizationPayload(req);

    if (!authorizationPayload.clientId) {
        return dashboardSigninController(req, res);
    }

    const payload = {
        ...req.body,
        ...authorizationPayload
    };
    const result = await userLogin.safeParseAsync(payload);

    if (!result.success) {
        throw ApiError.badRequest("Validation Error");
    }

    const { clientId, email, password, redirectUri, state, codeChallenge, codeChallengeMethod } = result.data;
    const response = await signinService(email, password, {
        clientId,
        redirectUri,
        state,
        ...(codeChallenge ? { codeChallenge } : {}),
        ...(codeChallengeMethod ? { codeChallengeMethod } : {})
    });

    if (!response) {
        throw ApiError.unauthorized("User Login failed");
    }

    return ApiResponse.ok(res, "Authorization code generated successfully", response);
};

export const token = async (req: Request, res: Response) => {
    const body = getBody(req);
    const basicCredentials = getBasicClientCredentials(req.headers.authorization);
    const payload = {
        ...body,
        grantType: getRequestValue(body.grantType) ?? getRequestValue(body.grant_type),
        clientId: getRequestValue(body.clientId) ?? getRequestValue(body.client_id) ?? basicCredentials?.clientId,
        clientSecret: getRequestValue(body.clientSecret) ?? getRequestValue(body.client_secret) ?? basicCredentials?.clientSecret,
        redirectUri: getRequestValue(body.redirectUri) ?? getRequestValue(body.redirect_uri),
        codeVerifier: getRequestValue(body.codeVerifier) ?? getRequestValue(body.code_verifier)
    };
    const result = await tokenExchange.safeParseAsync(payload);

    if (!result.success) {
        throw ApiError.badRequest("Validation Error");
    }

    const { clientId, clientSecret, code, redirectUri, codeVerifier, grantType } = result.data;

    if (grantType && grantType !== "authorization_code") {
        throw ApiError.badRequest("Unsupported grant_type");
    }

    if (!clientSecret) {
        throw ApiError.unauthorized("Invalid client credentials");
    }

    const issuer = `${req.protocol}://${req.get("host") ?? "localhost:8000"}`;
    const response = await exchangeAuthorizationCodeService(
        code,
        clientId,
        clientSecret,
        redirectUri,
        codeVerifier,
        issuer
    );
    return res.status(200).json(response);
};

export const userinfo = async (req: AuthenticatedRequest, res: Response) => {
    const response = await userInfoService(requireUserId(req));
    return res.status(200).json({
        sub: String(response.id),
        email: response.email,
        name: response.name
    });
};

export const certs = (_: Request, res: Response) => {
    const envPublicKey = process.env.JWT_PUBLIC_KEY?.replace(/\\n/g, "\n").trim();
    const publicKey = envPublicKey && envPublicKey.length > 0
        ? envPublicKey
        : fs.readFileSync(
            path.resolve(process.cwd(), "cert", "public.pem"),
            "utf8"
        );
    const jwk = createPublicKey(publicKey).export({ format: "jwk" }) as JsonWebKey;

    return res.status(200).json({
        keys: [
            {
                ...jwk,
                use: "sig",
                alg: "RS256",
                kid: "auth-service-rs256"
            }
        ]
    });
};

export const openIdConfig = (req: Request, res: Response) => {
    const baseURL = `${req.protocol}://${req.get("host") ?? "localhost:8000"}`;
    res.status(200).json({
        issuer: baseURL,
        authorization_endpoint: `${baseURL}/user/login`,
        token_endpoint: `${baseURL}/token`,
        userinfo_endpoint: `${baseURL}/userinfo`,
        jwks_uri: `${baseURL}/certs`,
        registration_endpoint: `${baseURL}/client/register`,
        response_types_supported: ["code"],
        response_modes_supported: ["query"],
        grant_types_supported: ["authorization_code"],
        scopes_supported: ["openid", "profile", "email"],
        subject_types_supported: ["public"],
        claims_supported: ["sub", "email", "name"],
        id_token_signing_alg_values_supported: ["RS256"],
        code_challenge_methods_supported: ["S256", "plain"],
        token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"]
    });
};






