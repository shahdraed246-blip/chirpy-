import argon2 from "argon2";
import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import type { JwtPayload } from "jsonwebtoken";
import type { Request } from "express";

export async function hashPassword(password: string): Promise<string> {
  return await argon2.hash(password);
}

export async function checkPasswordHash(
  password: string,
  hash: string,
): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

type payload = Pick<JwtPayload, "iss" | "sub" | "iat" | "exp">;

export function makeJWT(
  userID: string,
  expiresIn: number,
  secret: string,
): string {
  const iat = Math.floor(Date.now() / 1000);
  const data: payload = {
    iss: "chirpy",
    sub: userID,
    iat: iat,
    exp: iat + expiresIn,
  };
  return jwt.sign(data, secret);
}

export function validateJWT(tokenString: string, secret: string): string {
  let decoded: JwtPayload;
  try {
    decoded = jwt.verify(tokenString, secret) as JwtPayload;
  } catch {
    throw new Error("Invalid token");
  }

  if (!decoded.sub) {
    throw new Error("Invalid token");
  }
  return decoded.sub;
}

export function getBearerToken(req: Request): string {
  const header = req.get("Authorization");
  if (!header) {
    throw new Error("Missing Authorization header");
  }

  const parts = header.trim().split(/\s+/);
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    throw new Error("Malformed Authorization header");
  }
  return parts[1];
}

export function makeRefreshToken(): string {
  return crypto.randomBytes(32).toString("hex");
}
export function getAPIKey(req: Request): string {
  const header = req.get("Authorization");
  if (!header) {
    throw new Error("Missing Authorization header");
  }

  const parts = header.trim().split(/\s+/);
  if (parts.length !== 2 || parts[0] !== "ApiKey") {
    throw new Error("Malformed Authorization header");
  }
  return parts[1];
}
