import express from "express";
import { Request, Response, NextFunction } from "express";
import postgres from "postgres";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import { drizzle } from "drizzle-orm/postgres-js";

import { config } from "./config.js";
import {
  hashPassword,
  checkPasswordHash,
  makeJWT,
  validateJWT,
  getBearerToken,
  makeRefreshToken,
  getAPIKey,
} from "./auth.js";
import {
  createUser,
  deleteAllUsers,
  getUserByEmail,
  updateUser,
  upgradeUserToChirpyRed,
} from "./db/queries/users.js";
import {
  createChirp,
  getChirps,
  getChirpsByAuthor,
  getChirp,
  deleteChirp,
} from "./db/queries/chirps.js";
import {
  createRefreshToken,
  getUserFromRefreshToken,
  revokeRefreshToken,
} from "./db/queries/refreshTokens.js";

const migrationClient = postgres(config.db.url, { max: 1 });
await migrate(drizzle(migrationClient), config.db.migrationConfig);

const app = express();

app.use(express.json());
app.use(middlewareLogResponses);
app.use("/app", middlewareMetricsInc, express.static("./src/app"));

app.get("/api/healthz", handlerReadiness);
app.post("/api/chirps", handlerCreateChirp);
app.get("/api/chirps", handlerGetChirps);
app.get("/api/chirps/:chirpId", handlerGetChirp);
app.delete("/api/chirps/:chirpId", handlerDeleteChirp);
app.post("/api/users", handlerCreateUser);
app.put("/api/users", handlerUpdateUser);
app.post("/api/login", handlerLogin);
app.post("/api/refresh", handlerRefresh);
app.post("/api/revoke", handlerRevoke);
app.post("/api/polka/webhooks", handlerPolkaWebhook);
app.get("/admin/metrics", handlerMetrics);
app.post("/admin/reset", handlerReset);

app.use(errorHandler);

app.listen(config.api.port, () => {
  console.log(`Server is running at http://localhost:${config.api.port}`);
});

class BadRequestError extends Error {
  constructor(message: string) {
    super(message);
  }
}

class UnauthorizedError extends Error {
  constructor(message: string) {
    super(message);
  }
}

class ForbiddenError extends Error {
  constructor(message: string) {
    super(message);
  }
}

class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
  }
}

async function handlerReadiness(req: Request, res: Response) {
  res.set("Content-Type", "text/plain; charset=utf-8");
  res.send("OK");
}

async function handlerCreateUser(req: Request, res: Response) {
  type parameters = {
    email: string;
    password: string;
  };

  const params: parameters = req.body;

  if (
    !params ||
    typeof params.email !== "string" ||
    params.email === "" ||
    typeof params.password !== "string" ||
    params.password === ""
  ) {
    throw new BadRequestError("Email and password are required");
  }

  const hashedPassword = await hashPassword(params.password);
  const user = await createUser({
    email: params.email,
    hashedPassword: hashedPassword,
  });
  if (!user) {
    throw new BadRequestError("Could not create user");
  }

  respondWithJSON(res, 201, {
    id: user.id,
    email: user.email,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    isChirpyRed: user.isChirpyRed,
  });
}

async function handlerUpdateUser(req: Request, res: Response) {
  type parameters = {
    email: string;
    password: string;
  };

  let userId: string;
  try {
    const token = getBearerToken(req);
    userId = validateJWT(token, config.api.jwtSecret);
  } catch {
    throw new UnauthorizedError("Invalid or missing token");
  }

  const params: parameters = req.body;
  if (
    !params ||
    typeof params.email !== "string" ||
    params.email === "" ||
    typeof params.password !== "string" ||
    params.password === ""
  ) {
    throw new BadRequestError("Email and password are required");
  }

  const hashedPassword = await hashPassword(params.password);
  const user = await updateUser(userId, params.email, hashedPassword);
  if (!user) {
    throw new NotFoundError("User not found");
  }

  respondWithJSON(res, 200, {
    id: user.id,
    email: user.email,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    isChirpyRed: user.isChirpyRed,
  });
}

async function handlerLogin(req: Request, res: Response) {
  type parameters = {
    email: string;
    password: string;
  };

  const params: parameters = req.body;

  if (
    !params ||
    typeof params.email !== "string" ||
    typeof params.password !== "string"
  ) {
    throw new BadRequestError("Email and password are required");
  }

  const user = await getUserByEmail(params.email);
  if (!user) {
    throw new UnauthorizedError("incorrect email or password");
  }

  const matches = await checkPasswordHash(params.password, user.hashedPassword);
  if (!matches) {
    throw new UnauthorizedError("incorrect email or password");
  }

  const accessToken = makeJWT(user.id, 60 * 60, config.api.jwtSecret);

  const refreshToken = makeRefreshToken();
  await createRefreshToken({
    token: refreshToken,
    userId: user.id,
    expiresAt: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000),
  });

  respondWithJSON(res, 200, {
    id: user.id,
    email: user.email,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    isChirpyRed: user.isChirpyRed,
    token: accessToken,
    refreshToken: refreshToken,
  });
}

async function handlerRefresh(req: Request, res: Response) {
  let refreshToken: string;
  try {
    refreshToken = getBearerToken(req);
  } catch {
    throw new UnauthorizedError("Invalid or missing token");
  }

  const user = await getUserFromRefreshToken(refreshToken);
  if (!user) {
    throw new UnauthorizedError("Invalid or expired refresh token");
  }

  const accessToken = makeJWT(user.id, 60 * 60, config.api.jwtSecret);
  respondWithJSON(res, 200, { token: accessToken });
}

async function handlerRevoke(req: Request, res: Response) {
  let refreshToken: string;
  try {
    refreshToken = getBearerToken(req);
  } catch {
    throw new UnauthorizedError("Invalid or missing token");
  }

  await revokeRefreshToken(refreshToken);
  res.status(204).send();
}

async function handlerPolkaWebhook(req: Request, res: Response) {
  try {
    const apiKey = getAPIKey(req);
    if (apiKey !== config.api.polkaKey) {
      throw new Error("Invalid API key");
    }
  } catch {
    throw new UnauthorizedError("Invalid or missing API key");
  }

  type parameters = {
    event: string;
    data: {
      userId: string;
    };
  };

  const params: parameters = req.body;

  if (!params || typeof params.event !== "string") {
    throw new BadRequestError("Invalid request body");
  }

  if (params.event !== "user.upgraded") {
    res.status(204).send();
    return;
  }

  if (!params.data || typeof params.data.userId !== "string") {
    throw new BadRequestError("Invalid request body");
  }

  const user = await upgradeUserToChirpyRed(params.data.userId);
  if (!user) {
    throw new NotFoundError("User not found");
  }

  res.status(204).send();
}

async function handlerCreateChirp(req: Request, res: Response) {
  type parameters = {
    body: string;
  };

  let userId: string;
  try {
    const token = getBearerToken(req);
    userId = validateJWT(token, config.api.jwtSecret);
  } catch {
    throw new UnauthorizedError("Invalid or missing token");
  }

  const params: parameters = req.body;

  if (!params || typeof params.body !== "string") {
    throw new BadRequestError("Invalid request body");
  }

  if (params.body.length > 140) {
    throw new BadRequestError("Chirp is too long. Max length is 140");
  }

  const badWords = ["kerfuffle", "sharbert", "fornax"];
  const cleaned = params.body
    .split(" ")
    .map((word) => (badWords.includes(word.toLowerCase()) ? "****" : word))
    .join(" ");

  const chirp = await createChirp({ body: cleaned, userId: userId });
  if (!chirp) {
    throw new Error("Could not create chirp");
  }

  respondWithJSON(res, 201, {
    id: chirp.id,
    createdAt: chirp.createdAt,
    updatedAt: chirp.updatedAt,
    body: chirp.body,
    userId: chirp.userId,
  });
}

async function handlerGetChirps(req: Request, res: Response) {
  const authorId = req.query.authorId;
  const sort = req.query.sort === "desc" ? "desc" : "asc";

  let result;
  if (typeof authorId === "string" && authorId !== "") {
    result = await getChirpsByAuthor(authorId);
  } else {
    result = await getChirps();
  }

  result.sort((a, b) => {
    const diff = a.createdAt.getTime() - b.createdAt.getTime();
    return sort === "desc" ? -diff : diff;
  });

  respondWithJSON(res, 200, result);
}
async function handlerGetChirp(req: Request, res: Response) {
  const chirpId = req.params.chirpId;
  if (typeof chirpId !== "string") {
    throw new BadRequestError("Invalid chirp ID");
  }

  const chirp = await getChirp(chirpId);
  if (!chirp) {
    throw new NotFoundError("Chirp not found");
  }

  respondWithJSON(res, 200, chirp);
}

async function handlerDeleteChirp(req: Request, res: Response) {
  let userId: string;
  try {
    const token = getBearerToken(req);
    userId = validateJWT(token, config.api.jwtSecret);
  } catch {
    throw new UnauthorizedError("Invalid or missing token");
  }

  const chirpId = req.params.chirpId;
  if (typeof chirpId !== "string") {
    throw new BadRequestError("Invalid chirp ID");
  }

  const chirp = await getChirp(chirpId);
  if (!chirp) {
    throw new NotFoundError("Chirp not found");
  }

  if (chirp.userId !== userId) {
    throw new ForbiddenError("You can only delete your own chirps");
  }

  await deleteChirp(chirpId);
  res.status(204).send();
}

function respondWithJSON(res: Response, status: number, payload: unknown) {
  res.header("Content-Type", "application/json");
  res.status(status).send(JSON.stringify(payload));
}

async function handlerMetrics(req: Request, res: Response) {
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited ${config.api.fileserverHits} times!</p>
  </body>
</html>`);
}

async function handlerReset(req: Request, res: Response) {
  if (config.api.platform !== "dev") {
    throw new ForbiddenError("Forbidden");
  }

  config.api.fileserverHits = 0;
  await deleteAllUsers();

  res.set("Content-Type", "text/plain; charset=utf-8");
  res.send("OK");
}

function middlewareLogResponses(req: Request, res: Response, next: NextFunction) {
  res.on("finish", () => {
    const status = res.statusCode;
    if (status < 200 || status >= 300) {
      console.log(`[NON-OK] ${req.method} ${req.url} - Status: ${status}`);
    }
  });
  next();
}

function middlewareMetricsInc(req: Request, res: Response, next: NextFunction) {
  config.api.fileserverHits++;
  next();
}

function errorHandler(
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction,
) {
  if (err instanceof BadRequestError) {
    res.status(400).json({ error: err.message });
  } else if (err instanceof UnauthorizedError) {
    res.status(401).json({ error: err.message });
  } else if (err instanceof ForbiddenError) {
    res.status(403).json({ error: err.message });
  } else if (err instanceof NotFoundError) {
    res.status(404).json({ error: err.message });
  } else {
    console.log(err.message);
    res.status(500).json({ error: "Something went wrong on our end" });
  }
}
