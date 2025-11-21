import { IRequest } from "itty-router";
import { Env } from "./env.types";
import { Auth, createAuth } from "./auth";
import { mutableError } from "./util";
import { parseUploadMetadata } from "./parse";
import { Buffer } from "node:buffer";
import { generateUploadPath } from "./pathGenerator";
// lazy init because it requires env but is expensive to create
export let auth: Auth | undefined;

// Set request.user to the user from the basic auth credentials if the credential passes authentication
export async function withAuthenticatedUser(
  request: IRequest,
  env: Env,
  _ctx: ExecutionContext
): Promise<Response | undefined> {
  auth = auth || (await createAuth(env.SHARED_AUTH_SECRET, 3600 * 24 * 7));
  const authHeader = request.headers.get("Authorization");
  const url = new URL(request.url);
  const authTokenParam = url.searchParams.get("token");

  const token = authHeader ?? `Basic ${authTokenParam}`;

  if (!token) {
    return mutableError(401, "missing credentials");
  }

  const parsed = parseBasicAuth(token);

  if (parsed.state === "error") {
    return parsed.error;
  }
  const valid = await auth.validateCredentials(parsed.user, parsed.password);
  if (!valid) {
    return mutableError(401, "invalid credentials");
  }
  request.user = parsed.user;
}
// Auth usernames are of the form [permission$]namespace/entity. withAuthenticatedUser ensures that the username is
// a valid credential. After that we must also ensure that the user is authorized to perform the requested action.
// - If the endpoint requires permission, the permission field must be extracted and checked
// - The namespace must match the path prefix, e.g. attachments or backups
// - For uploads, the entity must match the target of the upload operation (which may be specified via path or metadata)
// - For non-public reads, the entity must match the top-level parent directory of the read-target
// Extracts the permission specifier from the already authenticated request.user and if it is 'read', set request.user
// to the rest of the username
export function withReadAuthorization(
  request: IRequest,
  env: Env,
  _ctx: ExecutionContext
): Response | undefined {
  return withPermission("read", request, env);
}

// Extracts the permission specifier from the already authenticated request.user and if it is 'write', set request.user
// to the rest of the username
export function withWriteAuthorization(
  request: IRequest,
  env: Env,
  _ctx: ExecutionContext
): Response | undefined {
  return withPermission("write", request, env);
}

// Strips off the permission specifier and make sure it matches expectedPermission
export function withPermission(
  expectedPermission: string,
  request: IRequest,
  _env: Env
): Response | undefined {
  // the user should be set by a prior middleware (and should already have been authenticated)
  if (!request.user) {
    return mutableError(500);
  }
  // strip off the permission and check it
  const splAt = request.user.indexOf("$");
  if (splAt === -1) {
    return mutableError(401);
  }
  const permission = request.user.substring(0, splAt);
  if (permission !== expectedPermission) {
    return mutableError(401);
  }

  // set the user as the remainder of the username
  request.user = request.user.substring(splAt + 1);
} // Set request.key to :subdir/:id from the request path, if the authenticated user matches :subdir
export function withSubdirAuthorizedKey(
  request: IRequest,
  env: Env,
  _ctx: ExecutionContext
): Response | undefined {
  return setAuthorizedKey(
    {
      keyExtractor: (request) =>
        `${request.params.subdir}/${request.params.id}`,
      entityExtractor: (request) => request.params.subdir,
    },
    request,
    env
  );
} // Set request.key to the name extracted from :id in the request path, if the authenticated user matches the name
export function withAuthorizedKeyFromPath(prefix?: string) {
  return (
    request: IRequest,
    env: Env,
    _ctx: ExecutionContext
  ): Response | undefined => {
    const key = (prefix ?? "") + `${request.params.id}`;

    // Validate path doesn't contain traversal attempts or dangerous patterns
    if (key.includes('..') || key.includes('//') || key.includes('\\')) {
      return mutableError(400, "invalid path");
    }

    return setAuthorizedKey(
      { keyExtractor: (_) => key },
      request,
      env
    );
  };
} // Set request.key to the name extracted from the uploadMetadata, if the authenticated user the name
export function withAuthorizedKeyFromMetadata(prefix = "") {
  return (
    request: IRequest,
    env: Env,
    _ctx: ExecutionContext
  ): Response | undefined => {
    const metadata = parseUploadMetadata(request.headers);
    if (!metadata.filename) {
      return mutableError(400, "filename required in Upload-Metadata");
    }

    // Extract serviceId from query parameters (if present - used for attachments)
    const url = new URL(request.url);
    const serviceId = url.searchParams.get("serviceId");

    let key: string;

    if (serviceId) {
      // For attachments with serviceId: generate hierarchical path
      // Format: {prefix}/{serviceId}/{filename}
      key = generateUploadPath({
        prefix: prefix.replace(/\/$/, ""), // Remove trailing slash if present
        serviceId: serviceId,
        filename: metadata.filename,
      });
    } else {
      // For backups without serviceId: use old flat format
      // Format: {prefix}{filename}
      key = prefix + metadata.filename;
    }

    return setAuthorizedKey(
      {
        keyExtractor: (_) => key,
      },
      request,
      env
    );
  };
} // Set request.key to the request's target if the (already authenticated) username matches the expected username for
// that target

export function setAuthorizedKey(
  authOptions: AuthOptions,
  request: IRequest,
  _env: Env
): Response | undefined {
  // the user should be set by a prior middleware (and should already have been authenticated)
  if (!request.user) {
    return mutableError(500);
  }

  // the namespace should have been set based on the request path by a prior middleware
  if (!request.namespace) {
    console.log("NAME_SPACE:NOT_FOUND");
    return mutableError(404);
  }

  // the key within the namespace that this request will operate on
  const key = authOptions.keyExtractor(request);
  if (!key) {
    console.log("NO_KEY_FOUND!!!");
    return mutableError(401);
  }

  // the entity within the namespace that should match the provided username
  const expectedEntity = (
    authOptions.entityExtractor || authOptions.keyExtractor
  )(request);

  if (!expectedEntity) {
    console.log("EXPECTED_ENTITY_NOT_FOUND:", expectedEntity);
    return mutableError(401);
  }

  // the username must match the expected entity that grants permission to the key
  // if (request.user !== `${request.namespace.name}/${expectedEntity}`) {
  //   console.log(
  //     "USER_AND_REQUEST_NAME_SPACE_NOT_MATCH",
  //     "\n",
  //     "[USER]",
  //     request.user,
  //     "\n",
  //     "[ENTITY]",
  //     `${request.namespace.name}/${expectedEntity}`
  //   );
  //   return mutableError(401);
  // }
  request.key = key;
} // Set request.key without any authentication (public access)
export function withUnauthenticatedKeyFromId(
  request: IRequest,
  _env: Env,
  _ctx: ExecutionContext
): Response | undefined {
  // For GET requests, we need to prepend the namespace to construct the full R2 key
  // Example: URL /attachments/serviceId/file.pdf
  // - request.params.id = "serviceId/file.pdf"
  // - request.namespace.name = "attachments"
  // - Result: request.key = "attachments/serviceId/file.pdf"
  const namespace = request.namespace?.name;
  if (namespace) {
    request.key = `${namespace}/${request.params.id}`;
  } else {
    request.key = request.params.id;
  }
  return;
}
export interface AuthOptions {
  // How to extract the key that will be attached to the request after a successful check
  keyExtractor: (request: IRequest) => string | undefined;
  // How to extract the expected contents of the username after the permission. If not
  // specified, defaults to the key
  entityExtractor?: (request: IRequest) => string | undefined;
}

interface ParseError {
  state: "error";
  error: Response;
}

interface Credentials {
  state: "success";
  user: string;
  password: string;
}

function parseBasicAuth(auth: string): Credentials | ParseError {
  const prefix = "Basic ";
  if (!auth.startsWith(prefix)) {
    return {
      state: "error",
      error: mutableError(400, "auth should be Basic "),
    };
  }

  const cred = auth.slice(prefix.length);
  const decoded = Buffer.from(cred, "base64").toString("utf8");

  const [username, ...rest] = decoded.split(":");
  const password = rest.join(":");
  if (!username || !password) {
    return { state: "error", error: mutableError(400, "invalid auth format") };
  }
  return { state: "success", user: username, password: password };
}
