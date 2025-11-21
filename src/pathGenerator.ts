import { Buffer } from "node:buffer";
/**
 * Path generation utilities for R2 object keys
 * Generates secure, hierarchical paths for file uploads
 */

export interface PathGenerationOptions {
  prefix: string; // e.g., "attachments" or "backups"
  serviceId: string; // Unique identifier for the upload session
  filename: string; // Original filename from Upload-Metadata
}

/**
 * Generates a secure, hierarchical R2 object key
 * Format: {prefix}/{serviceId}/{sanitized-filename}
 *
 * Example: "attachments/abc-123-uuid/document.pdf"
 *
 * @param options - Path generation parameters
 * @returns Sanitized R2 object key
 */
export function generateUploadPath(options: PathGenerationOptions): string {
  const { prefix, serviceId, filename } = options;

  // Sanitize filename to prevent path traversal and other security issues
  const safeFilename = sanitizeFilename(filename);

  // Validate serviceId format (should be a valid UUID or similar)
  if (!serviceId || serviceId.trim().length === 0) {
    throw new Error("serviceId is required for path generation");
  }

  // Construct hierarchical path: {prefix}/{serviceId}/{filename}
  return `${prefix}/${serviceId}/${safeFilename}`;
}

/**
 * Sanitizes a filename to prevent security issues
 * - Removes path traversal attempts (../, //, etc.)
 * - Removes or replaces dangerous characters
 * - Preserves file extension
 * - Ensures non-empty result
 *
 * @param filename - Original filename
 * @returns Sanitized filename safe for use in R2 keys
 */
export function sanitizeFilename(filename: string): string {
  if (!filename || filename.trim().length === 0) {
    return "unknown";
  }

  // Remove any path components (in case filename contains slashes)
  // This prevents "../" or "/" from being used in filenames
  const basename = filename.split("/").pop() || "unknown";

  // Remove path traversal attempts and normalize
  let sanitized = basename
    .replace(/\.\./g, "") // Remove ".."
    .replace(/\/+/g, "_") // Replace slashes with underscore
    .replace(/\\+/g, "_") // Replace backslashes with underscore
    .trim();

  // Replace dangerous or problematic characters
  // Keep: alphanumeric, dots, hyphens, underscores
  // This preserves file extensions like .pdf, .jpg, etc.
  sanitized = sanitized.replace(/[^a-zA-Z0-9._-]/g, "_");

  // Ensure we don't have empty filename after sanitization
  if (sanitized.length === 0) {
    return "unknown";
  }

  // Prevent filenames starting with dots (hidden files)
  if (sanitized.startsWith(".")) {
    sanitized = "_" + sanitized.substring(1);
  }

  return sanitized;
}

/**
 * Validates that a path is secure and well-formed
 * - Starts with expected prefix
 * - No path traversal attempts
 * - No double slashes
 * - Within R2's key length limit (1024 bytes)
 *
 * @param path - The path to validate
 * @param expectedPrefix - The expected prefix (e.g., "attachments")
 * @returns true if path is valid, false otherwise
 */
export function validatePath(path: string, expectedPrefix: string): boolean {
  // Must start with expected prefix
  if (!path.startsWith(expectedPrefix + "/")) {
    return false;
  }

  // No path traversal attempts
  if (path.includes("..")) {
    return false;
  }

  // No double slashes (could indicate path manipulation)
  if (path.includes("//")) {
    return false;
  }

  // R2 key length limit is 1024 bytes
  // Use Buffer.byteLength to account for multi-byte characters
  if (Buffer.byteLength(path, "utf8") > 1024) {
    return false;
  }

  // No backslashes (not valid in R2 keys)
  if (path.includes("\\")) {
    return false;
  }

  return true;
}

/**
 * Extracts the serviceId from a full R2 path
 * Format: {prefix}/{serviceId}/{filename}
 *
 * @param path - Full R2 object key
 * @param prefix - Expected prefix
 * @returns serviceId or null if path is invalid
 */
export function extractServiceIdFromPath(
  path: string,
  prefix: string
): string | null {
  // Remove prefix
  if (!path.startsWith(prefix + "/")) {
    return null;
  }

  const withoutPrefix = path.substring(prefix.length + 1);

  // Extract first segment (serviceId)
  const segments = withoutPrefix.split("/");
  if (segments.length < 2) {
    return null; // Invalid path structure
  }

  return segments[0] ?? null;
}
