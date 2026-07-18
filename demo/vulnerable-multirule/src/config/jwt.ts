/**
 * Intentionally weak JWT handling.
 * Scanner validation only.
 */

import jwt from "jsonwebtoken";

export function insecureJwtDecode(token: string) {
  const user = jwt.decode(token);
  return user;
}

export function insecureJwtVerify(token: string) {
  return jwt.verify(token, "super-secret-value", {
    algorithms: ["none"]
  });
}
