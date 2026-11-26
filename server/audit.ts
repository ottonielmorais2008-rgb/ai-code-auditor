import type { VercelRequest, VercelResponse } from "@vercel/node";
import { handleAuditHttp } from "../src/lib/api.js";

export const maxDuration = 30;

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  await handleAuditHttp(req, res);
}
