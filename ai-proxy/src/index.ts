import { callClaude, AIEnv } from "./anthropic";
import { verifyEntitlement, AuthEnv } from "./auth";

interface Env extends AIEnv, AuthEnv {}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" }
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);

    const ok = await verifyEntitlement(env, request);
    if (!ok) return json({ error: "Premium entitlement required" }, 402);

    const url = new URL(request.url);
    try {
      switch (url.pathname) {
        case "/meal-scan":
          return await handleMealScan(request, env);
        case "/biomarker":
          return await handleBiomarker(request, env);
        case "/body-comp":
          return await handleBodyComp(request, env);
        case "/protocol-suggest":
          return await handleProtocolSuggest(request, env);
        default:
          return json({ error: "Not found" }, 404);
      }
    } catch (err) {
      return json({ error: (err as Error).message }, 500);
    }
  }
};

async function handleMealScan(request: Request, env: Env): Promise<Response> {
  const body = await request.json<{ image_b64: string; media_type: string }>();
  const text = await callClaude(env, "meal", [
    {
      type: "image",
      source: { type: "base64", media_type: body.media_type as any, data: body.image_b64 }
    },
    { type: "text", text: "Estimate macros for this meal." }
  ]);
  return new Response(text, { headers: { "content-type": "application/json" } });
}

async function handleBiomarker(request: Request, env: Env): Promise<Response> {
  const body = await request.json<{ values: Array<{ marker: string; value: number; unit: string; ref_low?: number; ref_high?: number }> }>();
  const text = await callClaude(env, "biomarker", [
    { type: "text", text: `Markers:\n${JSON.stringify(body.values, null, 2)}` }
  ]);
  return new Response(text, { headers: { "content-type": "application/json" } });
}

async function handleBodyComp(request: Request, env: Env): Promise<Response> {
  const body = await request.json<{ before_b64: string; after_b64: string; media_type: string }>();
  const text = await callClaude(env, "bodyComp", [
    { type: "image", source: { type: "base64", media_type: body.media_type as any, data: body.before_b64 } },
    { type: "image", source: { type: "base64", media_type: body.media_type as any, data: body.after_b64 } },
    { type: "text", text: "Photo 1 is BEFORE, photo 2 is AFTER. Compare." }
  ]);
  return new Response(text, { headers: { "content-type": "application/json" } });
}

async function handleProtocolSuggest(request: Request, env: Env): Promise<Response> {
  const body = await request.json<{ goal: string; templates: Array<{ slug: string; name: string; summary: string }>; activity_summary?: string }>();
  const userText = `User goal: ${body.goal}\n\nAvailable templates (slug — name — summary):\n${body.templates.map(t => `- ${t.slug} — ${t.name} — ${t.summary}`).join("\n")}\n\nRecent activity: ${body.activity_summary ?? "none"}`;
  const text = await callClaude(env, "protocolSuggest", [{ type: "text", text: userText }]);
  return new Response(text, { headers: { "content-type": "application/json" } });
}
