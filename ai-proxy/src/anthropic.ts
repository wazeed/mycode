import Anthropic from "@anthropic-ai/sdk";

export interface AIEnv {
  ANTHROPIC_API_KEY: string;
  ANTHROPIC_MODEL: string;
}

export const SYSTEM_PROMPTS = {
  meal: `You are a nutritionist helping a peptide-tracking app log meals. Given an image of food, return STRICT JSON: {"name": string, "calories": number, "protein_g": number, "carbs_g": number, "fat_g": number, "confidence": 0..1}. No prose, no markdown — JSON only. If you cannot identify the food, return zeros and confidence 0.`,

  biomarker: `You are a clinically-careful health educator. Given a list of lab markers with values and reference ranges, return STRICT JSON: {"summary": string (≤120 words, plain English, NEVER claims of diagnosis or treatment), "flags": [{"marker": string, "status": "low"|"normal"|"high", "note": string}]}. Always end summary with the verbatim phrase "Discuss any concerns with a licensed clinician." JSON only.`,

  bodyComp: `You are visually estimating body-composition change between two progress photos taken from the same angle. Return STRICT JSON: {"observation": string (≤80 words, neutral, descriptive — no judgments about appearance), "estimated_change": "loss"|"gain"|"recomp"|"unclear"}. JSON only.`,

  protocolSuggest: `You are a peptide-research educator. Given the user's stated goal and current activity, suggest 1–3 named protocols from a SUPPLIED list of templates. Return STRICT JSON: {"recommendations": [{"slug": string, "rationale": string (≤60 words), "caveats": string (≤40 words, must mention consulting a clinician)}]}. NEVER recommend a protocol not in the supplied list. JSON only.`
};

export type PromptKey = keyof typeof SYSTEM_PROMPTS;

export async function callClaude(
  env: AIEnv,
  promptKey: PromptKey,
  userContent: Anthropic.MessageParam["content"]
): Promise<string> {
  const client = new Anthropic({ apiKey: env.ANTHROPIC_API_KEY });
  const response = await client.messages.create({
    model: env.ANTHROPIC_MODEL || "claude-sonnet-4-6",
    max_tokens: 1024,
    system: [
      {
        type: "text",
        text: SYSTEM_PROMPTS[promptKey],
        cache_control: { type: "ephemeral" }
      }
    ],
    messages: [{ role: "user", content: userContent }]
  });

  const text = response.content
    .filter((b): b is Anthropic.TextBlock => b.type === "text")
    .map((b) => b.text)
    .join("");
  return text;
}
