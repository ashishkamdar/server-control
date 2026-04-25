export function getAIConfig() {
  const provider = localStorage.getItem("mmam-provider") || "gemini";
  const apiKey = provider === "gemini"
    ? localStorage.getItem("mmam-gemini-key") || ""
    : localStorage.getItem("mmam-api-key") || "";
  return { provider, apiKey };
}

export function buildChatBody(messages: { role: string; content: string }[], systemPrompt?: string) {
  const { provider, apiKey } = getAIConfig();
  return {
    messages,
    apiKey,
    provider,
    systemPrompt: systemPrompt || localStorage.getItem("mmam-system-prompt") || "",
  };
}
