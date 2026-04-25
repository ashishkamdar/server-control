import Anthropic from "@anthropic-ai/sdk";
import { GoogleGenerativeAI } from "@google/generative-ai";

export async function POST(req: Request) {
  const { messages, apiKey, systemPrompt, provider } = await req.json();

  if (!apiKey) {
    return Response.json({ error: "API key is required" }, { status: 400 });
  }

  if (!messages || messages.length === 0) {
    return Response.json({ error: "Messages are required" }, { status: 400 });
  }

  const encoder = new TextEncoder();

  // Google Gemini
  if (provider === "gemini") {
    try {
      const genAI = new GoogleGenerativeAI(apiKey);
      const model = genAI.getGenerativeModel({
        model: "gemini-2.5-flash",
        systemInstruction: systemPrompt || "You are a helpful business advisor.",
      });

      const history = messages.slice(0, -1).map((m: { role: string; content: string }) => ({
        role: m.role === "assistant" ? "model" : "user",
        parts: [{ text: m.content }],
      }));

      const chat = model.startChat({ history });
      const lastMessage = messages[messages.length - 1].content;
      const result = await chat.sendMessageStream(lastMessage);

      const readable = new ReadableStream({
        async start(controller) {
          for await (const chunk of result.stream) {
            const text = chunk.text();
            if (text) controller.enqueue(encoder.encode(text));
          }
          controller.close();
        },
      });

      return new Response(readable, {
        headers: { "Content-Type": "text/plain; charset=utf-8" },
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error";
      return Response.json({ error: message }, { status: 500 });
    }
  }

  // Anthropic Claude (default)
  try {
    const client = new Anthropic({ apiKey });
    const stream = await client.messages.stream({
      model: "claude-sonnet-4-20250514",
      max_tokens: 4096,
      system: systemPrompt || "You are a helpful business advisor.",
      messages: messages.map((m: { role: string; content: string }) => ({
        role: m.role,
        content: m.content,
      })),
    });

    const readable = new ReadableStream({
      async start(controller) {
        for await (const event of stream) {
          if (
            event.type === "content_block_delta" &&
            event.delta.type === "text_delta"
          ) {
            controller.enqueue(encoder.encode(event.delta.text));
          }
        }
        controller.close();
      },
    });

    return new Response(readable, {
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return Response.json({ error: message }, { status: 500 });
  }
}
