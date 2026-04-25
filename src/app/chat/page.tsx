"use client";

import { useEffect, useRef, useState } from "react";

interface Message {
  role: "user" | "assistant";
  content: string;
}

interface ChatSession {
  id: number | string;
  title: string;
  messages: Message[];
  created_at?: string;
}

export default function ChatPage() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [streaming, setStreaming] = useState("");
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [currentSessionId, setCurrentSessionId] = useState<string | number | null>(null);
  const [showSessions, setShowSessions] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    fetch("/api/chat-sessions").then(r => r.json()).then(setSessions).catch(() => {});
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, streaming]);

  const autoResize = () => {
    const ta = textareaRef.current;
    if (ta) {
      ta.style.height = "auto";
      ta.style.height = Math.min(ta.scrollHeight, 160) + "px";
    }
  };

  const saveSession = async (msgs: Message[]) => {
    const title = msgs[0]?.content.slice(0, 60) || "New Chat";
    if (currentSessionId) {
      await fetch("/api/chat-sessions", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: currentSessionId, title, messages: msgs }),
      });
    } else {
      const res = await fetch("/api/chat-sessions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title, messages: msgs }),
      });
      const session = await res.json();
      setCurrentSessionId(session.id);
    }
    const res = await fetch("/api/chat-sessions");
    setSessions(await res.json());
  };

  const sendMessage = async () => {
    if (!input.trim() || loading) return;

    const provider = localStorage.getItem("mmam-provider") || "gemini";
    const apiKey = provider === "gemini"
      ? localStorage.getItem("mmam-gemini-key") || ""
      : localStorage.getItem("mmam-api-key") || "";
    if (!apiKey) {
      alert("Please set your API key in Settings first.");
      return;
    }

    const userMessage: Message = { role: "user", content: input.trim() };
    const newMessages = [...messages, userMessage];
    setMessages(newMessages);
    setInput("");
    setLoading(true);
    setStreaming("");

    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
    }

    try {
      const systemPrompt = localStorage.getItem("mmam-system-prompt") || "";
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: newMessages,
          apiKey,
          provider,
          systemPrompt,
        }),
      });

      if (!res.ok) {
        const error = await res.json();
        throw new Error(error.error || "API request failed");
      }

      const reader = res.body?.getReader();
      const decoder = new TextDecoder();
      let fullResponse = "";

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunk = decoder.decode(value, { stream: true });
          fullResponse += chunk;
          setStreaming(fullResponse);
        }
      }

      const finalMessages = [...newMessages, { role: "assistant" as const, content: fullResponse }];
      setMessages(finalMessages);
      setStreaming("");
      saveSession(finalMessages);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : "Something went wrong";
      setMessages([...newMessages, { role: "assistant", content: `Error: ${errorMsg}` }]);
      setStreaming("");
    } finally {
      setLoading(false);
    }
  };

  const newChat = () => {
    setMessages([]);
    setCurrentSessionId(null);
    setShowSessions(false);
  };

  const loadSession = (session: ChatSession) => {
    setMessages(session.messages);
    setCurrentSessionId(session.id);
    setShowSessions(false);
  };

  const saveSuggestion = async (content: string) => {
    await fetch("/api/suggestions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, category: "Strategy", source: "Chat conversation" }),
    });
    alert("Saved to Suggestions!");
  };

  return (
    <div className="flex h-full flex-col">
      {/* Chat header */}
      <div className="flex items-center justify-between border-b border-border px-4 py-3 sm:px-6">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowSessions(!showSessions)}
            className="rounded-lg bg-surface p-2 transition-colors hover:bg-surface-hover sm:hidden"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M20.25 7.5l-.625 10.632a2.25 2.25 0 01-2.247 2.118H6.622a2.25 2.25 0 01-2.247-2.118L3.75 7.5M10 11.25h4M3.375 7.5h17.25c.621 0 1.125-.504 1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125H3.375c-.621 0-1.125.504-1.125 1.125v1.5c0 .621.504 1.125 1.125 1.125z" />
            </svg>
          </button>
          <h1 className="text-lg font-semibold">Chat</h1>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowSessions(!showSessions)}
            className="hidden rounded-lg bg-surface px-3 py-2 text-sm font-medium text-muted transition-colors hover:bg-surface-hover hover:text-[var(--foreground)] sm:block"
          >
            History
          </button>
          <button
            onClick={newChat}
            className="rounded-lg bg-accent px-3 py-2 text-sm font-semibold text-white transition-colors hover:bg-accent-hover"
          >
            New Chat
          </button>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Sessions panel */}
        {showSessions && (
          <div className="absolute inset-0 z-30 bg-[var(--background)] sm:static sm:w-72 sm:border-r sm:border-border">
            <div className="flex items-center justify-between border-b border-border px-4 py-3 sm:hidden">
              <h2 className="font-semibold">Chat History</h2>
              <button onClick={() => setShowSessions(false)} className="rounded-lg p-2 text-muted hover:text-[var(--foreground)]">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-5">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="overflow-y-auto p-3">
              {sessions.length === 0 ? (
                <p className="p-4 text-center text-sm text-muted">No conversations yet</p>
              ) : (
                <div className="space-y-1">
                  {sessions.map((s) => (
                    <button
                      key={s.id}
                      onClick={() => loadSession(s)}
                      className={`w-full rounded-lg px-3 py-3 text-left transition-colors ${
                        currentSessionId === s.id
                          ? "bg-accent/15 text-accent"
                          : "text-muted hover:bg-surface-hover hover:text-[var(--foreground)]"
                      }`}
                    >
                      <p className="truncate text-sm font-medium">{s.title}</p>
                      <p className="mt-0.5 text-xs opacity-60">{s.created_at ? new Date(s.created_at).toLocaleDateString("en-IN") : ""}</p>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Messages area */}
        <div className="flex flex-1 flex-col">
          <div className="flex-1 overflow-y-auto px-4 py-6 sm:px-6">
            {messages.length === 0 && !streaming ? (
              <div className="flex h-full flex-col items-center justify-center text-center">
                <div className="mb-6 flex size-16 items-center justify-center rounded-2xl bg-accent/15 text-accent">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-8">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.455 2.456L21.75 6l-1.036.259a3.375 3.375 0 00-2.455 2.456zM16.894 20.567L16.5 21.75l-.394-1.183a2.25 2.25 0 00-1.423-1.423L13.5 18.75l1.183-.394a2.25 2.25 0 001.423-1.423l.394-1.183.394 1.183a2.25 2.25 0 001.423 1.423l1.183.394-1.183.394a2.25 2.25 0 00-1.423 1.423z" />
                  </svg>
                </div>
                <h2 className="text-xl font-semibold">What&apos;s on your mind?</h2>
                <p className="mt-2 max-w-sm text-sm text-muted">
                  Ask about business strategy, personality development, client acquisition, or anything else.
                </p>
                <div className="mt-6 flex flex-wrap justify-center gap-2">
                  {[
                    "How should I dress for a business meeting?",
                    "Coach me on my body language",
                    "How do I make a powerful first impression?",
                    "Help me prepare to pitch a client",
                  ].map((q) => (
                    <button
                      key={q}
                      onClick={() => {
                        setInput(q);
                        textareaRef.current?.focus();
                      }}
                      className="rounded-lg border border-border bg-surface px-3 py-2 text-sm text-muted transition-colors hover:border-accent/30 hover:text-[var(--foreground)]"
                    >
                      {q}
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              <div className="mx-auto max-w-3xl space-y-6">
                {messages.map((m, i) => (
                  <div key={i} className={`flex gap-3 ${m.role === "user" ? "justify-end" : ""}`}>
                    {m.role === "assistant" && (
                      <div className="mt-1 flex size-8 shrink-0 items-center justify-center rounded-full bg-accent/15 text-xs font-bold text-accent">
                        AI
                      </div>
                    )}
                    <div
                      className={`max-w-[85%] rounded-2xl px-4 py-3 text-sm leading-relaxed sm:max-w-[75%] ${
                        m.role === "user"
                          ? "bg-accent text-white"
                          : "bg-surface"
                      }`}
                    >
                      <p className="whitespace-pre-wrap">{m.content}</p>
                      {m.role === "assistant" && (
                        <button
                          onClick={() => saveSuggestion(m.content)}
                          className="mt-2 flex items-center gap-1 rounded-md px-2 py-1 text-xs text-muted transition-colors hover:bg-accent/10 hover:text-accent"
                        >
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-3.5">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M17.593 3.322c1.1.128 1.907 1.077 1.907 2.185V21L12 17.25 4.5 21V5.507c0-1.108.806-2.057 1.907-2.185a48.507 48.507 0 0 1 11.186 0Z" />
                          </svg>
                          Save
                        </button>
                      )}
                    </div>
                    {m.role === "user" && (
                      <div className="mt-1 flex size-8 shrink-0 items-center justify-center rounded-full bg-accent/20 text-xs font-bold text-accent">
                        AK
                      </div>
                    )}
                  </div>
                ))}
                {streaming && (
                  <div className="flex gap-3">
                    <div className="mt-1 flex size-8 shrink-0 items-center justify-center rounded-full bg-accent/15 text-xs font-bold text-accent">
                      AI
                    </div>
                    <div className="max-w-[85%] rounded-2xl bg-surface px-4 py-3 text-sm leading-relaxed sm:max-w-[75%]">
                      <p className="whitespace-pre-wrap">{streaming}</p>
                      <span className="ml-1 inline-block size-2 animate-pulse rounded-full bg-accent" />
                    </div>
                  </div>
                )}
                <div ref={messagesEndRef} />
              </div>
            )}
          </div>

          {/* Input area — fixed at bottom, large touch targets for mobile */}
          <div className="border-t border-border bg-[var(--background)] p-3 sm:p-4">
            <div className="mx-auto flex max-w-3xl gap-2 sm:gap-3">
              <textarea
                ref={textareaRef}
                value={input}
                onChange={(e) => {
                  setInput(e.target.value);
                  autoResize();
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    sendMessage();
                  }
                }}
                placeholder="Type your message..."
                rows={1}
                className="min-h-[44px] flex-1 resize-none rounded-xl border border-border bg-surface px-4 py-3 text-sm placeholder:text-muted focus:border-accent focus:outline-none"
              />
              <button
                onClick={sendMessage}
                disabled={loading || !input.trim()}
                className="flex size-11 shrink-0 items-center justify-center rounded-xl bg-accent text-white transition-colors hover:bg-accent-hover disabled:opacity-40 sm:size-auto sm:px-5"
              >
                {loading ? (
                  <svg className="size-5 animate-spin" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                ) : (
                  <svg viewBox="0 0 24 24" fill="currentColor" className="size-5">
                    <path d="M3.478 2.404a.75.75 0 0 0-.926.941l2.432 7.905H13.5a.75.75 0 0 1 0 1.5H4.984l-2.432 7.905a.75.75 0 0 0 .926.94 60.519 60.519 0 0 0 18.445-8.986.75.75 0 0 0 0-1.218A60.517 60.517 0 0 0 3.478 2.404Z" />
                  </svg>
                )}
                <span className="ml-2 hidden sm:inline">{loading ? "Thinking..." : "Send"}</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
