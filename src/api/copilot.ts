export interface CopilotCodeBlockData {
  file: string;
  code: string;
  lang: string;
}

export interface CopilotChatResponseData {
  message: string;
  code_block?: CopilotCodeBlockData | null;
  is_fallback: boolean;
  provider: string;
  model: string;
  finding_id?: number | null;
}

export interface CopilotStatusResponseData {
  configured_provider: string;
  configured_model: string;
  provider_available: boolean;
  fallback_available: boolean;
  latency_ms?: number | null;
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

export const fetchCopilotStatus = async (): Promise<CopilotStatusResponseData> => {
  try {
    const res = await fetch(`${API_BASE_URL}/api/copilot/status`);
    if (!res.ok) {
      throw new Error(`Copilot status returned code ${res.status}`);
    }
    return res.json();
  } catch (err) {
    return {
      configured_provider: 'ollama',
      configured_model: 'qwen2.5-coder:1.5b',
      provider_available: false,
      fallback_available: true,
      latency_ms: null,
    };
  }
};

export const sendCopilotChat = async (
  message: string,
  findingId?: number | null,
  stream: boolean = false
): Promise<CopilotChatResponseData> => {
  const payload = {
    finding_id: findingId || undefined,
    message,
    stream,
  };

  const res = await fetch(`${API_BASE_URL}/api/copilot/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Copilot API error (${res.status}): ${errText}`);
  }

  return res.json();
};

export const streamCopilotChat = async (
  message: string,
  findingId: number | null | undefined,
  onToken: (token: string) => void,
  onComplete: () => void,
  onError: (err: Error) => void
): Promise<void> => {
  try {
    const response = await fetch(`${API_BASE_URL}/api/copilot/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        finding_id: findingId || undefined,
        message,
        stream: true,
      }),
    });

    if (!response.ok) {
      throw new Error(`Streaming failed with status ${response.status}`);
    }

    if (!response.body) {
      throw new Error('Response body is unreadable');
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n\n');
      buffer = lines.pop() || '';

      for (const block of lines) {
        if (!block.trim()) continue;
        const eventMatch = block.match(/event:\s*(\w+)/);
        const dataMatch = block.match(/data:\s*(.+)/);

        if (eventMatch && dataMatch) {
          const eventType = eventMatch[1];
          try {
            const dataObj = JSON.parse(dataMatch[1]);
            if (eventType === 'token' && dataObj.delta) {
              onToken(dataObj.delta);
            } else if (eventType === 'done') {
              onComplete();
              return;
            } else if (eventType === 'error') {
              onError(new Error(dataObj.error || 'Stream error'));
              return;
            }
          } catch (e) {
            // Ignore parse errors for partial chunks
          }
        }
      }
    }
    onComplete();
  } catch (err: any) {
    onError(err instanceof Error ? err : new Error(String(err)));
  }
};
