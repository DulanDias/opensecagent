# OpenSecAgent - LLM client: OpenAI and Anthropic with unified interface
from __future__ import annotations

from typing import Any


async def chat(
    provider: str,
    model: str,
    messages: list[dict[str, str]],
    max_tokens: int = 2048,
    api_key: str = "",
    base_url: str | None = None,
) -> str:
    """
    Send chat messages to OpenAI or Anthropic. Returns assistant text.
    messages: list of {"role": "system"|"user"|"assistant", "content": "..."}
    """
    provider = (provider or "openai").strip().lower()
    if provider not in ("openai", "anthropic"):
        provider = "openai"
    if not api_key or not model:
        return ""

    if provider == "anthropic":
        return await _chat_anthropic(model, messages, max_tokens, api_key)
    return await _chat_openai(model, messages, max_tokens, api_key, base_url)


async def _chat_openai(
    model: str,
    messages: list[dict[str, str]],
    max_tokens: int,
    api_key: str,
    base_url: str | None,
) -> str:
    from openai import AsyncOpenAI
    client = AsyncOpenAI(api_key=api_key, base_url=base_url or None)
    r = await client.chat.completions.create(
        model=model,
        messages=messages,
        max_tokens=max_tokens,
    )
    if r.choices:
        return (r.choices[0].message.content or "").strip()
    return ""


async def _chat_anthropic(
    model: str,
    messages: list[dict[str, str]],
    max_tokens: int,
    api_key: str,
) -> str:
    from anthropic import AsyncAnthropic
    # Anthropic: system is separate; messages are only user/assistant
    system = ""
    conv: list[dict[str, str]] = []
    for m in messages:
        role = (m.get("role") or "user").lower()
        content = (m.get("content") or "").strip()
        if role == "system":
            system = content
        else:
            if role not in ("user", "assistant"):
                role = "user"
            conv.append({"role": role, "content": content})
    if not conv:
        return ""
    client = AsyncAnthropic(api_key=api_key)
    kwargs: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": conv,
    }
    if system:
        kwargs["system"] = system
    r = await client.messages.create(**kwargs)
    if r.content and isinstance(r.content, list) and len(r.content) > 0:
        block = r.content[0]
        text = block.get("text", "") if isinstance(block, dict) else getattr(block, "text", "")
        return (text or "").strip()
    return ""
