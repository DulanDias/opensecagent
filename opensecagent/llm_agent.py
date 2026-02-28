# OpenSecAgent - LLM Agent: suggest commands → execute → feed back → repeat
from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any

logger = __import__("logging").getLogger("opensecagent.llm_agent")

# Allowed commands: (regex pattern, allow_shell). Shell=false means exec-style (no shell expansion).
ALLOWED_COMMANDS = [
    # Read-only / scan
    (r"^apt\s+list\s+", False),
    (r"^apt-cache\s+", False),
    (r"^dpkg\s+-[lL]", False),
    (r"^rpm\s+-qa", False),
    (r"^ss\s+-", False),
    (r"^netstat\s+-", False),
    (r"^docker\s+ps", False),
    (r"^docker\s+images", False),
    (r"^docker\s+inspect\s+", False),
    (r"^cat\s+/etc/", False),
    (r"^ls\s+-la\s+/etc/", False),
    (r"^getent\s+", False),
    (r"^systemctl\s+list-units", False),
    (r"^systemctl\s+status\s+", False),
    (r"^id\s+", False),
    (r"^whoami$", False),
    (r"^uname\s+-a$", False),
    (r"^hostname$", False),
    # Remediation (safe)
    (r"^apt\s+install\s+-y\s+", False),
    (r"^apt\s+upgrade\s+-y$", False),
    (r"^apt-get\s+install\s+-y\s+", False),
    (r"^apt-get\s+upgrade\s+-y$", False),
    (r"^docker\s+stop\s+", False),
    (r"^docker\s+rm\s+-f\s+", False),
    (r"^ufw\s+deny\s+", False),
    (r"^iptables\s+-I\s+INPUT\s+", False),
]


def is_command_allowed(cmd: str) -> bool:
    """Check if command is in whitelist."""
    cmd = cmd.strip()
    if not cmd or cmd.startswith("#"):
        return False
    for pattern, _ in ALLOWED_COMMANDS:
        if re.search(pattern, cmd, re.I):
            return True
    return False


def parse_llm_commands(response: str) -> tuple[list[dict[str, str]], bool, dict[str, Any] | None]:
    """
    Parse LLM response. Returns (commands, done, finding).
    finding is set when vulnerability_found is true (scan mode).
    """
    commands: list[dict[str, str]] = []
    done = False
    finding: dict[str, Any] | None = None
    try:
        json_match = re.search(r"\{[\s\S]*\}", response)
        if json_match:
            data = json.loads(json_match.group())
            commands = data.get("commands", [])
            if isinstance(commands, list):
                commands = [c if isinstance(c, dict) else {"cmd": str(c), "reason": ""} for c in commands]
            else:
                commands = []
            done = bool(data.get("done", False))
            if data.get("vulnerability_found") and isinstance(data.get("finding"), dict):
                finding = data["finding"]
    except (json.JSONDecodeError, KeyError, TypeError):
        pass
    if not commands:
        for block in re.findall(r"```(?:bash|sh)?\s*\n(.*?)```", response, re.DOTALL):
            for line in block.strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    commands.append({"cmd": line, "reason": "from markdown"})
    return commands, done, finding


class LLMAgent:
    """Agent loop: LLM suggests commands → execute (with optional run_as) → feed back → repeat."""

    def __init__(self, config: dict[str, Any], activity_logger: Any = None) -> None:
        self._full_config = config
        self.config = config.get("llm", {})
        agent_cfg = config.get("llm_agent", {})
        self._enabled = agent_cfg.get("enabled", False) or self.config.get("enabled", False)
        self._api_key = self.config.get("api_key", "")
        self._provider = (self.config.get("provider") or "openai").strip().lower()
        if self._provider not in ("openai", "anthropic"):
            self._provider = "openai"
        self._model = self.config.get("model", "gpt-4o-mini")
        self._model_scan = self.config.get("model_scan") or self._model
        self._model_resolve = self.config.get("model_resolve") or self._model
        self._base_url = self.config.get("base_url", "")
        self._max_iterations = agent_cfg.get("agent_max_iterations", 10) or self.config.get("agent_max_iterations", 10)
        self._redact_patterns = self.config.get("redact_patterns", ["password", "secret", "token", "key"])
        self._activity = activity_logger
        self._run_as = (config.get("execution", {}) or {}).get("run_as")

    def _get_model_for_mode(self, mode: str) -> str:
        """Select model by mode: scan uses cheaper model, resolve uses advanced model."""
        if (mode or "").strip().lower() == "resolve":
            return self._model_resolve
        return self._model_scan

    async def run_agent_loop(
        self,
        context: dict[str, Any],
        incident: Any | None = None,
        mode: str = "scan",
    ) -> dict[str, Any]:
        """
        Run agent loop. mode: "scan" (discover only) or "resolve" (remediate).
        Returns summary plus "finding" (if scan found vulnerability) and "actions_taken" for resolve.
        """
        if not self._enabled or not self._api_key:
            return {"iterations": 0, "commands_executed": 0, "summary": "LLM agent disabled"}

        from opensecagent.threat_registry import load_threats_for_context
        from opensecagent.prompts import get_system_prompt

        threat_context = load_threats_for_context(self._full_config, limit=15)
        system_prompt = get_system_prompt(mode, threat_context, self._full_config)
        messages: list[dict[str, str]] = [{"role": "system", "content": system_prompt}]
        current_model = self._get_model_for_mode(mode)

        user_context = f"System context:\n{json.dumps(context, indent=2)[:8000]}\n"
        if incident:
            user_context += f"\nIncident to address: {incident.title}\n{incident.narrative}\n"
        if mode == "scan":
            user_context += "\nSuggest commands to SCAN only. Return JSON. If you identify a vulnerability, set vulnerability_found: true and include finding."
        else:
            user_context += "\nSuggest commands to RESOLVE the issue. Return JSON only."
        messages.append({"role": "user", "content": user_context})

        total_commands = 0
        iteration = 0
        finding: dict[str, Any] | None = None
        actions_taken: list[str] = []

        while iteration < self._max_iterations:
            iteration += 1
            t0 = time.perf_counter()
            try:
                response = await self._call_llm(messages, model=current_model)
            except Exception as e:
                logger.warning("LLM agent call failed: %s", e)
                if self._activity:
                    await self._activity.log_llm_call(
                        "agent_loop", None, None, time.perf_counter() - t0, False, str(e)
                    )
                break

            if self._activity:
                await self._activity.log_llm_call(
                    "agent_loop", None, None, time.perf_counter() - t0, True, None
                )

            commands, done, parsed_finding = parse_llm_commands(response)
            if parsed_finding:
                finding = parsed_finding
            executed = 0

            for c in commands:
                cmd = c.get("cmd", "").strip()
                if not cmd or not is_command_allowed(cmd):
                    continue
                result = await self._execute_command(cmd)
                executed += 1
                total_commands += 1
                actions_taken.append(cmd)
                messages.append({"role": "assistant", "content": response})
                result_text = f"Command: {cmd}\nExit: {result['exit_code']}\nStdout: {result['stdout'][:1500]}\nStderr: {result['stderr'][:500]}"
                messages.append({"role": "user", "content": result_text})

            if self._activity:
                await self._activity.log_agent_iteration(
                    iteration, len(commands), executed, done, f"Executed {executed} commands"
                )

            if done or executed == 0:
                break

            messages.append({
                "role": "user",
                "content": "Based on the command outputs above, suggest next commands or set done: true. Return JSON only.",
            })

        out = {
            "iterations": iteration,
            "commands_executed": total_commands,
            "summary": f"Agent completed {iteration} iterations, executed {total_commands} commands",
        }
        if finding:
            out["finding"] = finding
        if actions_taken:
            out["actions_taken"] = actions_taken
        return out

    async def _execute_command(self, cmd: str) -> dict[str, Any]:
        """Execute a whitelisted command (with optional run_as)."""
        t0 = time.perf_counter()
        run_cmd = cmd
        if self._run_as:
            run_cmd = f"sudo -u {self._run_as} {cmd}"
        try:
            proc = await asyncio.create_subprocess_shell(
                run_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            exit_code = proc.returncode or 0
            out = stdout.decode("utf-8", errors="replace")
            err = stderr.decode("utf-8", errors="replace")
        except Exception as e:
            exit_code = -1
            out = ""
            err = str(e)
        duration = time.perf_counter() - t0

        if self._activity:
            await self._activity.log_command_execution(
                cmd, exit_code, out, err, duration, source="llm_agent"
            )

        return {"exit_code": exit_code, "stdout": out, "stderr": err}

    async def _call_llm(self, messages: list[dict[str, str]], model: str | None = None) -> str:
        from opensecagent.llm_client import chat
        model = model or self._model
        return await chat(
            provider=self._provider,
            model=model,
            messages=messages,
            max_tokens=self.config.get("max_tokens", 2048),
            api_key=self._api_key,
            base_url=self._base_url or None,
        )
