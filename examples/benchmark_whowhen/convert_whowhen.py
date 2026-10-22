"""Convert Who&When (Agents_Failure_Attribution, ICML 2025, MIT) trajectories
to Pramana's native trace schema. Each file is one multi-agent task = one session."""

import json
import sys
from pathlib import Path

ROOT_ROLES = {"human", "user"}
TOOL_ROLES = {"tool", "function", "tool_result", "observation"}


def convert(traj: dict, sid: str) -> list[dict]:
    history = traj.get("history", [])
    events, root = [], None
    for i, m in enumerate(history):
        role = (m.get("role") or "").lower()
        name = m.get("name") or m.get("role") or "agent"
        content = m.get("content") or ""
        eid = f"{sid}-e{i:03d}"
        if role in ROOT_ROLES and root is None:
            root = eid
            events.append(
                {
                    "event_id": eid,
                    "ts": "",
                    "session_id": sid,
                    "type": "user_request",
                    "actor": "user:caller",
                    "parent_id": None,
                    "content": content,
                }
            )
        elif role in TOOL_ROLES:
            events.append(
                {
                    "event_id": eid,
                    "ts": "",
                    "session_id": sid,
                    "type": "tool_result",
                    "actor": f"system:{name}",
                    "parent_id": root,
                    "result": content,
                }
            )
        else:
            events.append(
                {
                    "event_id": eid,
                    "ts": "",
                    "session_id": sid,
                    "type": "model_output",
                    "actor": f"agent:{name}",
                    "parent_id": root,
                    "reasoning": content,
                    "content": content[:400],
                }
            )
    return events


def main(src_dir: str, out: str):
    files = sorted(Path(src_dir).glob("*.json"), key=lambda p: p.stem)
    all_events, labels = [], []
    for f in files:
        traj = json.loads(f.read_text())
        sid = f"WW-{f.stem}"
        all_events += convert(traj, sid)
        labels.append(
            {
                "session": sid,
                "mistake_agent": traj.get("mistake_agent"),
                "mistake_step": traj.get("mistake_step"),
                "mistake_reason": (traj.get("mistake_reason") or "")[:120],
            }
        )
    Path(out).write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in all_events) + "\n")
    Path(out + ".labels.json").write_text(json.dumps(labels, indent=2))
    print(f"{len(files)} trajectories -> {len(all_events)} events -> {out}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
