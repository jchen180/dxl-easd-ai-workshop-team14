import argparse
import hashlib
import html as _html
import importlib
import importlib.util
import json
import re
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

from api_hackathon.ai import FixtureAI
from api_hackathon.artifacts import load_json, load_text

BOARD = Path("portal.json")
REPORT = Path("report.html")
REPORTS = Path("reports")
SUBMISSIONS = Path("submissions")

# Maps internal level key → (display name used in portal.json, max points)
LEVEL_META = {
    "L1": ("L1 Contract review", 20),
    "L2": ("L2 Test design", 25),
    "L3": ("L3 Incident diagnosis", 30),
    "L4": ("L4 Migration", 25),
}


# Expected answers are stored as short SHA-256 digests so reading this file
# does not reveal which AI claims are real.
L1_KEEP = ("c605de71af436b5a", "da274a300f615649", "39524b8d399dde43")
L1_DROP = "36e73b6fdda89207"
L2_KEEP = ("d898ffb428e06101", "f725a27eac2e7723", "e84a486e2e435f6f")
L2_DROP = "910b4cf5bb049642"
L3_CAUSE = "27cac5503836765c"
L4_KEEP = ("b5cf3bfedbd60b6a", "71098f3a1bdbaf90")
L4_DROP = "c43456edfb79b600"


def _digest(value) -> str:
    return hashlib.sha256(str(value).encode()).hexdigest()[:16]


def calculate(module) -> tuple[int, dict, list]:
    ai = FixtureAI()
    v1, v2 = load_json("openapi-v1.json"), load_json("openapi-v2.json")
    logs = load_text("incident.log")
    checks: list[dict] = []

    def chk(level: str, name: str, earned: int, max_pts: int, passed: bool, note: str = "") -> None:
        checks.append({"level": level, "name": name, "earned": earned,
                       "max": max_pts, "passed": passed, "note": note})

    # ── Level 1: contract review ──────────────────────────────────────────────
    findings = module.review_contract(v1, ai)
    ids = {_digest(item.get("id")) for item in findings}
    for n, fid in enumerate(L1_KEEP, 1):
        ok = fid in ids
        chk("L1", f"Supported finding {n} of {len(L1_KEEP)} kept", 5 if ok else 0, 5, ok,
            "A finding the spec supports was dropped")
    halluc_ok = L1_DROP not in ids
    chk("L1", "No unsupported findings included", 5 if halluc_ok else 0, 5, halluc_ok,
        "Drop any finding whose path, method or evidence pointer is not in the v1 spec")

    # ── Level 2: negative tests ───────────────────────────────────────────────
    cases = module.design_negative_tests(v1, ai)
    print("v1 paths:", {p: [m for m in i if m in {"get","put","post","delete","patch","options","head","trace"}]
                    for p, i in v1["paths"].items()})
    # for c in cases:
    #     print(_digest(c["name"]) == L2_DROP, c["method"], c["path"], c["expected_status"], "|", c["name"])
    names = {_digest(item.get("name")) for item in cases}
    for n, tname in enumerate(L2_KEEP, 1):
        ok = tname in names
        chk("L2", f"Valid test case {n} of {len(L2_KEEP)} kept", 5 if ok else 0, 5, ok,
            "A test case for a real route with an accepted status code was dropped")
    invented_ok = L2_DROP not in names
    chk("L2", "No tests for non-existent endpoints", 5 if invented_ok else 0, 5, invented_ok,
        "Drop any test case whose path and method are not in the v1 spec")
    required = {"name", "method", "path", "input", "expected_status"}
    all_valid = bool(cases) and all(required <= set(case.keys()) for case in cases)
    chk("L2", "All test cases have required fields", 5 if all_valid else 0, 5, all_valid,
        f"Each case must include: {', '.join(sorted(required))}")

    # ── Level 3: incident diagnosis ───────────────────────────────────────────
    diagnosis = module.diagnose_incident(logs, ai)
    words = re.findall(r"[a-z0-9]+", diagnosis.get("cause", "").lower())
    pool_ok = any(_digest(word) == L3_CAUSE for word in words)
    evidence_items = diagnosis.get("evidence", [])
    evid_ok = bool(evidence_items) and all(item in logs for item in evidence_items)
    chk("L3", "Diagnosis names the cause the log supports", 20 if pool_ok else 0, 20, pool_ok,
        f"Cause returned: {diagnosis.get('cause', '(none)')!r}. Return the diagnosis whose evidence is all in incident.log")
    chk("L3", "All evidence lines appear in logs", 10 if evid_ok else 0, 10, evid_ok,
        "Every string in diagnosis['evidence'] must appear verbatim in incident.log")

    # ── Level 4: migration review ─────────────────────────────────────────────
    changes = module.review_migration(v1, v2, ai)
    change_ids = {_digest(item.get("id")) for item in changes}
    for n, cid in enumerate(L4_KEEP, 1):
        ok = cid in change_ids
        chk("L4", f"Confirmed breaking change {n} of {len(L4_KEEP)} kept", 10 if ok else 0, 10, ok,
            "A change that the two specs really show was dropped")
    false_ok = L4_DROP not in change_ids
    chk("L4", "No unverified changes included", 5 if false_ok else 0, 5, false_ok,
        "Drop any claimed change that a direct comparison of v1 and v2 does not confirm")

    level_points = {
        display: sum(c["earned"] for c in checks if c["level"] == lk)
        for lk, (display, _) in LEVEL_META.items()
    }
    return sum(level_points.values()), level_points, checks


# ── HTML report ───────────────────────────────────────────────────────────────

def _report_html(team: str, score: int, levels: dict, checks: list, ts: str) -> str:
    max_score = sum(lmax for _, lmax in LEVEL_META.values())
    color = "#16a34a" if score >= max_score * 0.8 else "#d97706" if score >= max_score * 0.5 else "#dc2626"
    pct = round(score / max_score * 100) if max_score else 0

    cards = ""
    for lk, (lname, lmax) in LEVEL_META.items():
        lc = [c for c in checks if c["level"] == lk]
        earned = sum(c["earned"] for c in lc)
        lpct = round(earned / lmax * 100) if lmax else 0

        items = ""
        for c in lc:
            cls = "pass" if c["passed"] else "fail"
            icon = "✅" if c["passed"] else "❌"
            note = (f'<div class="note">{_html.escape(c["note"])}</div>'
                    if c.get("note") and not c["passed"] else "")
            pts_color = "green" if c["passed"] else "red"
            items += f"""
          <li class="{cls}">
            <span class="icon">{icon}</span>
            <div class="body"><div class="cname">{_html.escape(c["name"])}</div>{note}</div>
            <span class="pts {pts_color}">{c['earned']}/{c['max']}</span>
          </li>"""

        cards += f"""
      <div class="card">
        <div class="lh">
          <span class="ltitle">{_html.escape(lname)}</span>
          <span class="lscore">{earned} / {lmax} pts</span>
        </div>
        <div class="lbar"><div class="lbar-fill" style="width:{lpct}%"></div></div>
        <ul class="checks">{items}
        </ul>
      </div>"""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Score Report – {_html.escape(team)}</title>
  <style>
    :root{{--bg:#f8fafc;--card:#fff;--border:#e2e8f0;--sub:#64748b;--bar:#e2e8f0;--accent:#2563eb}}
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:#0f172a;padding:24px 16px}}
    .wrap{{max-width:780px;margin:0 auto}}
    header{{text-align:center;padding:32px 0 28px}}
    .label{{font-size:.78rem;text-transform:uppercase;letter-spacing:.1em;color:var(--sub);font-weight:600}}
    .tname{{font-size:2rem;font-weight:700;margin:6px 0 20px;word-break:break-word}}
    .big-score{{font-size:4rem;font-weight:800;color:{color};line-height:1}}
    .big-score span{{font-size:1.8rem;color:var(--sub);font-weight:400}}
    .bar-wrap{{background:var(--bar);border-radius:999px;height:14px;max-width:500px;margin:14px auto 8px;overflow:hidden}}
    .bar-fill{{height:100%;border-radius:999px;background:linear-gradient(90deg,#2563eb,#7c3aed);width:{pct}%}}
    .ts{{font-size:.82rem;color:var(--sub);margin-top:8px}}
    .cards{{display:grid;gap:16px;margin-top:24px}}
    .card{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px 22px}}
    .lh{{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;gap:8px}}
    .ltitle{{font-size:1rem;font-weight:600}}
    .lscore{{font-size:.9rem;font-weight:700;color:var(--accent);white-space:nowrap}}
    .lbar{{background:var(--bar);border-radius:999px;height:5px;margin-bottom:14px;overflow:hidden}}
    .lbar-fill{{height:100%;border-radius:999px;background:var(--accent)}}
    .checks{{list-style:none;display:flex;flex-direction:column;gap:7px}}
    .checks li{{display:flex;align-items:flex-start;gap:10px;padding:9px 12px;border-radius:8px;font-size:.88rem}}
    .pass{{background:#dcfce7}}.fail{{background:#fee2e2}}
    .icon{{line-height:1.5;flex-shrink:0}}
    .body{{flex:1}}
    .cname{{font-weight:500}}
    .note{{color:#7f1d1d;font-size:.8rem;margin-top:3px;line-height:1.4}}
    .pts{{font-weight:700;font-size:.88rem;white-space:nowrap;padding-top:2px;flex-shrink:0}}
    .green{{color:#16a34a}}.red{{color:#dc2626}}
    .back{{display:inline-block;margin-bottom:20px;color:var(--accent);font-size:.9rem;text-decoration:none}}
    .back:hover{{text-decoration:underline}}
    @media(max-width:500px){{.big-score{{font-size:3rem}}}}
  </style>
</head>
<body>
  <div class="wrap">
    <a class="back" href="http://localhost:8081/progress">← Progress page</a>
    <header>
      <div class="label">Score Report</div>
      <div class="tname">{_html.escape(team)}</div>
      <div class="big-score">{score}<span> / {max_score}</span></div>
      <div class="bar-wrap"><div class="bar-fill"></div></div>
      <div class="ts">Scored {_html.escape(ts)}</div>
    </header>
    <div class="cards">{cards}
    </div>
  </div>
</body>
</html>"""


# ── Module loading ────────────────────────────────────────────────────────────

def load_module(path: Path):
    """Load a workshop.py (or any .py) from an arbitrary file path."""
    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(f"No such file: {path}")
    # Unique name so multiple team files can be loaded in one process
    mod_name = f"_submission_{path.parent.name}_{path.stem}_{id(path)}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module


def resolve_module(file: Path | None):
    if file is not None:
        return load_module(file)
    return importlib.import_module("api_hackathon.workshop")


def discover_submissions(root: Path) -> list[tuple[str, Path]]:
    """Find team workshop files under submissions/.

    Expected layout:
        submissions/
          Team Alpha/workshop.py
          Team Beta/workshop.py
    """
    if not root.is_dir():
        return []
    found: list[tuple[str, Path]] = []
    for child in sorted(root.iterdir(), key=lambda p: p.name.lower()):
        if child.name.startswith(".") or child.name.startswith("_"):
            continue
        if child.is_dir():
            workshop = child / "workshop.py"
            if workshop.is_file():
                found.append((child.name, workshop))
        elif child.suffix == ".py" and child.name != "README.py":
            found.append((child.stem, child))
    return found


# ── Persistence ───────────────────────────────────────────────────────────────

def update_board(team: str, score: int, levels: dict, checks: list) -> str:
    board = json.loads(BOARD.read_text()) if BOARD.exists() else []
    board = [e for e in board if e["team"] != team]
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    board.append({"team": team, "score": score, "levels": levels,
                  "checks": checks, "updated": ts})
    board.sort(key=lambda e: (-e["score"], e["updated"]))
    BOARD.write_text(json.dumps(board, indent=2), encoding="utf-8")
    return ts


def write_report(team: str, score: int, levels: dict, checks: list, ts: str,
                 path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_report_html(team, score, levels, checks, ts), encoding="utf-8")
    return path


def score_one(team: str, module, report_path: Path) -> tuple[int, dict, list]:
    score, levels, checks = calculate(module)
    ts = update_board(team, score, levels, checks)
    write_report(team, score, levels, checks, ts, report_path)
    max_score = sum(lmax for _, lmax in LEVEL_META.values())
    print(f"{team}: {score}/{max_score}")
    for level, points in levels.items():
        print(f"  {level}: {points}")
    print(f"  report → {report_path.resolve()}")
    return score, levels, checks


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Score workshop.py and update the shared progress dashboard."
    )
    parser.add_argument("--team", default="Local team",
                        help="Team name for a single-run score (ignored with --all).")
    parser.add_argument("--file", type=Path, default=None,
                        help="Score a specific workshop.py instead of the local one.")
    parser.add_argument("--all", action="store_true",
                        help="Score every team under submissions/ and update the board.")
    parser.add_argument("--submissions", type=Path, default=SUBMISSIONS,
                        help="Folder of team submissions (default: submissions/).")
    parser.add_argument("--open", action="store_true",
                        help="Open the HTML report in the browser after scoring.")
    args = parser.parse_args()

    if args.all:
        teams = discover_submissions(args.submissions)
        if not teams:
            print(f"No submissions found in {args.submissions.resolve()}/")
            print('Expected: submissions/"Team Name"/workshop.py')
            sys.exit(1)

        print(f"Scoring {len(teams)} team(s) from {args.submissions.resolve()} …\n")
        results: list[tuple[str, int | None, str | None]] = []
        for team, path in teams:
            try:
                module = load_module(path)
                safe = "".join(c if c.isalnum() or c in "-_ " else "_" for c in team).strip()
                report_path = REPORTS / f"{safe}.html"
                score, _, _ = score_one(team, module, report_path)
                results.append((team, score, None))
            except Exception as exc:
                print(f"{team}: ERROR — {exc}")
                traceback.print_exc()
                results.append((team, None, str(exc)))
            print()

        print("─" * 40)
        print("Leaderboard snapshot")
        ranked = sorted(
            ((t, s) for t, s, err in results if s is not None),
            key=lambda x: -x[1],
        )
        for i, (team, score) in enumerate(ranked, 1):
            print(f"  {i}. {team}: {score}/100")
        errors = [(t, e) for t, s, e in results if e]
        if errors:
            print("\nFailed:")
            for team, err in errors:
                print(f"  {team}: {err}")
        print(f"\nProgress file → {BOARD.resolve()}")
        print("Refresh http://localhost:8081/progress to see all teams.")
        return

    module = resolve_module(args.file)
    score_one(args.team, module, REPORT)

    if args.open:
        import webbrowser
        webbrowser.open(REPORT.resolve().as_uri())


if __name__ == "__main__":
    main()
