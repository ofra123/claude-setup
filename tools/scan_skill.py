"""Layer-1 sanitization scan for a skill folder.

Exit codes: 0 = pass, 2 = HIGH findings need human/LLM review, 1 = CRITICAL, block.

Usage: python scan_skill.py path/to/skill [--allow-domain example.com ...]
Catches crude injection and payload tricks cheaply. It is NOT a complete
defense: pair it with adversarial LLM review, human review, and least privilege.
"""
import argparse, base64, binascii, pathlib, re, sys, unicodedata

# Zero-width, bidi-override, word-joiner, BOM and soft-hyphen characters, plus
# Unicode "tag" characters (U+E0000-E007F), which can smuggle invisible text.
INVISIBLE = re.compile(
    "[\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufeff\\u00ad]"
    "|[\\U000e0000-\\U000e007f]"
)
HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
B64_BLOB = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
URL = re.compile(r"https?://([A-Za-z0-9.-]+)", re.I)
# Phrase rules can't tell *mentioning* an attack from *doing* one, so in visible
# text they are HIGH (review). The same phrase in hidden content is CRITICAL.
PHRASES = {"instruction override", "concealment from user"}
# Docs often *mention* .env or eval(); scripts actually *doing* it is the risk.
CODE_RISKS = {"credential access", "dynamic execution"}
RULES = [  # (severity, label, pattern)
    ("CRITICAL", "instruction override",
     r"ignore (all |any )?(previous|prior|above) (instructions|rules)"
     r"|disregard (the |your )?(system|previous)|you are now\b|new system prompt"),
    ("CRITICAL", "concealment from user",
     r"(do not|don't|never) (tell|inform|show|mention)[^.\n]{0,40}\buser\b"
     r"|without (asking|telling|informing|notifying) (the )?user"
     r"|without (the )?user'?s? (knowledge|consent|confirmation)"),
    ("CRITICAL", "fetch-and-execute",
     r"(curl|wget)[^\n|]*\|\s*(ba|z)?sh\b"
     r"|(iwr|invoke-webrequest|irm)[^\n|]*\|\s*iex"
     r"|powershell[^\n]*-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}"),
    ("CRITICAL", "security disablement",
     r"(disable|turn off|bypass)[^.\n]{0,30}(sandbox|permission|security|antivirus|defender|firewall)"
     r"|dangerously-?skip-?permissions"),
    ("HIGH", "credential access",
     r"~?[/\\]\.(ssh|aws|kube|docker)\b|id_rsa|\.env\b|credentials\.json"
     r"|(aws_secret|api[_-]?key|token)\s*[:=]"),
    ("HIGH", "dynamic execution",
     r"\beval\s*\(|\bexec\s*\(|atob\s*\(|base64\s+(-d|--decode)|FromBase64String"),
]
# Checked against the frontmatter description only: the manipulation target.
PERSUASIVE = re.compile(
    r"always (use|prefer|choose) this|instead of (any )?other skills"
    r"|(most )?(official|trusted|preferred) skill", re.I)
DESCRIPTION = re.compile(r"^description:\s*(.+)$", re.M)
BINARY_EXT = {".exe", ".dll", ".so", ".dylib", ".bin", ".zip", ".7z", ".rar",
              ".tar", ".gz", ".jar", ".pyc"}


def frontmatter(text: str) -> str:
    """Return the YAML frontmatter block of a SKILL.md, or '' if absent."""
    if not text.startswith("---"):
        return ""
    end = text.find("\n---", 3)
    return text[3:end] if end != -1 else ""


def scan(root: pathlib.Path, allowed: set[str]) -> list[tuple[str, str, str]]:
    out = []

    def add(sev, where, msg):
        if (sev, where, msg) not in out:  # report each distinct finding once
            out.append((sev, where, msg))

    for f in sorted(root.rglob("*")):
        rel = f.relative_to(root).as_posix()
        if f.is_symlink():
            add("CRITICAL", rel, "symlink (may point outside the skill)")
            continue
        if not f.is_file():
            continue
        if f.suffix.lower() in BINARY_EXT:
            add("CRITICAL", rel, "binary or archive file")
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            add("HIGH", rel, "not valid UTF-8 text")
            continue

        for m in INVISIBLE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            add("CRITICAL", f"{rel}:{line}", f"invisible/bidi/tag char U+{ord(m.group()):04X}")
        if unicodedata.normalize("NFKC", text) != text:
            add("MEDIUM", rel, "text changes under NFKC normalization (look-alike characters?)")

        if rel == "SKILL.md":
            d = DESCRIPTION.search(frontmatter(text))
            p = PERSUASIVE.search(d.group(1)) if d else None
            if p:
                add("MEDIUM", rel, f"persuasive description: {p.group()!r}")

        if f.suffix.lower() == ".md":  # comments are invisible once markdown renders
            for m in HTML_COMMENT.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                add("MEDIUM", f"{rel}:{line}", "HTML comment (hidden from rendered view)")

        is_md = f.suffix.lower() == ".md"
        hidden = [m.group() for m in HTML_COMMENT.finditer(text)] if is_md else []
        for m in B64_BLOB.finditer(text):
            try:
                decoded = base64.b64decode(m.group(), validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            hidden.append(decoded)  # re-scan decoded payloads
            add("HIGH", rel, "base64 blob that decodes to text")

        visible = HTML_COMMENT.sub(" ", text) if is_md else text
        for sev, label, pat in RULES:
            vis_sev = ("HIGH" if label in PHRASES
                       else "MEDIUM" if label in CODE_RISKS and is_md else sev)
            for m in re.finditer(pat, visible, re.I):
                add(vis_sev, rel, f"{label}: {m.group()[:70]!r}")
            for chunk in hidden:  # a match inside hidden content is deliberate
                for m in re.finditer(pat, chunk, re.I):
                    add("CRITICAL", rel, f"{label} (hidden): {m.group()[:70]!r}")

        for m in URL.finditer(text):
            host = m.group(1).lower()
            if not any(host == d or host.endswith("." + d) for d in allowed):
                add("MEDIUM", rel, f"URL to non-allowlisted domain: {host}")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("skill_dir")
    ap.add_argument("--allow-domain", action="append", default=[])
    args = ap.parse_args()
    root = pathlib.Path(args.skill_dir)
    if not (root / "SKILL.md").is_file():
        sys.exit(f"{root}: no SKILL.md")
    findings = scan(root, set(args.allow_domain))
    for sev, where, msg in findings:
        print(f"{sev:8} {where}: {msg}")
    crit = sum(1 for s, _, _ in findings if s == "CRITICAL")
    high = sum(1 for s, _, _ in findings if s == "HIGH")
    print(f"\n{len(findings)} finding(s): {crit} critical, {high} high")
    sys.exit(1 if crit else 2 if high else 0)
