"""
Sanitize Engine v2.2 — Steganographic Defense for AI Agent Pipelines
5-pass Unicode sanitization + TOCTOU-safe file loading + auto-logging
Dependencies: pip install confusables (recommended)
Standalone: seam_contracts imports this, not the reverse.
Reviewed by: Claude (Anthropic) + Gemini 3.1 + Grok 4
"""
import unicodedata, hashlib, json, os, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from confusables import is_confusable
    HAS_CONFUSABLES_LIB = True
except ImportError:
    HAS_CONFUSABLES_LIB = False

def log_security_event(db_path, event_type, severity, details):
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE IF NOT EXISTS security_event (id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL, severity TEXT NOT NULL CHECK(severity IN ('INFO','WARNING','CRITICAL')), context TEXT, details_json TEXT, resolved INTEGER DEFAULT 0, detected_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("INSERT INTO security_event (event_type, severity, context, details_json) VALUES (?,?,?,?)",
                 (event_type, severity, details.get("context",""), json.dumps(details)))
    conn.commit(); conn.close()

DANGEROUS_CODEPOINTS = set()
DANGEROUS_CODEPOINTS.update({'\u200B','\u200C','\u200D','\u200E','\u200F','\uFEFF','\u2060','\u2061','\u2062','\u2063','\u2064','\u00AD','\u202A','\u202B','\u202C','\u202D','\u202E','\u2066','\u2067','\u2068','\u2069'})
for cp in range(0xE0000, 0xE0080): DANGEROUS_CODEPOINTS.add(chr(cp))
for cp in range(0xFE00, 0xFE10): DANGEROUS_CODEPOINTS.add(chr(cp))
for cp in range(0xE0100, 0xE01F0): DANGEROUS_CODEPOINTS.add(chr(cp))
for cp in range(0x1F3FB, 0x1F400): DANGEROUS_CODEPOINTS.add(chr(cp))

CONFUSABLE_SPACES = {'\u2000':' ','\u2001':' ','\u2002':' ','\u2003':' ','\u2004':' ','\u2005':' ','\u2006':' ','\u2007':' ','\u2008':' ','\u2009':' ','\u200A':' ','\u202F':' ','\u205F':' ','\u3000':' ','\u00A0':' '}
FALLBACK_HOMOGLYPHS = {'\u0430':'a','\u0435':'e','\u043E':'o','\u0440':'p','\u0441':'c','\u0443':'y','\u0445':'x','\u0456':'i','\u0455':'s','\u04BB':'h','\u0501':'d','\u051B':'q','\u051D':'w','\u0410':'A','\u0412':'B','\u0415':'E','\u041A':'K','\u041C':'M','\u041D':'H','\u041E':'O','\u0420':'P','\u0421':'C','\u0422':'T','\u0425':'X','\u03B1':'a','\u03BF':'o','\u03C1':'p','\u0391':'A','\u0392':'B','\u0395':'E','\u0396':'Z','\u0397':'H','\u039A':'K','\u039C':'M','\u039D':'N','\u039F':'O','\u03A1':'P','\u03A4':'T','\u03A7':'X'}

class UnicodeSecurityError(Exception): pass
_HASH_CACHE = {}

def sanitize_text(text, context="unknown", db_path=None):
    if not text: return text, {"detections":0,"max_severity":"CLEAN"}
    original_len = len(text); detections = []
    # P1: Strip dangerous
    stripped=0; has_inv=False; cleaned=[]
    for ch in text:
        if ch in DANGEROUS_CODEPOINTS:
            stripped+=1
            if ord(ch)<0x1F3FB: has_inv=True
        else: cleaned.append(ch)
    text=''.join(cleaned)
    if stripped: detections.append({"type":"dangerous_codepoints","count":stripped,"severity":"CRITICAL" if has_inv else "WARNING"})
    # P2: Whitespace
    sc=0
    for c,r in CONFUSABLE_SPACES.items():
        n=text.count(c)
        if n: text=text.replace(c,r); sc+=n
    if sc: detections.append({"type":"confusable_whitespace","count":sc,"severity":"WARNING"})
    # P3: NFKC
    nfkc=unicodedata.normalize('NFKC',text)
    if nfkc!=text:
        d=sum(1 for a,b in zip(text,nfkc) if a!=b)+abs(len(text)-len(nfkc))
        detections.append({"type":"nfkc","count":d,"severity":"INFO"}); text=nfkc
    # P4: Homoglyphs
    hc=0
    if HAS_CONFUSABLES_LIB:
        chars=list(text)
        for i,ch in enumerate(chars):
            if ord(ch)>127:
                r=is_confusable(ch,preferred_aliases=['latin'])
                if r:
                    for e in r:
                        if 'latin' in [a.lower() for a in e.get('alias',[])]:
                            chars[i]=e.get('c',ch); hc+=1; break
        text=''.join(chars)
    else:
        nc=[]
        for ch in text:
            if ch in FALLBACK_HOMOGLYPHS: nc.append(FALLBACK_HOMOGLYPHS[ch]); hc+=1
            else: nc.append(ch)
        text=''.join(nc)
    if hc: detections.append({"type":"homoglyphs","count":hc,"severity":"CRITICAL","lib":"confusables" if HAS_CONFUSABLES_LIB else "fallback"})
    # P5: Control chars
    cc=0; final=[]
    for ch in text:
        if unicodedata.category(ch).startswith('C') and ch not in '\n\r\t': cc+=1
        else: final.append(ch)
    text=''.join(final)
    if cc: detections.append({"type":"control_chars","count":cc,"severity":"WARNING"})
    sr={"CLEAN":0,"INFO":1,"WARNING":2,"CRITICAL":3}
    ms=max((d["severity"] for d in detections),default="CLEAN",key=lambda s:sr[s])
    report={"context":context,"engine":"v2.2","original_len":original_len,"cleaned_len":len(text),"modifications":original_len-len(text),"max_severity":ms,"confusables_lib":HAS_CONFUSABLES_LIB,"details":detections}
    if ms=="CRITICAL" and db_path: log_security_event(db_path,"stego_detected","CRITICAL",report)
    return text, report

def assert_clean(text, context="unknown", db_path=None):
    cleaned,report=sanitize_text(text,context,db_path)
    if report["max_severity"]=="CRITICAL": raise UnicodeSecurityError(f"CRITICAL in {context}: {report['modifications']} mods")
    return cleaned

def register_immutable(fp):
    _HASH_CACHE[os.path.abspath(fp)]=hashlib.sha256(open(fp,'rb').read()).hexdigest()

def register_workspace(workspace, patterns=None):
    patterns=patterns or["SOUL.md","IDENTITY.md","TOOLS.md","AGENTS.md","SECURITY.md","*.py","*.sh"]
    c=0
    for p in patterns:
        for f in Path(workspace).rglob(p):
            if f.is_file(): register_immutable(str(f)); c+=1
    return c

def load_immutable_file_safe(filepath, db_path=None):
    ap=os.path.abspath(filepath); raw=open(filepath,'rb').read()
    cur=hashlib.sha256(raw).hexdigest(); exp=_HASH_CACHE.get(ap)
    if exp and cur!=exp:
        if db_path: log_security_event(db_path,"file_tampered","CRITICAL",{"file":filepath,"expected":exp[:16],"actual":cur[:16]})
        raise UnicodeSecurityError(f"INTEGRITY: {filepath} modified. Expected {exp[:16]}, got {cur[:16]}")
    content=raw.decode('utf-8'); cleaned,report=sanitize_text(content,f"bootstrap:{os.path.basename(filepath)}",db_path)
    if report["max_severity"]=="CRITICAL": raise UnicodeSecurityError(f"CONTAMINATED: {filepath}")
    return cleaned

def safe_write(filepath, content, db_path=None):
    cleaned,report=sanitize_text(content,f"write:{os.path.basename(filepath)}",db_path)
    if report["max_severity"]=="CRITICAL": raise UnicodeSecurityError(f"Blocked write to {filepath}")
    with open(filepath,'w',encoding='utf-8') as f: f.write(cleaned)
    return report

def sanitize_sub_agent(output, name, db_path=None):
    cleaned,report=sanitize_text(output,f"sub_agent:{name}",db_path)
    if report["max_severity"]=="CRITICAL":
        return f"[SECURITY: '{name}' had {report['modifications']} hidden chars — sanitized]\n\n"+cleaned, report
    return cleaned, report

def verify_contract_text(contract):
    findings=[]
    def scan(val,path="root"):
        if isinstance(val,str):
            _,r=sanitize_text(val,f"contract:{path}")
            if r["max_severity"]!="CLEAN": findings.append({"path":path,"report":r})
        elif isinstance(val,dict):
            for k,v in val.items(): scan(k,f"{path}.key({k})"); scan(v,f"{path}.{k}")
        elif isinstance(val,list):
            for i,v in enumerate(val): scan(v,f"{path}[{i}]")
    scan(contract)
    return {"clean":len(findings)==0,"findings":findings}

if __name__=="__main__":
    import argparse,sys
    p=argparse.ArgumentParser(prog="sanitize_engine",description="Sanitize Engine v2.2")
    s=p.add_subparsers(dest="cmd")
    s.add_parser("check").add_argument("--file",required=True)
    dp=s.add_parser("deploy"); dp.add_argument("--workspace",default="."); dp.add_argument("--db",default="agent.db")
    a=p.parse_args()
    if a.cmd=="check":
        with open(a.file) as f: _,r=sanitize_text(f.read(),f"check:{a.file}")
        if r["max_severity"] in("CRITICAL","WARNING"): print(f"⚠️ {r['max_severity']}: {a.file}"); sys.exit(1)
        else: print(f"OK: {a.file}")
    elif a.cmd=="deploy":
        c=register_workspace(a.workspace); fails=0
        for fp in _HASH_CACHE:
            try: load_immutable_file_safe(fp,a.db); print(f"  OK: {os.path.basename(fp)}")
            except UnicodeSecurityError as e: print(f"  FAIL: {e}"); fails+=1
        print(f"\n{'⚠️ '+str(fails)+' failures' if fails else 'Clean. '+str(c)+' files verified.'}"); sys.exit(1 if fails else 0)
    else: p.print_help()
