import os, json, time, ipaddress, threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import requests
import numpy as np
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sklearn.ensemble import IsolationForest

TOKEN = os.getenv("COLLECTOR_TOKEN", "")
ORIGINS = [x.strip() for x in os.getenv("CORS_ORIGINS", "") .split(",") if x.strip()]
LOGS = {
    "zeek": os.getenv("ZEEK_CONN_LOG", "/var/log/zeek/current/conn.log"),
    "suricata": os.getenv("SURICATA_EVE_LOG", "/var/log/suricata/eve.json"),
    "cowrie": os.getenv("COWRIE_LOG", "/opt/cowrie/var/log/cowrie/cowrie.json"),
    "linux_auth": os.getenv("LINUX_AUTH_LOG", "/var/log/auth.log"),
}
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
app = FastAPI(title="SentinelMind Collector", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_credentials=False, allow_methods=["GET"], allow_headers=["Authorization","Content-Type"])
lock = threading.Lock()
EVENTS: list[dict[str, Any]] = []
DETECTIONS: list[dict[str, Any]] = []
MODEL = None
LAST_TRAIN = 0
MAX_EVENTS = 5000

def now(): return datetime.now(timezone.utc).isoformat()
def exists(path): return bool(path) and Path(path).is_file()
def safe_ts(value):
    try:
        if isinstance(value, (int,float)): return datetime.fromtimestamp(value, timezone.utc).isoformat()
        return datetime.fromisoformat(str(value).replace("Z","+00:00")).isoformat()
    except Exception: return now()
def add_event(e):
    e.setdefault("timestamp", now())
    e.setdefault("severity", "low")
    with lock:
        EVENTS.append(e)
        if len(EVENTS) > MAX_EVENTS: del EVENTS[:-MAX_EVENTS]
def parse_json_lines(path, sensor):
    if not exists(path): return
    try:
        with open(path, "r", errors="replace") as f:
            # Starter poll reads recent tail on each refresh; production should use a cursor/checkpoint.
            lines = f.readlines()[-100:]
        for line in lines:
            try: obj = json.loads(line)
            except Exception: continue
            if sensor == "suricata":
                if obj.get("event_type") not in ("alert","flow","ssh","anomaly","dns","http"): continue
                alert = obj.get("alert", {})
                src = obj.get("src_ip", "")
                add_event({"timestamp":safe_ts(obj.get("timestamp")), "title":alert.get("signature") or f"Suricata {obj.get('event_type','event')}", "src_ip":src, "severity": {"1":"critical","2":"high","3":"medium","4":"low"}.get(str(alert.get("severity","4")),"low"), "sensor":"Suricata", "category":alert.get("category",obj.get("event_type","network")), "description":f"{obj.get('proto','')} {obj.get('src_port','')} → {obj.get('dest_ip','')}:{obj.get('dest_port','')}"})
            elif sensor == "cowrie":
                et = obj.get("eventid","cowrie.event")
                if et in ("cowrie.session.connect","cowrie.login.failed","cowrie.login.success","cowrie.command.input","cowrie.session.closed"):
                    add_event({"timestamp":safe_ts(obj.get("timestamp")), "title":et.replace("cowrie.","").replace("."," ").title(), "src_ip":obj.get("src_ip",""), "severity":"high" if "login.success" in et or "command.input" in et else "medium", "sensor":"Cowrie", "category":"honeypot", "description":str(obj.get("input",""))[:180]})
def parse_zeek():
    path=LOGS["zeek"]
    if not exists(path): return
    try:
        with open(path,"r",errors="replace") as f: lines=f.readlines()[-100:]
        fields=[]
        for line in lines:
            if line.startswith("#fields"): fields=line.rstrip().split("\t")[1:]; continue
            if line.startswith("#") or not fields: continue
            vals=line.rstrip("\n").split("\t")
            if len(vals)!=len(fields): continue
            o=dict(zip(fields,vals))
            def num(k):
                try: return float(o.get(k,"0").replace("-","0"))
                except: return 0.0
            ts=safe_ts(num("ts"))
            duration=num("duration"); orig_bytes=num("orig_bytes"); resp_bytes=num("resp_bytes")
            orig_pkts=num("orig_pkts"); resp_pkts=num("resp_pkts")
            record={"timestamp":ts,"title":f"Zeek connection {o.get('proto','?').upper()} {o.get('id.orig_h','')}:{o.get('id.orig_p','')} → {o.get('id.resp_h','')}:{o.get('id.resp_p','')}","src_ip":o.get("id.orig_h",""),"severity":"low","sensor":"Zeek","category":"network connection","description":f"duration={duration:.2f}s bytes={orig_bytes+resp_bytes:.0f} packets={orig_pkts+resp_pkts:.0f}","features":[duration,orig_bytes+resp_bytes,orig_pkts+resp_pkts,num("id.orig_p"),num("id.resp_p")]}
            add_event(record)
    except Exception: pass
def parse_auth():
    path=LOGS["linux_auth"]
    if not exists(path): return
    try:
        with open(path,"r",errors="replace") as f: lines=f.readlines()[-100:]
        for line in lines:
            low=line.lower()
            if "failed password" in low or "authentication failure" in low or "invalid user" in low:
                import re
                m=re.search(r"(?:from)\s+([0-9a-fA-F:.]+)",line)
                add_event({"timestamp":now(),"title":"SSH authentication failure","src_ip":m.group(1) if m else "unknown","severity":"medium","sensor":"Linux auth","category":"authentication","description":line.strip()[-180:]})
    except Exception: pass
def train_model():
    global MODEL, LAST_TRAIN, DETECTIONS
    with lock: rows=[e.copy() for e in EVENTS if e.get("sensor")=="Zeek" and isinstance(e.get("features"),list)]
    if len(rows)<30 or time.time()-LAST_TRAIN<60: return
    X=np.array([r["features"] for r in rows[-1000:]],dtype=float)
    X=np.nan_to_num(X,nan=0.0,posinf=0.0,neginf=0.0)
    if len(X)<30:return
    try:
        model=IsolationForest(n_estimators=100,contamination="auto",random_state=42)
        model.fit(X)
        raw=-model.score_samples(X)
        lo,hi=float(raw.min()),float(raw.max())
        scored=[]
        for row,score,pred in zip(rows[-len(X):],raw,model.predict(X)):
            normalized=0.0 if hi==lo else float((score-lo)/(hi-lo))
            if pred==-1:
                scored.append({"timestamp":row["timestamp"],"title":"Unusual network connection pattern","src_ip":row.get("src_ip",""),"score":round(normalized,3),"model":"IsolationForest","sensor":"Zeek","features":row["features"]})
        with lock:
            global_dummy = None
            DETECTIONS=scored[-300:]
            MODEL=model; LAST_TRAIN=time.time()
    except Exception: pass
def ingest():
    # This simple starter polls log tails. It may repeat the same tail rows; production should use offsets/checkpoints.
    while True:
        try:
            before=len(EVENTS)
            parse_json_lines(LOGS["suricata"],"suricata")
            parse_json_lines(LOGS["cowrie"],"cowrie")
            parse_zeek(); parse_auth(); train_model()
            # deduplicate recent tail re-reads by stable key
            with lock:
                seen=set(); unique=[]
                for e in EVENTS:
                    key=(e.get("timestamp"),e.get("sensor"),e.get("title"),e.get("src_ip"),e.get("description"))
                    if key not in seen: seen.add(key); unique.append(e)
                EVENTS[:] = unique[-MAX_EVENTS:]
        except Exception: pass
        time.sleep(10)
threading.Thread(target=ingest,daemon=True).start()

def auth(authorization):
    if not TOKEN: raise HTTPException(503,"Collector token is not configured")
    if authorization != f"Bearer {TOKEN}": raise HTTPException(401,"Invalid bearer token")

@app.get("/health")
def health(authorization: str | None = Header(default=None)):
    auth(authorization)
    return {"status":"ok","sources":{"network metadata":exists(LOGS["zeek"]),"suricata":exists(LOGS["suricata"]),"cowrie":exists(LOGS["cowrie"]),"linux auth":exists(LOGS["linux_auth"])},"events_cached":len(EVENTS),"model_ready":MODEL is not None,"checked_at":now()}
@app.get("/api/events")
def events(limit: int=Query(default=100,ge=1,le=500), authorization: str | None=Header(default=None)):
    auth(authorization)
    with lock: data=list(EVENTS[-limit:])
    data.reverse()
    return {"events":data}
@app.get("/api/detections")
def detections(limit: int=Query(default=100,ge=1,le=500), authorization: str | None=Header(default=None)):
    auth(authorization)
    with lock: data=list(DETECTIONS[-limit:])
    data.reverse()
    return {"detections":data}
@app.get("/api/intel/{ip}")
def intel(ip: str, authorization: str | None=Header(default=None)):
    auth(authorization)
    try:
        addr=ipaddress.ip_address(ip)
        if addr.version!=4 or addr.is_private or addr.is_loopback or addr.is_reserved:
            return {"ip":ip,"status":"unknown","reason":"Only public IPv4 addresses are queried","source":None,"checked_at":now()}
    except ValueError: raise HTTPException(400,"Invalid IP address")
    if not ABUSE_KEY: return {"ip":ip,"status":"unknown","reason":"ABUSEIPDB_API_KEY is not configured","source":"AbuseIPDB","checked_at":now()}
    try:
        r=requests.get("https://api.abuseipdb.com/api/v2/check",headers={"Key":ABUSE_KEY,"Accept":"application/json"},params={"ipAddress":ip,"maxAgeInDays":90},timeout=8)
        if r.status_code!=200:return {"ip":ip,"status":"unknown","reason":f"Provider returned HTTP {r.status_code}","source":"AbuseIPDB","checked_at":now()}
        d=r.json().get("data",{})
        confidence=int(d.get("abuseConfidenceScore",0))
        return {"ip":ip,"status":"malicious" if confidence>=50 else ("low-confidence" if confidence>0 else "no-abuse-reported"),"abuse_confidence":confidence,"total_reports":d.get("totalReports"),"source":"AbuseIPDB","checked_at":now()}
    except Exception:return {"ip":ip,"status":"unknown","reason":"Provider lookup failed","source":"AbuseIPDB","checked_at":now()}
