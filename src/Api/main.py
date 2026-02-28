from datetime import datetime
from io import StringIO
import csv

from fastapi import Depends, FastAPI, Query
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy.orm import Session

from src.Shared.db import Finding, ScanRun, SessionLocal, init_db
from src.Shared.scanner import Scanner

app = FastAPI(title="AIRS API")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
def startup():
    init_db()


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return """
<!doctype html><html><body>
<h1>AIRS Dashboard</h1>
<button onclick='runScan()'>Run Scan</button>
<pre id='out'></pre>
<script>
async function runScan(){
  const run=await fetch('/scan/run',{method:'POST'}).then(r=>r.json());
  const latest=await fetch('/scan/latest').then(r=>r.json());
  document.getElementById('out').textContent=JSON.stringify({run,latest},null,2);
}
</script>
</body></html>
"""


@app.post("/scan/run")
def run_scan(db: Session = Depends(get_db)):
    run = ScanRun(started_at=datetime.utcnow(), status="running", summary={}, warnings=[])
    db.add(run)
    db.commit()
    db.refresh(run)

    result = Scanner().run()
    for f in result["findings"]:
        payload = dict(f)
        payload["metadata_json"] = payload.pop("metadata", {})
        db.add(Finding(scan_run_id=run.id, **payload))

    run.status = "completed"
    run.completed_at = datetime.utcnow()
    run.summary = result["counts"]
    run.warnings = result["warnings"]
    db.commit()
    return {"scanRunId": run.id, "summary": run.summary, "warnings": run.warnings}


@app.get("/scan/latest")
def latest_scan(db: Session = Depends(get_db)):
    run = db.query(ScanRun).order_by(ScanRun.id.desc()).first()
    if not run:
        return {"summary": {}, "counts": {}, "warnings": []}
    return {
        "scanRunId": run.id,
        "status": run.status,
        "startedAt": run.started_at,
        "completedAt": run.completed_at,
        "counts": run.summary,
        "warnings": run.warnings,
    }


@app.get("/findings")
def findings(
    severity: str | None = Query(default=None),
    category: str | None = Query(default=None),
    type: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    q = db.query(Finding)
    if severity:
        q = q.filter(Finding.severity == severity)
    if category:
        q = q.filter(Finding.category == category)
    if type:
        q = q.filter(Finding.type == type)
    rows = q.order_by(Finding.id.desc()).all()
    return [
        {
            "id": r.id,
            "entityKind": r.entity_kind,
            "entityId": r.entity_id,
            "displayName": r.display_name,
            "severity": r.severity,
            "category": r.category,
            "type": r.type,
            "description": r.description,
            "metadata": r.metadata_json,
        }
        for r in rows
    ]


@app.get("/export/findings.csv")
def export_findings(db: Session = Depends(get_db)):
    rows = db.query(Finding).order_by(Finding.id.desc()).all()
    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "entity_kind", "entity_id", "display_name", "severity", "category", "type", "description", "metadata"])
    for r in rows:
        writer.writerow([r.id, r.entity_kind, r.entity_id, r.display_name, r.severity, r.category, r.type, r.description, r.metadata_json])
    buf.seek(0)
    return StreamingResponse(iter([buf.read()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=findings.csv"})
