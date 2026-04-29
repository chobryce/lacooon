import json
import os
import tempfile
import shutil

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from laocoon import LaocoonScanner, ManifestParser

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  # IMPORTANT
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"status": "lacooon backend online"}

def sse(data: dict):
    return f"data: {json.dumps(data)}\n\n"

@app.post("/scan")
async def scan(file: UploadFile = File(...)):
    async def event_stream():
        suffix = file.filename

        yield sse({
            "type": "status",
            "phase": "upload",
            "message": f"Received {file.filename}"
        })

tmp_dir = tempfile.mkdtemp()
tmp_path = os.path.join(tmp_dir, file.filename)

content = await file.read()
with open(tmp_path, "wb") as tmp:
    tmp.write(content)

        try:
            yield sse({
                "type": "status",
                "phase": "parse",
                "message": "Parsing manifest..."
            })

            packages = ManifestParser.from_file(tmp_path)

            yield sse({
                "type": "status",
                "phase": "scan",
                "message": f"Loaded {len(packages)} package(s). Running scanner..."
            })

            scanner = LaocoonScanner(deep=False)

            results = []
            flagged = 0
            total_findings = 0

            for pkg in packages:
                yield sse({
                    "type": "status",
                    "phase": "scan",
                    "message": f"Checking {pkg.name}@{pkg.version}..."
                })

                result = scanner.scan_package(pkg)
                results.append(result)

                if result.is_malicious:
                    flagged += 1
                    total_findings += len(result.matches)

                    yield sse({
                        "type": "finding",
                        "package": result.to_dict()
                    })

            yield sse({
                "type": "summary",
                "total": len(packages),
                "flagged": flagged,
                "total_findings": total_findings,
                "clean": flagged == 0
            })

            yield sse({"type": "done"})

        except Exception as e:
            yield sse({
                "type": "error",
                "message": str(e)
            })

        finally:
            try:
                import shutil
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass

    return StreamingResponse(event_stream(), media_type="text/event-stream")
