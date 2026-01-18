"""Flask application serving as auth endpoint for w3ds"""

import os
import uuid
from multiprocessing import Manager

import segno
from flask import Flask, request, Response, render_template
from flask_cors import CORS

# pylint: disable=line-too-long, invalid-name, fixme

manager = Manager()
# sessions are using mp.Manager().dict which safely locks
sessions = manager.dict()


def _get_state_for_session(sid: str):
    """Returns stored state for session id or None
    NB: if called before auth finished will return mp.Event"""
    print(os.getpid(), "getting", sid, "from", sessions)
    return sessions.get(sid)


def _set_state_for_session(sid: str, state):
    """Stores data provided by eid app"""
    print(os.getpid(), "setting", state, "for", sid)
    if sid in sessions:
        evt = sessions[sid]
        sessions[sid] = state
        evt.set()
    else:
        sessions[sid] = state


def _add_event(sid: str):
    """Stores a mapping from session id to mp.Event to wait on"""
    evt = manager.Event()
    if sid in sessions:
        evt.set()
    else:
        sessions[sid] = evt
    return evt


app = Flask(__name__)
CORS(app)


def _is_valid_token(data):
    """Partial token (from eid app) validation"""
    session = data.get("session")
    if session is None:
        return False
    signature = data.get("signature")
    if signature is None:
        return False
    # TODO validate signature
    # consider https://github.com/MetaState-Prototype-Project/prototype/blob/d6dc3c798c7d392c6718a9e26b674690dcaa3b33/infrastructure/signature-validator/src/index.ts#L334
    print(signature)
    return True


@app.route("/ppauth", methods=["POST", "GET", "OPTIONS"])
def authenticate():
    """Will be called by eid app when going to 'redirect'"""
    if request.method == "OPTIONS":
        res = Response()
        res.headers["X-Content-Type-Options"] = "*"
        return res
    if request.method == "POST":
        data = request.get_json()
        enm = data["ename"]
        if not _is_valid_token(data):
            return "error", 300
        _set_state_for_session(data["session"], enm)
        return "OK"
    return "error", 300


@app.route("/ename/<session>")
def ename(session):
    """Return the ename for this session, when authentication is done"""

    def stream():
        """Can be used with normal request or EventSource"""
        event = _add_event(session)
        event.wait()
        yield _get_state_for_session(session)

    return Response(stream(), mimetype="text/event-stream")


def _get_qr_dict(base: str, platform: str):
    """Draw redirect to auth QR for given platform"""
    base = "/".join(base.split("/")[0:-2])
    ssn = str(uuid.uuid4())
    txt = f"w3ds://auth?redirect={base}/ppauth&session={ssn}&platform={platform}"
    qrcode = segno.make(txt)
    return {"qr": qrcode.svg_inline(scale=5), "session": ssn}


@app.route("/headless/<platform>")
def headless(platform):
    """Return QR code"""
    return _get_qr_dict(request.base_url, platform)


@app.route("/login/<platform>")
def login(platform):
    """Render a simple page with QR code for eid app"""
    data = _get_qr_dict(request.base_url, platform)
    return render_template(
        "login.html", qr=data["qr"], session=data["session"], platform=platform
    )


# test with:
# gunicorn app:app --bind=0.0.0.0:5000 --workers=4 --log-level debug --preload
# as long as --preload is used, sessions mp.dict will be shared between procs
