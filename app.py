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

# events sequence:
# we generate a session id and embed it in qr
# after presenting the QR the client fetches /ename/<sid>
# at this point an event-to-wait-on is stored in sessions map for sid
# /ename/<sid> returns a stream -- the generator is blocked on event.wait
# eventually, eid app talks to /ppauth/
# we validate eid and set ename in sessions map
# we signal the event to wake up the waiting generator
# it yields the ename into /ename stream

# note, in this impl. calling /ename/<sid> can easily block
# if the <sid> is bogus or real but never scanned by eid app
# it will, however, time out after 60 seconds
# upon timeout it will clear the sid, so sessions do not leak


def _get_state_for_session(sid: str):
    """Returns stored state for session id or None
    NB: if called before auth finished will return mp.Event"""
    print(os.getpid(), "getting", sid)
    return sessions.pop(sid, "!invalid")


def _set_state_for_session(sid: str, state):
    """Stores data provided by eid app"""
    print(os.getpid(), "setting", state, "for", sid)
    if sid in sessions:
        evt = sessions[sid]
        sessions[sid] = state
        evt.set()
    else:
        # this session is gone or never was
        print(sid, "is not a valid session")


def _add_event(sid: str):
    """Stores a mapping from session id to mp.Event to wait on"""
    if sid in sessions:
        # why would we have it? who knows, maybe you are calling many /enames/<sid>
        evt = sessions[sid]
        assert type(evt) is manager.Event
        return evt
    evt = manager.Event()
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
        """Can be used with normal request"""
        event = _add_event(session)
        success = event.wait(timeout=60)
        value = _get_state_for_session(session) if success else "!timedout"
        yield value

    return Response(stream(), mimetype="text/event-stream")


@app.route("/ename_s/<session>")
def ename_s(session):
    """Return the ename for this session, when authentication is done"""

    def stream():
        """Can be used with EventSource"""
        event = _add_event(session)
        success = event.wait(timeout=60)
        value = _get_state_for_session(session) if success else "!timedout"
        yield "data: %s\n\n" % value

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


@app.route("/health")
def health():
    return "OK", 200


# test with:
# gunicorn app:app --bind=0.0.0.0:5000 --workers=4 --log-level debug --preload --timeout 100
# as long as --preload is used, sessions mp.dict will be shared between procs
