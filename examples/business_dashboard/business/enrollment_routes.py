"""Purpose-bound enrollment capabilities never create ordinary sessions."""

import math
import time
from typing import Annotated

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from pydantic import StringConstraints

from .enrollment import EnrollmentError, complete_enrollment, start_enrollment
from .models import RequestModel
from .security import read_session_token
from .work_limits import BoundedWork


class EnrollmentBegin(RequestModel):
    username: Annotated[str, StringConstraints(strict=True, strip_whitespace=True, min_length=1, max_length=64)]
    enrollment_secret: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=128)]


class EnrollmentFinish(RequestModel):
    new_password: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=128)]
    otp: Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9]{6}$")]


def enrollment_cookie_name(origin):
    return "__Host-westbridge_enrollment" if origin.scheme == "https" else "westbridge_enrollment"


def install_enrollment_routes(app, database, origin):
    # Enrollment is a separate work budget from normal sign-in. Possession of
    # this cookie never reaches authenticate() or the protected application.
    work = BoundedWork(2, "Account enrollment")
    cookie_name = enrollment_cookie_name(origin)

    def rejected(error):
        headers = {"Retry-After": str(error.retry_after)} if error.retry_after else None
        return JSONResponse({"detail": str(error)}, status_code=error.status_code, headers=headers)

    def begin(payload, response):
        try:
            pending = start_enrollment(database, payload.username, payload.enrollment_secret)
        except EnrollmentError as error:
            return rejected(error)
        response.set_cookie(cookie_name, pending.token,
                            max_age=max(0, math.ceil(pending.expires_at - time.time())),
                            httponly=True, secure=origin.scheme == "https", samesite="strict", path="/")
        return {"username": pending.username, "csrf": pending.csrf, "secret": pending.secret,
                "uri": pending.uri, "expires_at": pending.expires_at}

    def finish(payload, request):
        try:
            complete_enrollment(database, read_session_token(request, cookie_name),
                                request.headers.get("x-enrollment-csrf"), payload.new_password, payload.otp)
        except EnrollmentError as error:
            return rejected(error)
        # The consumed token is rejected in storage. A late response must not
        # erase a newer enrollment cookie or install an application session.
        return {"ok": True, "sign_in_required": True}

    @app.post("/api/enrollment/start")
    async def enrollment_start(payload: EnrollmentBegin, response: Response):
        return await work.run(begin, payload, response)

    @app.post("/api/enrollment/complete")
    async def enrollment_complete(payload: EnrollmentFinish, request: Request):
        return await work.run(finish, payload, request)
