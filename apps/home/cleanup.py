# -*- encoding: utf-8 -*-
"""
Utilities for cleaning analysis-related temporary state (file + session keys).
"""

import os
from flask import session as flask_session


def _safe_unlink(path: str) -> None:
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except Exception:
        # Best-effort cleanup; ignore IO errors
        pass


def clear_analysis_state(session: dict | None = None) -> dict:
    """
    Remove temporary analysis artifacts:
    - delete pickled dataframe stored at session['temp_file'] (if present)
    - pop 'temp_file', 'analysis_results', 'filename' from the session

    Returns a simple result dict with success/message for uniformity.
    """
    sess = session or flask_session

    temp_path = sess.get('temp_file')
    if temp_path:
        _safe_unlink(temp_path)

    # Drop session keys regardless of file removal outcome
    for key in ('temp_file', 'analysis_results', 'filename'):
        try:
            sess.pop(key, None)
        except Exception:
            pass

    return {"success": True, "message": "Données d'analyse temporaires effacées"}
