"""Provide the legacy ``openvino.runtime`` import path when OpenVINO omits it.

RapidOCR releases may still import from ``openvino.runtime`` while newer
OpenVINO versions expose the same API from the top-level ``openvino`` package.
"""

import importlib
import sys
import types


def install_legacy_runtime_alias() -> None:
    try:
        importlib.import_module("openvino.runtime")
        return
    except ModuleNotFoundError as error:
        if error.name != "openvino.runtime":
            raise

    openvino = importlib.import_module("openvino")
    runtime = types.ModuleType("openvino.runtime")
    for name in dir(openvino):
        if not name.startswith("_"):
            setattr(runtime, name, getattr(openvino, name))

    sys.modules["openvino.runtime"] = runtime
    openvino.runtime = runtime
