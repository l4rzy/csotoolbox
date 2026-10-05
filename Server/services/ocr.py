import asyncio
import base64
import io
import logging
import os
import threading

from infrastructure.constants import OCR_MAX_SIDE, MAX_REQUEST_BODY_BYTES
from infrastructure.executors import OCR_EXECUTOR
from services.base import TunnelService, CachePolicy
from infrastructure.models import ServiceType, TunnelOptions, ServiceResult
from infrastructure.utils import make_error
from infrastructure.errors import ErrorType


logger = logging.getLogger()

_ocr_init_lock = threading.Lock()
_ov_engine = None


def _resize_if_huge(image, max_side: int = OCR_MAX_SIDE):
    w, h = image.size
    if w <= max_side and h <= max_side:
        return image
    ratio = min(max_side / w, max_side / h)
    return image.resize((int(w * ratio), int(h * ratio)), 1)  # 1 = Image.LANCZOS


def _init_ocr_engine() -> None:
    global _ov_engine
    from infrastructure.openvino_compat import install_legacy_runtime_alias
    install_legacy_runtime_alias()
    from rapidocr_openvino import RapidOCR

    threads = os.cpu_count() or 4
    _ov_engine = RapidOCR(
        params={
            "Global": {"max_side_len": OCR_MAX_SIDE, "use_cls": False},
            "EngineConfig": {"inference_num_threads": threads},
        }
    )
    logger.info(f"OCR engine: OpenVINO (threads={threads})")


def perform_ocr(image_bytes: bytes) -> str:
    global _ov_engine
    try:
        with _ocr_init_lock:
            if _ov_engine is None:
                _init_ocr_engine()
        from PIL import Image

        image = Image.open(io.BytesIO(image_bytes))
        if image.width > OCR_MAX_SIDE or image.height > OCR_MAX_SIDE:
            image = _resize_if_huge(image)
            logger.info(f"Image downscaled: {image.size}")
        result, elapse_list = _ov_engine(image)
        elapse_list = elapse_list or []
        total_elapsed = sum(elapse_list)
        logger.info(
            f"OpenVINO OCR: {total_elapsed:.3f}s (det={elapse_list[0]:.3f}s, cls={elapse_list[1]:.3f}s, rec={elapse_list[2]:.3f}s)"
        )
        if result:
            if hasattr(result, "txts"):
                texts = result.txts
            else:
                texts = [line[1] for line in result if line and len(line) > 1]
            text = "\n".join(texts)
            return text.strip()
        return ""
    except ImportError as e:
        logger.error(f"OCR dependency missing: {e}")
        raise
    except Exception as e:
        logger.error(f"OCR error: {str(e)}")
        raise


class OcrService(TunnelService):
    @property
    def service_type(self) -> ServiceType:
        return ServiceType.OCR

    def cache_policy(self, result: object) -> CachePolicy:
        return CachePolicy(should_cache=False)

    async def handle(self, payload: str, options: TunnelOptions) -> ServiceResult:
        if len(payload) > MAX_REQUEST_BODY_BYTES:
            return make_error(ErrorType.VALIDATION_ERROR, "Image payload too large")

        try:
            image_data = base64.b64decode(payload)
        except Exception:
            return make_error(ErrorType.VALIDATION_ERROR, "Failed to decode image data")

        try:
            loop = asyncio.get_running_loop()
            extracted_text = await loop.run_in_executor(OCR_EXECUTOR, perform_ocr, image_data)
        except ImportError as e:
            return make_error(ErrorType.UPSTREAM_SERVICE_ERROR, str(e))
        except Exception as e:
            return make_error(ErrorType.UPSTREAM_SERVICE_ERROR, f"OCR failed: {str(e)}")

        if not extracted_text:
            return make_error(ErrorType.NOT_FOUND_ERROR, "No text detected in image")
        return ServiceResult(payload={"text": extracted_text}, error=None)
