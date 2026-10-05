import concurrent.futures

# Dedicated thread pools for blocking work dispatched off the event loop.
#
# asyncio.to_thread() always targets Python's single shared default executor,
# so a slow/hung job in one service can starve every other service's blocking
# calls. Giving each workload its own bounded pool contains that blast radius:
# a burst of slow OCR jobs can never starve DNS lookups, and vice versa.
DNS_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=16, thread_name_prefix="dns")
OCR_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="ocr")


def shutdown_executors():
    DNS_EXECUTOR.shutdown(wait=False, cancel_futures=True)
    OCR_EXECUTOR.shutdown(wait=False, cancel_futures=True)
