import random
import time
from urllib.parse import quote, urlparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import urllib3
from urllib3.exceptions import InsecureRequestWarning

"""
Reusable HTTP client helpers for BitrixProbe pentest modules.
"""


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
]

DEFAULT_USER_AGENT = random.choice(USER_AGENTS)

DEFAULT_TIMEOUT = (2, 3)
DEFAULT_VERIFY_SSL = False
DEFAULT_MAX_REDIRECTS = 5

HTML_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
IMAGE_ACCEPT = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
DEFAULT_ACCEPT = "*/*"
_thread_local = threading.local()
_tls_warning_lock = threading.Lock()
_insecure_request_warning_disabled = False


def configure_tls_warning_filter(verify_ssl) -> None:
    """
    Suppress only urllib3's warning when TLS verification is disabled.
    Certificate, protocol, connection, and timeout errors are not suppressed.
    """

    global _insecure_request_warning_disabled

    if verify_ssl:
        return

    if _insecure_request_warning_disabled:
        return

    with _tls_warning_lock:
        if _insecure_request_warning_disabled:
            return

        urllib3.disable_warnings(InsecureRequestWarning)
        _insecure_request_warning_disabled = True


def get_default_user_agent() -> str:
    """
    Return the User-Agent selected once for the current Python process.
    """

    return DEFAULT_USER_AGENT


def normalize_target_url(target_url, default_scheme="https") -> str:
    """
    Normalize a target URL and add a default scheme if it is missing.
    """

    target_url = str(target_url).strip()

    if not target_url:
        raise ValueError("Target URL is empty.")

    parsed_url = urlparse(target_url)

    if not parsed_url.scheme:
        target_url = f"{default_scheme}://{target_url}"

    return target_url.rstrip("/")


def quote_url_path(path) -> str:
    """
    Quote a URL path while keeping path separators unchanged.
    """

    return quote(str(path).lstrip("/"), safe="/:@$-_.~")


def build_target_url(target_url, path="", quote_path=False) -> str:
    """
    Build a full URL from a base target URL and a relative path.
    """

    target_url = normalize_target_url(target_url)

    if not path:
        return target_url

    if quote_path:
        path = quote_url_path(path)

    return target_url.rstrip("/") + "/" + str(path).lstrip("/")


def strip_url_fragment(url) -> str:
    """
    Remove a URL fragment because fragments are not sent in HTTP requests.
    """

    return str(url).split("#", 1)[0]


def build_headers(user_agent=None, accept=None, extra_headers=None) -> dict:
    """
    Build default HTTP headers for pentest requests.
    """

    headers = {
        "User-Agent": user_agent or get_default_user_agent(),
        "Accept": accept or DEFAULT_ACCEPT,
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"
    }

    if extra_headers:
        headers.update(extra_headers)

    return headers


def create_www_session(user_agent=None, accept=None, extra_headers=None,
                       max_redirects=DEFAULT_MAX_REDIRECTS) -> requests.Session:
    """
    Create a configured requests session for BitrixProbe pentest modules.
    """

    session = requests.Session()
    session.max_redirects = max_redirects

    session.headers.update(
        build_headers(
            user_agent=user_agent,
            accept=accept,
            extra_headers=extra_headers,
        )
    )

    return session

def normalize_http_task(task) -> dict:
    """
    Normalize a concurrent HTTP task into a standard dictionary.
    """

    if isinstance(task, str):
        return {
            "path": task,
            "metadata": {},
        }

    if not isinstance(task, dict):
        raise ValueError("HTTP task must be a string path or a dictionary.")

    if "path" not in task:
        raise ValueError("HTTP task dictionary must contain the 'path' key.")

    return {
        "path": task["path"],
        "metadata": task.get("metadata", {}),
    }


def get_thread_www_session(user_agent=None, accept=None, extra_headers=None,
                           max_redirects=DEFAULT_MAX_REDIRECTS) -> requests.Session:
    """
    Return a thread-local HTTP session for concurrent HTTP probing.
    """

    headers_key = tuple(sorted((extra_headers or {}).items()))

    session_key = (
        user_agent or get_default_user_agent(),
        accept or DEFAULT_ACCEPT,
        headers_key,
        max_redirects,
    )

    if (
        not hasattr(_thread_local, "www_session")
        or not hasattr(_thread_local, "www_session_key")
        or _thread_local.www_session_key != session_key
    ):
        _thread_local.www_session = create_www_session(
            user_agent=user_agent,
            accept=accept,
            extra_headers=extra_headers,
            max_redirects=max_redirects,
        )
        _thread_local.www_session_key = session_key

    return _thread_local.www_session


def get_task_skip_key(task, skip_by_metadata_key) -> str:
    """
    Extract a skip key from task metadata.
    """

    if not skip_by_metadata_key:
        return ""

    metadata = task.get("metadata", {})

    if skip_by_metadata_key not in metadata:
        return ""

    return str(metadata[skip_by_metadata_key])


def is_task_skipped(skip_key, skip_state, skip_lock) -> bool:
    """
    Check whether a task should be skipped by its skip key.
    """

    if not skip_key:
        return False

    if skip_state is None or skip_lock is None:
        return False

    with skip_lock:
        return skip_key in skip_state["skipped"]


def update_skip_state(skip_key, status_code, skip_state, skip_lock, skip_on_status=None, skip_after=0) -> None:
    """
    Update skip state after an HTTP response.
    """

    if not skip_key:
        return

    if skip_state is None or skip_lock is None:
        return

    if skip_on_status is None:
        return

    if skip_after <= 0:
        return

    with skip_lock:
        if status_code == skip_on_status:
            current_count = skip_state["consecutive"].get(skip_key, 0) + 1
            skip_state["consecutive"][skip_key] = current_count

            if current_count >= skip_after:
                skip_state["skipped"].add(skip_key)
                skip_state["events"].append(
                    {
                        "key": skip_key,
                        "status_code": skip_on_status,
                        "count": current_count,
                    }
                )
        else:
            skip_state["consecutive"][skip_key] = 0


def run_http_task(target_url, task, method="GET", timeout=DEFAULT_TIMEOUT, verify_ssl=DEFAULT_VERIFY_SSL,
                  allow_redirects=True, quote_path=False, user_agent=None, accept=None, extra_headers=None,
                  max_redirects=DEFAULT_MAX_REDIRECTS, headers=None, include_body=None, include_content=False,
                  delay=0, skip_by_metadata_key=None, skip_on_status=None, skip_after=0, skip_state=None,
                  skip_lock=None) -> dict:
    """
    Run one HTTP task using a thread-local HTTP session.
    """

    normalized_task = normalize_http_task(task)
    skip_key = get_task_skip_key(normalized_task, skip_by_metadata_key)

    if is_task_skipped(skip_key, skip_state, skip_lock):
        return {
            "task": normalized_task,
            "probe_result": None,
            "error": "",
            "skipped": True,
            "skip_reason": f"skipped: {skip_key}",
        }

    session = get_thread_www_session(
        user_agent=user_agent,
        accept=accept,
        extra_headers=extra_headers,
        max_redirects=max_redirects,
    )

    probe_result = run_http_request(
        session=session,
        target_url=target_url,
        path=normalized_task["path"],
        method=method,
        timeout=timeout,
        verify_ssl=verify_ssl,
        allow_redirects=allow_redirects,
        quote_path=quote_path,
        headers=headers,
        include_body=include_body,
        include_content=include_content,
        delay=delay,
    )

    update_skip_state(
        skip_key=skip_key,
        status_code=probe_result["status_code"],
        skip_state=skip_state,
        skip_lock=skip_lock,
        skip_on_status=skip_on_status,
        skip_after=skip_after,
    )

    return {
        "task": normalized_task,
        "probe_result": probe_result,
        "error": "",
        "skipped": False,
        "skip_reason": "",
    }


def run_http_requests_concurrent(target_url, tasks, method="GET", timeout=DEFAULT_TIMEOUT,
                                 verify_ssl=DEFAULT_VERIFY_SSL, allow_redirects=True, quote_path=False,
                                 user_agent=None, accept=None, extra_headers=None,
                                 max_redirects=DEFAULT_MAX_REDIRECTS, headers=None, include_body=None,
                                 include_content=False, max_workers=20, delay=0, progress_callback=None,
                                 skip_by_metadata_key=None, skip_on_status=None, skip_after=0) -> dict:
    """
    Run multiple HTTP tasks concurrently using ThreadPoolExecutor.
    """

    results = []
    errors = []

    normalized_tasks = []

    for task in tasks:
        normalized_tasks.append(normalize_http_task(task))

    total_tasks = len(normalized_tasks)
    completed_tasks = 0

    skip_state = {
        "consecutive": {},
        "skipped": set(),
        "events": [],
    }

    skip_lock = threading.Lock()

    if total_tasks == 0:
        return {
            "results": [],
            "errors": [],
            "skipped_keys": [],
            "skip_events": [],
        }

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {}

        for task in normalized_tasks:
            future = executor.submit(
                run_http_task,
                target_url,
                task,
                method,
                timeout,
                verify_ssl,
                allow_redirects,
                quote_path,
                user_agent,
                accept,
                extra_headers,
                max_redirects,
                headers,
                include_body,
                include_content,
                delay,
                skip_by_metadata_key,
                skip_on_status,
                skip_after,
                skip_state,
                skip_lock,
            )

            future_map[future] = task

        for future in as_completed(future_map):
            task = future_map[future]
            completed_tasks += 1

            try:
                item = future.result()
                results.append(item)

                progress_error = ""

                if item.get("skipped"):
                    progress_error = item.get("skip_reason", "skipped")

                if progress_callback:
                    progress_callback(
                        completed_tasks,
                        total_tasks,
                        item["task"],
                        item["probe_result"],
                        progress_error,
                    )

            except Exception as error:
                error_text = str(error)

                item = {
                    "task": task,
                    "probe_result": None,
                    "error": error_text,
                    "skipped": False,
                    "skip_reason": "",
                }

                results.append(item)
                errors.append(
                    {
                        "task": task,
                        "error": error_text,
                    }
                )

                if progress_callback:
                    progress_callback(
                        completed_tasks,
                        total_tasks,
                        task,
                        None,
                        error_text,
                    )

    return {
        "results": results,
        "errors": errors,
        "skipped_keys": sorted(skip_state["skipped"]),
        "skip_events": skip_state["events"],
    }


def extract_redirect_chain(response) -> list:
    """
    Extract a serializable HTTP redirect chain from a requests response.
    """

    redirect_chain = []

    for redirect in response.history:
        redirect_chain.append(
            {
                "status_code": redirect.status_code,
                "url": redirect.url,
            }
        )

    return redirect_chain


def format_redirect_chain(redirect_chain) -> str:
    """
    Format HTTP redirect chain for human-readable output.
    """

    if not redirect_chain:
        return "-"

    lines = []

    for redirect in redirect_chain:
        lines.append(f"{redirect['status_code']} -> {redirect['url']}")

    return "\n".join(lines)


def build_response_chain_data(response) -> list:
    """
    Build serializable response chain data from redirects and final response.
    """

    response_chain_data = []

    for item in response.history + [response]:
        response_chain_data.append(
            {
                "url": item.url,
                "status_code": item.status_code,
                "headers": dict(item.headers),
                "cookies": item.cookies.get_dict(),
            }
        )

    return response_chain_data


def build_response_result(response, path, display_url, request_url, method="GET",
                          include_body=True, include_content=False) -> dict:
    """
    Convert a requests response into a standard BitrixProbe HTTP result.
    """

    content = response.content
    if not content:
        content = b""

    content_length_header = response.headers.get("Content-Length", "") # Get files size

    result = {
        "method": method,
        "path": path,
        "display_url": display_url,
        "request_url": request_url,
        "final_url": response.url,
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "cookies": response.cookies.get_dict(),
        "redirect_chain": extract_redirect_chain(response),
        "redirect_location": response.headers.get("Location", ""),
        "content_type": response.headers.get("Content-Type", ""),
        "content_length": len(content),
        "content_length_header": content_length_header,
        "response_chain_data": build_response_chain_data(response),
    }

    if include_body:
        result["body"] = response.text

    if include_content:
        result["content"] = content

    return result


def run_http_request(session, target_url, path="", method="GET", timeout=DEFAULT_TIMEOUT,
                     verify_ssl=DEFAULT_VERIFY_SSL, allow_redirects=True, quote_path=False, headers=None,
                     include_body=None, include_content=False, delay=0, data=None) -> dict:
    """
    Send an HTTP request and return a standard HTTP probe result.
    """

    method = str(method).upper()

    if include_body is None:
        include_body = method != "HEAD"

    configure_tls_warning_filter(verify_ssl) # Remove InsecureRequestWarning: Unverified HTTPS request

    display_url = build_target_url(
        target_url=target_url,
        path=path,
        quote_path=quote_path,
    )

    request_url = strip_url_fragment(display_url)

    response = session.request(
        method=method,
        url=request_url,
        headers=headers,
        data=data,
        timeout=timeout,
        verify=verify_ssl,
        allow_redirects=allow_redirects,
    )

    if delay > 0:
        time.sleep(delay)

    return build_response_result(
        response=response,
        path=path,
        display_url=display_url,
        request_url=request_url,
        method=method,
        include_body=include_body,
        include_content=include_content,
    )