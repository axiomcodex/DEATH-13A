import time
import requests


def get_http_info(url):
    result = {
        "status_code": None,
        "final_url": None,
        "server": None,
        "content_type": None,
        "content_length": None,
        "response_time": None,
        "redirects": [],
        "headers": {},
        "error": None
    }

    try:
        start_time = time.perf_counter()

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "WebReconFramework/1.0"
            }
        )

        end_time = time.perf_counter()

        result["status_code"] = response.status_code
        result["final_url"] = response.url
        result["server"] = response.headers.get("Server")
        result["content_type"] = response.headers.get("Content-Type")
        result["content_length"] = response.headers.get("Content-Length")

        result["response_time"] = round(
            end_time - start_time,
            3
        )

        result["redirects"] = [
            {
                "status_code": redirect.status_code,
                "url": redirect.url,
                "location": redirect.headers.get("Location")
            }
            for redirect in response.history
        ]

        result["headers"] = dict(response.headers)

    except requests.RequestException as error:
        result["error"] = str(error)

    return result