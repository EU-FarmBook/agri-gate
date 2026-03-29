import os
from pathlib import Path

import requests


class AgriGateClient:
    def __init__(self, base_url: str, api_token: str, timeout: int = 60) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_token}",
        }

    def scan_url(self, url: str) -> dict:
        response = requests.post(
            f"{self.base_url}/v1/scan/url",
            headers={
                **self._headers(),
                "Content-Type": "application/json",
            },
            json={"url": url},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def scan_file(self, file_path: str, timeout: int = 300) -> dict:
        path = Path(file_path)
        with path.open("rb") as file_obj:
            response = requests.post(
                f"{self.base_url}/v1/scan/file",
                headers=self._headers(),
                files={"file": (path.name, file_obj)},
                timeout=timeout,
            )
        response.raise_for_status()
        return response.json()


if __name__ == "__main__":
    base_url = os.environ.get("AGRI_GATE_BASE_URL", "https://agrigate.nexavion.com")
    api_token = os.environ["AGRI_GATE_API_TOKEN"]

    client = AgriGateClient(base_url=base_url, api_token=api_token)

    print("URL scan example:")
    print(client.scan_url("https://example.org"))

    # Uncomment and update the path to try a file scan.
    # print("File scan example:")
    # print(client.scan_file("/absolute/path/to/file.pdf"))
