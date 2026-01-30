import requests

class GitHubUtils:

    @staticmethod
    def get_latest_release(repo: str):
        """
        repo format: 'owner/repository'
        """
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        r = requests.get(url, timeout=10)

        if r.status_code != 200:
            return None

        return r.json()

    @staticmethod
    def download_asset(url: str):
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return None
        return r.content