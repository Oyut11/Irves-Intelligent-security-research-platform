"""
IRVES — Git Service
Handles cloning repositories from GitHub and GitLab.
Supports HTTPS + Personal Access Token (PAT) and SSH authentication.
Uses GitHub/GitLab archive API for fast downloads (ZIP) instead of slow git packfile protocol.
"""

import asyncio
import io
import shutil
import zipfile
import logging
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlunparse
from services.settings_service import settings_service

logger = logging.getLogger(__name__)


class GitCloneError(Exception):
    """Raised when a git clone operation fails."""
    pass


class GitService:
    """Service for cloning and managing remote repositories."""

    def __init__(self):
        self._git_bin = shutil.which("git") or "git"

    # ── Public API ─────────────────────────────────────────────────────────────

    async def clone(
        self,
        repo_url: str,
        dest_dir: Path,
        branch: str = "main",
        token: Optional[str] = None,
        progress_callback=None,
        timeout: int = 600,  # 10 minutes for large repos
    ) -> Path:
        """
        Clone a repository into dest_dir.
        Uses GitHub/GitLab archive API (ZIP download) for speed — 5-10x faster
        than git packfile protocol. Falls back to git clone for SSH URLs.

        Args:
            repo_url:  HTTPS URL  (https://github.com/org/repo)
                       or SSH URL (git@github.com:org/repo.git)
            dest_dir:  Target directory — will be created if absent.
            branch:    Branch / tag / commit to check out.
            token:     Personal Access Token for HTTPS repos.
                       Ignored for SSH URLs.
            progress_callback: Optional async-friendly callable(str).
            timeout:   Clone timeout in seconds (default 600s for large repos).

        Returns:
            Path to cloned repository root.
        """
        dest_dir.mkdir(parents=True, exist_ok=True)
        log_url = self._redact(self._inject_token(repo_url, token))

        # SSH URLs must use git clone — no archive API available
        if repo_url.startswith("git@") or repo_url.startswith("ssh://"):
            return await self._git_clone(repo_url, dest_dir, branch, token, progress_callback, timeout)

        # Try fast archive download first
        try:
            if progress_callback:
                progress_callback(f"Downloading {log_url} @ {branch}…")
            logger.info(f"[Git] Archive download {log_url} @ {branch} → {dest_dir}")
            result = await self._archive_download(repo_url, dest_dir, branch, token, timeout)
            if progress_callback:
                progress_callback(f"Repository downloaded successfully.")
            return result
        except Exception as e:
            logger.warning(f"[Git] Archive download failed ({e}), falling back to git clone")
            # Clean up partial download
            if dest_dir.exists():
                shutil.rmtree(dest_dir, ignore_errors=True)
                dest_dir.mkdir(parents=True, exist_ok=True)

        # Fallback to git clone
        return await self._git_clone(repo_url, dest_dir, branch, token, progress_callback, timeout)

    async def _archive_download(
        self,
        repo_url: str,
        dest_dir: Path,
        branch: str,
        token: Optional[str],
        timeout: int,
    ) -> Path:
        """Download repository as ZIP archive via GitHub/GitLab API. Much faster than git protocol."""
        import httpx

        parsed = urlparse(repo_url)
        host = parsed.hostname or ""
        parts = parsed.path.strip("/").rstrip(".git").split("/")
        if len(parts) < 2:
            raise GitCloneError(f"Cannot parse owner/repo from {repo_url}")
        owner, repo = parts[0], parts[1]

        # Build archive URL
        if "github" in host:
            archive_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{branch}"
        elif "gitlab" in host:
            # GitLab archive API
            encoded = f"{owner}/{repo}".replace("/", "%2F")
            archive_url = f"https://{host}/api/v4/projects/{encoded}/repository/archive.zip?sha={branch}"
        else:
            raise GitCloneError(f"Archive API not supported for host: {host}")

        # Resolve token
        effective_token = token
        if token and token.startswith("__CONNECTED__:"):
            provider = token.split(":")[1]
            stored = settings_service.load()
            effective_token = stored.get("integrations", {}).get(provider, {}).get("access_token", "")

        headers = {"Accept": "application/vnd.github+json"} if "github" in host else {}
        if effective_token:
            if effective_token.startswith("glpat_"):
                headers["PRIVATE-TOKEN"] = effective_token
            else:
                headers["Authorization"] = f"Bearer {effective_token}"

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(archive_url, headers=headers)
            if resp.status_code != 200:
                raise GitCloneError(f"Archive API returned {resp.status_code}: {resp.text[:200]}")

            # Extract ZIP in-place
            with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                # GitHub ZIPs have a top-level directory like "owner-repo-hash/"
                # We need to strip it and extract directly into dest_dir
                names = zf.namelist()
                if not names:
                    raise GitCloneError("Archive is empty")

                # Detect common prefix (e.g., "Oyut11-langflow-abc123/")
                prefix = names[0].split("/")[0] + "/" if "/" in names[0] else ""

                for name in names:
                    if name.endswith("/"):
                        continue  # skip directories
                    # Strip the top-level prefix
                    relative = name[len(prefix):] if name.startswith(prefix) else name
                    if not relative:
                        continue
                    target = dest_dir / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(name) as src, open(target, "wb") as dst:
                        dst.write(src.read())

        # Initialize as a git repo so downstream tools work
        await self._init_git_repo(dest_dir, branch)

        logger.info(f"[Git] Archive download complete → {dest_dir}")
        return dest_dir

    async def _init_git_repo(self, repo_path: Path, branch: str) -> None:
        """Initialize a minimal git repo in the extracted directory for downstream compatibility."""
        cmds = [
            [self._git_bin, "init"],
            [self._git_bin, "checkout", "-b", branch],
            [self._git_bin, "add", "-A"],
            [self._git_bin, "commit", "-m", "Initial import from archive", "--author=IRVES <irves@local>"],
        ]
        for cmd in cmds:
            stdout, stderr, rc = await self._run(cmd, cwd=repo_path, timeout=30)
            if rc != 0:
                logger.warning(f"[Git] Init step failed: {stderr.strip()[-200:]}")
                break

    async def _git_clone(
        self,
        repo_url: str,
        dest_dir: Path,
        branch: str,
        token: Optional[str],
        progress_callback,
        timeout: int,
    ) -> Path:
        """Fallback: traditional git clone with shallow + filter optimizations."""
        effective_url = self._inject_token(repo_url, token)

        cmd = [
            self._git_bin, "clone",
            "--depth", "1",
            "--filter=blob:none",
            "--jobs", "4",
            "--branch", branch,
            "--single-branch",
            "--progress",
            effective_url,
            str(dest_dir),
        ]

        log_url = self._redact(effective_url)
        if progress_callback:
            progress_callback(f"Cloning {log_url} @ {branch}…")

        logger.info(f"[Git] Cloning {log_url} → {dest_dir} (timeout: {timeout}s)")

        try:
            stdout, stderr, rc = await self._run(cmd, cwd=dest_dir.parent, timeout=timeout)
        except TimeoutError:
            raise GitCloneError(
                f"Clone timed out after {timeout}s. Repository may be too large or connection slow. "
                f"Try cloning manually or increasing timeout."
            )
        except Exception as e:
            raise GitCloneError(f"git clone failed: {e}") from e

        if rc != 0:
            detail = stderr.strip() or stdout.strip()
            raise GitCloneError(f"git clone exited {rc}: {detail[-400:]}")

        logger.info(f"[Git] Clone complete → {dest_dir}")
        if progress_callback:
            progress_callback(f"Repository cloned successfully.")

        return dest_dir

    async def verify_repo(self, repo_url: str, token: Optional[str] = None) -> dict:
        """
        Verify that the repository is accessible without cloning.
        Returns {reachable: bool, error: str|None, default_branch: str|None}.
        """
        effective_url = self._inject_token(repo_url, token)
        # --symref can show where HEAD points (the default branch)
        cmd = [self._git_bin, "ls-remote", "--symref", effective_url, "HEAD"]

        try:
            stdout, stderr, rc = await self._run(cmd, cwd=Path("/tmp"))
        except Exception as e:
            return {"reachable": False, "error": str(e), "default_branch": None}

        if rc != 0:
            return {"reachable": False, "error": stderr.strip()[-200:], "default_branch": None}

        # Parse default branch from ls-remote output
        # Typical output: ref: refs/heads/master	HEAD
        default = "main"
        for line in stdout.splitlines():
            if line.startswith("ref: refs/heads/") and "HEAD" in line:
                default = line.split("refs/heads/")[1].split()[0].strip()
                break

        return {"reachable": True, "error": None, "default_branch": default}

    def cleanup(self, dest_dir: Path) -> None:
        """Remove a cloned repository directory."""
        if dest_dir.exists():
            shutil.rmtree(dest_dir, ignore_errors=True)
            logger.info(f"[Git] Cleaned up {dest_dir}")

        # ── Repository Analysis ───────────────────────────────────────────────────

    async def get_repo_info(self, repo_path: Path) -> dict:
        """
        Get repository metadata for analysis.

        Returns:
            Dict with repository statistics and structure
        """
        info = {
            "path": str(repo_path),
            "exists": repo_path.exists(),
            "is_git_repo": False,
            "branches": [],
            "current_branch": None,
            "remote_url": None,
            "commit_count": 0,
            "last_commit": None,
            "languages": {},
            "file_count": 0,
            "total_size_mb": 0,
        }

        if not repo_path.exists():
            return info

        git_dir = repo_path / ".git"
        info["is_git_repo"] = git_dir.exists()

        if not info["is_git_repo"]:
            # Still analyze as directory
            info.update(await self._analyze_directory(repo_path))
            return info

        try:
            # Get current branch
            stdout, _, rc = await self._run(
                [self._git_bin, "branch", "--show-current"],
                cwd=repo_path
            )
            if rc == 0:
                info["current_branch"] = stdout.strip()

            # Get all branches
            stdout, _, rc = await self._run(
                [self._git_bin, "branch", "-a"],
                cwd=repo_path
            )
            if rc == 0:
                info["branches"] = [b.strip().strip("* ") for b in stdout.strip().split("\n") if b.strip()]

            # Get remote URL
            stdout, _, rc = await self._run(
                [self._git_bin, "remote", "get-url", "origin"],
                cwd=repo_path
            )
            if rc == 0:
                info["remote_url"] = self._redact(stdout.strip())

            # Get commit count
            stdout, _, rc = await self._run(
                [self._git_bin, "rev-list", "--count", "HEAD"],
                cwd=repo_path
            )
            if rc == 0:
                info["commit_count"] = int(stdout.strip())

            # Get last commit info
            stdout, _, rc = await self._run(
                [self._git_bin, "log", "-1", "--format=%H|%an|%ae|%ad|%s"],
                cwd=repo_path
            )
            if rc == 0:
                parts = stdout.strip().split("|")
                if len(parts) >= 5:
                    info["last_commit"] = {
                        "hash": parts[0][:8],
                        "author": parts[1],
                        "email": parts[2],
                        "date": parts[3],
                        "message": parts[4],
                    }

        except Exception as e:
            logger.warning(f"[Git] Error getting repo info: {e}")

        # Analyze directory structure
        info.update(await self._analyze_directory(repo_path))

        return info

    async def get_file_list(self, repo_path: Path, extensions: Optional[list] = None) -> list:
        """
        Get list of files in repository, optionally filtered by extensions.

        Args:
            repo_path: Repository root
            extensions: List of extensions to filter (e.g., ['.py', '.js'])

        Returns:
            List of file paths relative to repo root
        """
        files = []

        try:
            # Use git ls-files if it's a git repo
            if (repo_path / ".git").exists():
                stdout, _, rc = await self._run(
                    [self._git_bin, "ls-files"],
                    cwd=repo_path
                )
                if rc == 0:
                    files = [f.strip() for f in stdout.strip().split("\n") if f.strip()]
            else:
                # Fallback to directory walk
                for item in repo_path.rglob("*"):
                    if item.is_file():
                        try:
                            rel_path = item.relative_to(repo_path)
                            files.append(str(rel_path))
                        except ValueError:
                            pass

            # Filter by extensions
            if extensions:
                files = [f for f in files if any(f.lower().endswith(ext.lower()) for ext in extensions)]

        except Exception as e:
            logger.error(f"[Git] Error listing files: {e}")

        return files

    async def get_commit_history(self, repo_path: Path, limit: int = 100) -> list:
        """
        Get recent commit history for secrets analysis.

        Returns:
            List of commit dicts with hash, author, message
        """
        commits = []

        try:
            stdout, _, rc = await self._run(
                [self._git_bin, "log", f"-{limit}", "--format=%H|%an|%ae|%ad|%s"],
                cwd=repo_path
            )

            if rc == 0:
                for line in stdout.strip().split("\n"):
                    parts = line.split("|")
                    if len(parts) >= 5:
                        commits.append({
                            "hash": parts[0][:8],
                            "author": parts[1],
                            "email": parts[2],
                            "date": parts[3],
                            "message": parts[4],
                        })

        except Exception as e:
            logger.error(f"[Git] Error getting commit history: {e}")

        return commits

    async def _analyze_directory(self, path: Path) -> dict:
        """Analyze directory structure and languages."""
        result = {
            "languages": {},
            "file_count": 0,
            "total_size_mb": 0,
        }

        try:
            total_size = 0
            file_types = {}

            for item in path.rglob("*"):
                if item.is_file():
                    # Skip .git directory
                    if ".git" in item.parts:
                        continue

                    result["file_count"] += 1

                    # Get file size
                    try:
                        size = item.stat().st_size
                        total_size += size
                    except OSError:
                        pass

                    # Count by extension
                    ext = item.suffix.lower()
                    if ext:
                        lang = self._extension_to_language(ext)
                        file_types[lang] = file_types.get(lang, 0) + 1

            result["total_size_mb"] = round(total_size / (1024 * 1024), 2)
            result["languages"] = dict(sorted(file_types.items(), key=lambda x: x[1], reverse=True)[:10])

        except Exception as e:
            logger.warning(f"[Git] Error analyzing directory: {e}")

        return result

    @staticmethod
    def _extension_to_language(ext: str) -> str:
        """Map file extension to language name."""
        mapping = {
            ".py": "Python",
            ".js": "JavaScript",
            ".ts": "TypeScript",
            ".jsx": "JavaScript (React)",
            ".tsx": "TypeScript (React)",
            ".java": "Java",
            ".kt": "Kotlin",
            ".swift": "Swift",
            ".go": "Go",
            ".rs": "Rust",
            ".cpp": "C++",
            ".c": "C",
            ".h": "C/C++ Header",
            ".hpp": "C++ Header",
            ".cs": "C#",
            ".rb": "Ruby",
            ".php": "PHP",
            ".html": "HTML",
            ".css": "CSS",
            ".scss": "SCSS",
            ".sass": "Sass",
            ".json": "JSON",
            ".xml": "XML",
            ".yaml": "YAML",
            ".yml": "YAML",
            ".md": "Markdown",
            ".sh": "Shell",
            ".bash": "Bash",
            ".ps1": "PowerShell",
            ".sql": "SQL",
            ".dockerfile": "Dockerfile",
        }
        return mapping.get(ext, f"Other ({ext})")

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _inject_token(repo_url: str, token: Optional[str]) -> str:
        """
        For HTTPS URLs, embed the PAT as the username (GitHub/GitLab convention).
        SSH URLs are returned unchanged.
        """
        if not token:
            return repo_url
        if repo_url.startswith("git@") or repo_url.startswith("ssh://"):
            return repo_url  # SSH: token not applicable

        # Resolve connected account tokens
        if token.startswith("__CONNECTED__:"):
            provider = token.split(":")[1]
            stored = settings_service.load()
            token = stored.get("integrations", {}).get(provider, {}).get("access_token", "")
            if not token:
                logger.warning(f"[Git] Repository requested {provider} connection but no token found in settings")
                return repo_url

        parsed = urlparse(repo_url)
        # Use token for authentication
        # For GitHub and GitLab, simply token@hostname or oauth2:token@hostname works
        # If token starts with ghp_ or glpat_, just prepending token is standard.
        # Otherwise, prefixing with `oauth2:` acts as a standard fallback username for Oauth flows.
        username = f"{token}" if token.startswith(("ghp_", "glpat_")) else f"oauth2:{token}"
        
        authed = parsed._replace(netloc=f"{username}@{parsed.hostname}"
                                 + (f":{parsed.port}" if parsed.port else ""))
        return urlunparse(authed)


    @staticmethod
    def _redact(url: str) -> str:
        """Replace embedded token with *** for safe logging."""
        parsed = urlparse(url)
        if parsed.username:
            safe = parsed._replace(netloc=f"***@{parsed.hostname}"
                                   + (f":{parsed.port}" if parsed.port else ""))
            return urlunparse(safe)
        return url

    async def _run(self, cmd: list, cwd: Path, timeout: int = 120) -> tuple:
        """Run a subprocess and return (stdout, stderr, returncode)."""
        env = {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "echo",
            # Fail fast if connection is throttled (bytes/sec, seconds)
            "GIT_HTTP_LOW_SPEED_LIMIT": "1000",
            "GIT_HTTP_LOW_SPEED_TIME": "30",
            # Larger post buffer for big packfiles
            "GIT_HTTP_MAX_REQUEST_BUFFER": "100M",
        }
        import os
        full_env = {**os.environ, **env}

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=full_env,
        )

        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise TimeoutError(f"git command timed out after {timeout}s")

        return (
            stdout_b.decode("utf-8", errors="replace"),
            stderr_b.decode("utf-8", errors="replace"),
            proc.returncode or 0,
        )


# Global singleton
git_service = GitService()
