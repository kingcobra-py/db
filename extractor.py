from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path, PurePosixPath, PureWindowsPath
from config import Settings

SUPPORTED = re.compile(r"(?i).*(?:\.zip|\.7z|\.rar|\.tar|\.tgz|\.txz|\.tar\.gz|\.tar\.xz|\.gz|\.xz|\.7z\.\d{3}|\.zip\.\d{3}|\.z\d{2}|\.part\d+\.rar|\.r\d{2})$")
FIRST_7Z = re.compile(r"(?i).*\.7z\.001$")
OTHER_7Z = re.compile(r"(?i).*\.7z\.(?!001$)\d{3}$")
FIRST_ZIP = re.compile(r"(?i).*\.zip\.001$")
OTHER_ZIP = re.compile(r"(?i).*\.zip\.(?!001$)\d{3}$")
ZIP_PART = re.compile(r"(?i).*\.z\d{2}$")
RAR_PART = re.compile(r"(?i).*\.part(\d+)\.rar$")
RAR_OLD_PART = re.compile(r"(?i).*\.r\d{2}$")


class ExtractionError(RuntimeError):
    pass


def is_archive(path: Path) -> bool:
    return bool(SUPPORTED.fullmatch(path.name))


def is_non_primary(path: Path) -> bool:
    name = path.name
    if OTHER_7Z.fullmatch(name) or OTHER_ZIP.fullmatch(name) or ZIP_PART.fullmatch(name) or RAR_OLD_PART.fullmatch(name):
        return True
    part = RAR_PART.fullmatch(name)
    return bool(part and int(part.group(1)) != 1)


def validate_member(name: str) -> None:
    normalized = name.replace("\\", "/").strip()
    if not normalized:
        return
    posix, windows = PurePosixPath(normalized), PureWindowsPath(name)
    if posix.is_absolute() or windows.is_absolute() or windows.drive:
        raise ExtractionError(f"Absolute archive path rejected: {name!r}")
    if ".." in posix.parts or "\x00" in normalized:
        raise ExtractionError(f"Unsafe archive path rejected: {name!r}")


class ArchiveProcessor:
    def __init__(self, settings: Settings, password_provider=None):
        self.s = settings
        self.password_provider = password_provider or (lambda: [])
        self.exe = str(Path(self._locate_7z()).resolve())

    @staticmethod
    def _locate_7z() -> str:
        """Find the 7-Zip binary on Windows or Linux. Explicit override wins."""
        override = os.environ.get("SEVENZIP_PATH", "").strip()
        if override:
            if Path(override).is_file():
                return override
            raise RuntimeError(f"SEVENZIP_PATH does not point to a file: {override!r}")
        for name in ("7z", "7zz", "7za"):
            found = shutil.which(name)
            if found:
                return found
        if os.name == "nt":
            # The Windows installer does not add 7-Zip to PATH.
            candidates = [
                Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "7-Zip" / "7z.exe",
                Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "7-Zip" / "7z.exe",
                Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "7-Zip" / "7z.exe",
            ]
            for candidate in candidates:
                if candidate.is_file():
                    return str(candidate)
        raise RuntimeError(
            "7-Zip not found. Install p7zip-full (Ubuntu) or 7-Zip (Windows), "
            "add it to PATH, or set SEVENZIP_PATH to the binary."
        )

    def _child_env(self) -> dict[str, str]:
        """Minimal, platform-correct environment for the 7-Zip subprocess."""
        if os.name == "nt":
            env = {"PATH": os.environ.get("PATH", "")}
            for key in ("SYSTEMROOT", "SystemRoot", "COMSPEC", "TEMP", "TMP"):
                if key in os.environ:
                    env[key] = os.environ[key]
            return env
        return {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.exe, *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True,
            encoding="oem" if os.name == "nt" else "utf-8",
            errors="replace",
            timeout=self.s.extraction_timeout_seconds, check=False, shell=False,
            env=self._child_env(),
        )

    def _passwords(self, files: list[Path]) -> list[str | None]:
        values: list[str | None] = [None]
        for stored in self.password_provider():
            if stored and stored not in values:
                values.append(stored)
        locations = {p.parent / "passwords.txt" for p in files} | {p.parent / "file" / "passwords.txt" for p in files}
        for candidate in sorted(locations):
            if not candidate.is_file():
                continue
            if candidate.stat().st_size > 1024**2:
                raise ExtractionError("passwords.txt exceeds 1 MiB")
            for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
                password = line.strip()
                if password and password not in values:
                    values.append(password)
        return values

    @staticmethod
    def _password_arg(password: str | None) -> str:
        return "-p" if password is None else f"-p{password}"

    @staticmethod
    def _summarize_7z_output(output: str, limit: int = 240) -> str:
        text = " ".join(line.strip() for line in (output or "").splitlines() if line.strip())
        if not text:
            return "no 7z output"
        lowered = text.lower()
        if "wrong password" in lowered:
            return "wrong password"
        if "cannot open" in lowered and "password" in lowered:
            return "password required or incorrect"
        if "unsupported method" in lowered:
            return "unsupported compression method"
        if "is not archive" in lowered or "can not open the file as archive" in lowered:
            return "not a valid archive"
        return text[:limit]

    def _inspect(self, archive: Path, password: str | None) -> tuple[int, int]:
        result = self._run(["l", "-slt", "-bd", "-y", self._password_arg(password), str(archive)])
        if result.returncode != 0:
            raise ExtractionError(f"Archive listing failed: {self._summarize_7z_output(result.stdout)}")
        count = expanded = 0
        in_entries = False
        is_directory = False
        for line in result.stdout.splitlines():
            if line.startswith("----------"):
                in_entries = True
                continue
            if not in_entries:
                continue
            if line.startswith("Path = "):
                validate_member(line[7:]); count += 1; is_directory = False
            elif line.startswith("Attributes = "):
                is_directory = "D" in line[13:].strip()
            elif line.startswith("Size = ") and line[7:].strip().isdigit():
                if not is_directory:
                    expanded += int(line[7:].strip())
            if count > self.s.max_archive_files:
                raise ExtractionError("Archive file-count limit exceeded")
        if count == 0:
            raise ExtractionError("Archive is empty or unreadable")
        return count, expanded

    def _verify_disk(self, expanded: int) -> None:
        if shutil.disk_usage(self.s.data_root).free < expanded + self.s.min_free_bytes:
            raise ExtractionError("Insufficient free disk space")

    def _post_validate(self, root: Path) -> tuple[int, int]:
        resolved_root = root.resolve(); count = total = 0
        for path in root.rglob("*"):
            count += 1
            if count > self.s.max_archive_files:
                raise ExtractionError("Actual file-count limit exceeded")
            stat = path.lstat()
            if path.is_symlink() or (path.is_file() and stat.st_nlink > 1):
                raise ExtractionError("Extracted links are not allowed")
            try:
                path.resolve().relative_to(resolved_root)
            except ValueError as exc:
                raise ExtractionError("Extracted path escaped work directory") from exc
            if path.is_file(): total += stat.st_size
            if total > self.s.max_expanded_bytes:
                raise ExtractionError("Actual expanded-size limit exceeded")
        return count, total

    def _extract(self, archive: Path, destination: Path, passwords: list[str | None]) -> None:
        """Extract archive with per-file password testing.

        1. First attempt: no password on each file
        2. If file needs password: try each password until one works
        3. If no password works: skip file (mark as failed)
        4. Continue with next file
        """
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)

        # First pass: try NO password on all files
        last_error = "archive rejected"
        try:
            _, expanded = self._inspect(archive, None)
            self._verify_disk(expanded)
            result = self._run(["x", "-bd", "-y", "-aoa",
                               f"-o{destination}",
                               self._password_arg(None),
                               str(archive)])
            if result.returncode == 0:
                self._post_validate(destination)
                return  # SUCCESS: No password needed

            last_error = self._summarize_7z_output(result.stdout) or "archive needs password"
        except (ExtractionError, subprocess.TimeoutExpired) as exc:
            last_error = str(exc) or type(exc).__name__

        # Second pass: archive needs password, try each one on the archive
        if len(passwords) <= 1:
            shutil.rmtree(destination, ignore_errors=True)
            raise ExtractionError(
                f"Could not safely extract {archive.name}: {last_error} "
                "(no archive passwords configured)"
            )

        for password in passwords[1:]:  # Skip None, already tried
            destination_temp = destination.parent / f"{destination.name}_temp_{abs(hash(password)) & 0xFFFFFFFF:x}"
            try:
                shutil.rmtree(destination_temp, ignore_errors=True)
                destination_temp.mkdir(parents=True, exist_ok=True, mode=0o700)

                _, expanded = self._inspect(archive, password)
                self._verify_disk(expanded)

                result = self._run(["x", "-bd", "-y", "-aoa",
                                   f"-o{destination_temp}",
                                   self._password_arg(password),
                                   str(archive)])

                if result.returncode == 0:
                    self._post_validate(destination_temp)
                    # Move temp to final destination
                    shutil.rmtree(destination, ignore_errors=True)
                    destination_temp.rename(destination)
                    return  # SUCCESS with this password

                last_error = self._summarize_7z_output(result.stdout) or "wrong password"
            except (ExtractionError, subprocess.TimeoutExpired) as exc:
                last_error = str(exc) or type(exc).__name__
            finally:
                shutil.rmtree(destination_temp, ignore_errors=True)

        # All passwords failed
        shutil.rmtree(destination, ignore_errors=True)
        raise ExtractionError(f"Could not safely extract {archive.name}: {last_error}")

    def process(self, message_id: int, files: list[Path]) -> Path:
        if not files:
            raise ExtractionError("No input files")
        work = self.s.work_dir / str(message_id)
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True, exist_ok=True, mode=0o700)
        passwords = self._passwords(files)
        copied = work / "files"; copied.mkdir(parents=True, exist_ok=True, mode=0o700)
        for path in files:
            if not is_archive(path): shutil.copy2(path, copied / path.name)
        primary = [p for p in files if is_archive(p) and not is_non_primary(p)]
        for index, archive in enumerate(primary):
            self._extract(archive, work / f"archive-{index}", passwords)
        if not primary and not any(copied.iterdir()):
            raise ExtractionError("No supported archive or ordinary input file")
        processed: set[Path] = {p.resolve() for p in primary}
        for depth in range(self.s.max_nesting_depth):
            nested = [p for p in work.rglob("*") if p.is_file() and is_archive(p) and not is_non_primary(p) and p.resolve() not in processed]
            if not nested: break
            for index, archive in enumerate(nested):
                processed.add(archive.resolve())
                self._extract(archive, archive.parent / f".nested-{depth}-{index}-{archive.stem}", passwords)
        self._post_validate(work)
        return work