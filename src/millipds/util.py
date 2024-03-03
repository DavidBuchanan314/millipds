import os

def mkdirs_for_file(path: str) -> None:
	os.makedirs(os.path.dirname(path), exist_ok=True)
