import argparse

from . import service

"""
This is the entrypoint for the `millipds` command (declared in project.scripts)
"""
def main():
	parser = argparse.ArgumentParser(description="millipds service")
	parser.add_argument("--sock_path", help="unix domain socket to listen on (supersedes HOST and PORT options)")
	parser.add_argument("--host", default="127.0.0.1", help="defaults to 127.0.0.1")
	parser.add_argument("--port", type=int, default=8123, help="defaults to 8123")

	args = parser.parse_args()

	service.run(sock_path=args.sock_path, host=args.host, port=args.port)

"""
This is the entrypoint for python3 -m millipds
"""
if __name__ == "__main__":
	main()
