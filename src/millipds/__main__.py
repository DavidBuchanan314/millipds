import sys

from .service import run

"""
This is the entrypoint for the `millipds` command (declared in project.scripts)
"""
def main():
	run(sys.argv)

"""
This is the entrypoint for python3 -m millipds
"""
if __name__ == "__main__":
	main()
