from pathlib import Path
from jinja2 import Environment, FileSystemLoader

# TODO: set up bytecode_cache, probably involves moving this into service.py
_env = Environment(
	loader=FileSystemLoader(Path(__file__).parent / "templates"),
	autoescape=True,
	auto_reload=False,  # don't reload on each request
)


def authn_page() -> str:
	return _env.get_template("authn.html").render()


def authz_page() -> str:
	return _env.get_template("authz.html").render(
		client_id="http://localhost/foobar.json", form_action="/oauth/foobar"
	)


def error_page(msg: str) -> str:
	return _env.get_template("error.html").render(message=msg)


if __name__ == "__main__":
	with open("authn_test.html", "w") as authn:
		authn.write(authn_page())
	with open("authz_test.html", "w") as authz:
		authz.write(authz_page())
	with open("error_test.html", "w") as authz:
		authz.write(
			error_page(
				"oh no something bad happened. you probably used the wrong password. idiot."
			)
		)
