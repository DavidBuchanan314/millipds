"""
we don't have much HTML to render for millipds (just OAuth UI, currently), so
there's really no need to pull in a proper templating framework.

use https://marketplace.visualstudio.com/items?itemName=samwillis.python-inline-source
to make this source look nice
"""

html = str

AUTH_PANEL_HEAD: html = """\
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Authorize</title>
		<style>
			/*html, body {
				height: 100%
			}*/
			body {
				background-color: #333;
				color: #fff;
				font-family: system-ui, sans-serif;
				font-size: 16pt;
				margin: 2em 0;
			}

			.panel {
				background-color: #222;
				max-width: 420px;
				margin: auto;
				padding: 1.5em;
			}

			h1 {
				margin: 0;
				border-bottom: 0.1em solid #ff0048;
				line-height: 0.9;
			}

			form {
				/*margin-top: 1.5em;*/
			}

			input {
				width: 100%;
				box-sizing: border-box;
				padding: 0.5em 0.6em;
				font-size: 16pt;
				margin-bottom: 1em;
				margin-top: 0.5em;
				background-color: #1a1a1a;
				color: #fff;
				/*border: 0.1px solid #888;*/
				border-style: none;
				/*border-radius: 4px;*/
			}

			input[type="submit"] {
				/*margin-top: 1em;*/
				background-color: #ff0048;
				font-weight: bold;
				box-shadow: 2px 2px #000;
				margin-bottom: 0;
				/*border: 0.1px solid #fff;*/
			}

			input[type="submit"]:hover {
				background-color: #e10042;
			}

			input[type="submit"]:active {
				background-color: #c00038;
			}

			code {
				font-weight: normal;
				background-color: #1a1a1a;
				font-size: 12pt;
				padding: 0.2em 0.5em;
			}
		</style>
	</head>
	<body>
		<div class="panel">
			<h1>millipds</h1>"""

AUTH_PANEL_TAIL: html = """
		</div>
	</body>
</html>
"""

def authn_page():
	authn_body: html = """\
		<h3>put yer creds in the box.</h3>
		<form action="" method="POST">
			<label>handle: <input type="text" name="handle" value="todo.invalid" placeholder="bob.example.org"></label>
			<label>password: <input type="password" name="password" placeholder="password"></label>
			<input type="submit" value="sign in">
		</form>\
	"""
	return AUTH_PANEL_HEAD + authn_body + AUTH_PANEL_TAIL

def authz_page():
	authz_body: html = """\
		<h3>application <code>http://localhost/foobar.json</code> wants permission to:</h3>
		<ul>
			<li>eat the last donut</li>
			<li>install linux on your toaster</li>
			<li>deprecate your dependencies</li>
		</ul>
		<p>this is just a UI test, it doesn't actually do anything yet.</p>
		<form action="/oauth/foobar" method="POST">
			<input type="submit" value="authorize">
		</form>\
	"""
	
	return AUTH_PANEL_HEAD + authz_body + AUTH_PANEL_TAIL

if __name__ == "__main__":
	with open("authn_test.html", "w") as authn:
		authn.write(authn_page())
	with open("authz_test.html", "w") as authz:
		authz.write(authz_page())
