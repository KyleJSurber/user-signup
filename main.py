from flask import Flask, request, redirect
import html
import re

app = Flask(__name__)
app.config['DEBUG'] = True


def escape_html(msg):
    return html.escape(msg, quote=True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(uname):
    return USER_RE.match(uname)

def valid_password(pword):
    return PASSWORD_RE.match(pword)

def valid_email(email):
    return EMAIL_RE.match(email)

signup_form='''
<html>
  <head>
    <title>User Signup</title>
    <style type="text/css">
      .label {text-align: right}
      .error {color: red}
    </style>

  </head>

  <body>
    <h2>Signup</h2>
    <form method="post">
      <table>
        <tr>
          <td class="label">
            Username
          </td>
          <td>
            <input type="text" name="username" value="%(username)s">
          </td>
          <td class="error">
            %(username_error)s
          </td>
        </tr>

        <tr>
          <td class="label">
            Password
          </td>
          <td>
            <input type="password" name="password" value="%(password)s">
          </td>
          <td class="error">
            %(password_error)s
          </td>

          </td>
        </tr>

        <tr>
          <td class="label">
            Verify Password
          </td>
          <td>
            <input type="password" name="verify" value="%(verify)s">
          </td>
          <td class="error">
            %(verify_error)s
          </td>
        </tr>

        <tr>
          <td class="label">
            E-mail
          </td>
          <td>
            <input type="text" name="email" value="%(email)s">
          </td>
          <td class="error">
            %(email_error)s
          </td>
        </tr>
      </table>
      <br>
      <input type="submit">
    </form>
  </body>

</html>
'''

@app.route("/", methods=['POST'])
def validate():        
    user_username = request.form.get('username')
    user_password = request.form.get('password')
    user_verify = request.form.get('verify')
    user_email = request.form.get('email')

    escaped_username = escape_html(user_username)
    escaped_password = escape_html(user_password)
    escaped_verify = escape_html(user_verify)
    escaped_email = escape_html(user_email)

    username_error = ""
    password_error = ""
    verify_error = ""

    error = False

    if not valid_username(user_username):
        username_error = "Please enter a valid username!"
        error = True

    if not valid_password(user_password):
        password_error = "Please enter a valid password!"
        error = True

    if not user_verify or not user_password == user_verify:
        verify_error = "Your passwords do not match!"
        error = True

    if not valid_email(user_email):
        email_error = "Please enter a valid email address!"
        error = True

    if error:
        return write_form(escaped_username, escaped_password, escaped_verify, escaped_email, username_error, password_error, verify_error, email_error)
    else:
        return redirect("/welcome?username=%s" % user_username)
@app.route("/")
def index():
    return write_form()

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(uname):
    return USER_RE.match(uname)

def valid_password(pword):
    return PASSWORD_RE.match(pword)

def valid_email(email):
    return EMAIL_RE.match(email)


def write_form(username="", password="", verify="", email="", username_error="", password_error="", verify_error="", email_error=""):
    return signup_form % {"username" : username,
                                                "password" : password,
                                                "verify" : verify,
                                                "email" : email,
                                                "username_error" : username_error,
                                                "password_error" : password_error,
                                                "verify_error" : verify_error,
                                                "email_error" : email_error}




@app.route("/welcome")
def welcome():
    username = request.args.get("username")
    return ("Welcome,  %s" % username)

app.run()
