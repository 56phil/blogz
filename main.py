#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import jinja2
import webapp2
import hashutils
from google.appengine.ext import db

# set up jinja
template_dir=os.path.join(os.path.dirname(__file__), "templates")
jinja_env=jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                             autoescape=True)


# a list of pages that anyone is allowed to visit
# (any others require logging in)
allowed_routes = [
    "/login",
    "/logout",
    "/register"
]


class User(db.Model):
    """ Represents a user on our site """
    username = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)


class Post(db.Model):
    owner = db.ReferenceProperty(User, required=True)
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)


def get_posts(limit=5, offset=0):
    q_str = 'select * from Post order by created desc limit {} offset {}'.\
            format(limit, offset)
    rows = db.GqlQuery(q_str).count()
    page_rows = db.GqlQuery(q_str).count(limit=limit, offset=offset)
    result = db.GqlQuery(q_str)
    return (result, rows, page_rows)


def get_cookies(request):
    cookies = {}
    raw_cookies = request.headers.get("Cookie")
    if raw_cookies:
        for cookie in raw_cookies.split(";"):
            print cookie
            name, value = cookie.split("=")
            cookies[name] = value
    return cookies


class Handler(webapp2.RequestHandler):
    """ A base RequestHandler class for our app.
        The other handlers inherit form this one.
    """

    def renderError(self, error_code):
        """ Sends an HTTP error code and a generic "oops!" message to the client. """
        self.error(error_code)
        self.response.write("Oops! Something went wrong.")

    def login_user(self, user):
        """ Logs in a user specified by a User object """
        user_id = user.key().id()
        self.set_secure_cookie('user_id', str(user_id))

    def logout_user(self):
        """ Logs out the current user """
        self.set_secure_cookie('user_id', '')

    def read_secure_cookie(self, name):
        """ Returns the value associated with a name in the user's cookie,
            or returns None, if no value was found or the value is not valid
        """
        cookie_val = self.request.cookies.get(name)
        if cookie_val:
            return hashutils.check_secure_val(cookie_val)

    def set_secure_cookie(self, name, val):
        """ Adds a secure name-value pair cookie to the response """
        cookie_val = hashutils.make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '{}={}; Path=/'.\
                format(name, cookie_val))

    def initialize(self, *a, **kw):
        """ Any subclass of webapp2.RequestHandler can implement a method
        called 'initialize' to specify what should happen before handling a
        request.

        Here, we use it to ensure that the user is logged in. If not, and
        they try to visit a page that requires an logging in (like /ratings),
        then we redirect them to the /login page
        """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.get_by_id(int(uid))

        if not self.user and self.request.path not in allowed_routes:
            return self.redirect('/login')

    def get_user_by_name(self, username):
        """ Given a username, try to fetch the user from the database """
        q_str = "SELECT * from User WHERE username = '{}'".format(username)
        user = db.GqlQuery(q_str)
        if user:
            return user.get()

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class Front(Handler):
    def get(self):
        limit = 5
        offset = 0
        current_page = self.request.get('page')
        if current_page.isdigit():
            current_page = int(current_page)
            offset = (current_page - 1) * limit
        else:
            current_page = 1
        posts, rows, page_rows = get_posts(limit, offset)
        last_page = rows // limit + 1
        if rows % limit == 0:
            last_page -= 1
        self.response.set_cookie('page', str(current_page), path='/')
        self.render('front.html', posts = posts, page = current_page,
                last_page = last_page)


class NewPost(Handler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, owner=self.user)
            p.put()
            self.redirect('/blog/{}'.format(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)


class Next(Handler):
    def get(self):
        cookies = get_cookies(self.request)
        current_page = cookies.get('page')
        if current_page.isdigit():
            current_page = int(current_page) + 1
        else:
            current_page = 2
        self.redirect('/blog?page={}'.format(current_page))


class PostPage(Handler):
    def get(self, *args, **kwargs):
        key = db.Key.from_path('Post', int(kwargs['id']), parent=blog_key())

        post = db.get(key)

        if post:
            self.render("permalink.html", post = post)
            return

        self.error(404)


class Prev(Handler):
    def get(self):
        cookies = get_cookies(self.request)
        current_page = cookies.get('page')
        if current_page.isdigit():
            current_page = int(current_page) - 1
        else:
            current_page = 1
        self.redirect('/blog?page={}'.format(current_page))


class Login(Handler):

    def render_login_form(self, error=""):
        t = jinja_env.get_template("login.html")
        content = t.render(error=error)
        self.response.write(content)

    def get(self):
        """ Display the login page """
        self.render_login_form()

    def post(self):
        """ User is trying to log in """
        submitted_username = self.request.get("username")
        submitted_password = self.request.get("password")

        user = self.get_user_by_name(submitted_username)
        if not user:
            self.render_login_form(error = "Invalid username")
        elif not hashutils.valid_pw(submitted_username, submitted_password, user.pw_hash):
            self.render_login_form(error = "Invalid password")
        else:
            self.login_user(user)
            return self.redirect("/")


class Logout(Handler):

    def get(self):
        """ User is trying to log out """
        self.logout_user()
        return self.redirect("/login")


class Register(Handler):

    def validate_username(self, username):
        """ Returns the username string untouched if it is valid,
            otherwise returns an empty string
        """
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        if USER_RE.match(username):
            return username

        return ""

    def validate_password(self, password):
        """ Returns the password string untouched if it is valid,
            otherwise returns an empty string
        """
        PWD_RE = re.compile(r"^.{3,20}$")
        if PWD_RE.match(password):
            return password
        else:
            return ""

    def validate_verify(self, password, verify):
        """ Returns the password verification string untouched if it matches
            the password, otherwise returns an empty string
        """
        if password == verify:
            return verify

    def get(self):
        """ Display the registration page """
        t = jinja_env.get_template("register.html")
        content = t.render(errors={})
        self.response.out.write(content)

    def post(self):
        """ User is trying to register """
        submitted_username = self.request.get("username")
        submitted_password = self.request.get("password")
        submitted_verify = self.request.get("verify")

        username = self.validate_username(submitted_username)
        password = self.validate_password(submitted_password)
        verify = self.validate_verify(submitted_password, submitted_verify)

        errors = {}
        existing_user = self.get_user_by_name(username)
        has_error = False

        if existing_user:
            errors['username_error'] = "A user with that username already exists"
            has_error = True
        elif (username and password and verify):
            # create new user object
            pw_hash = hashutils.make_pw_hash(username, password)
            user = User(username=username, pw_hash=pw_hash)
            user.put()

            self.login_user(user)
        else:
            has_error = True

            if not username:
                errors['username_error'] = "That's not a valid username"

            if not password:
                errors['password_error'] = "That's not a valid password"

            if not verify:
                errors['verify_error'] = "Passwords don't match"

        if has_error:
            t = jinja_env.get_template("register.html")
            content = t.render(username=username, errors=errors)
            self.response.out.write(content)
        else:
            return self.redirect('/')


app = webapp2.WSGIApplication([('/', Front),
    webapp2.Route(r'/blog/<id:\d+>', PostPage),
    ('/blog', Front),
    ('/blog/', Front),
    ('/blog/prev', Prev),
    ('/blog/newpost', NewPost),
    ('/blog/next', Next),
    ('/login', Login),
    ('/logout', Logout),
    ('/register', Register)
    ],
    debug=True)
