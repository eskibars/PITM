"""
PITM ("People in the Middle") is an application hich lives inside of mitmproxy. It provides
a flexible web-based method to add/remove allowed users.

See the associated README and LICENSE documents for all instructional bits.

Have fun.  Always.
"""
import sqlite3
import os.path
import urllib
import md5
import string
import random
import sys
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, redirect, request as flask_request
from libmproxy.protocol.http import HTTPResponse
from libmproxy import flow
from netlib.odict import ODictCaseless

app = Flask("eskibars-proxy-users")

def check_is_logged_in(r, sqlitecursor, requireadmin=False):
	auth_id = r.cookies.get('auth')
	if not auth_id:
		return False
	user = False
	if requireadmin:
		sqlitecursor.execute("SELECT username FROM users WHERE loginip = ? AND admin = 'y' AND authid = ?", (r.remote_addr,auth_id))
		row = sqlitecursor.fetchone()
		if row:
			return row[0]
		else:
			return False
	else:
		sqlitecursor.execute("SELECT username FROM users WHERE loginip = ?", (r.remote_addr,))
		row = sqlitecursor.fetchone()
		if row:
			return row[0]
		else:
			return False
	return user

def random_id(size=30, chars=string.ascii_letters + string.digits):
	return ''.join(random.choice(chars) for _ in range(size))

def hash_user_password(username, password):
	return md5.new("pitm_proxy|" + username + "|" + password).hexdigest()

@app.route('/')
def home():
	redirectto = flask_request.args.get('redirectto')
	return render_template('login.html', redirecturl=redirectto)

@app.route('/users', methods=['GET','POST'])
def users_manage():
	redirectto = ''
	message = ''
	try:
		redirectto = flask_request.values['redirectto']
	except KeyError:
		pass
		#ignore
	conn = sqlite3.connect('users.db')
	c = conn.cursor()
	loggedinusername = check_is_logged_in(flask_request, c, requireadmin=True)
	if not loggedinusername:
		return redirect("/", code=303)
		
	if flask_request.method == 'POST':
		try:
			username = flask_request.form['username']
			action = flask_request.form['action']
		
			if action == 'add':
				is_admin = 'n'
				try:
					is_admin = flask_request.form['admin']
				except KeyError:
					pass
				password = flask_request.form['password']
				password_hash = hash_user_password(username,password)
				try:
					c.execute("INSERT INTO users (username, password, loginip, admin, authid) VALUES (?, ?, '', ?, '')", (username, password_hash, is_admin[:1]))
					conn.commit()
					message = "User \"%s\" added" % username
				except sqlite3.Error:
					message = "Could not add user \"%s\"" % username
			elif action == 'delete':
				c.execute("DELETE FROM users WHERE username = ?", (username,))
				conn.commit()
				message = "User \"%s\" deleted" % username
			elif action == 'logout':
				c.execute("UPDATE users SET loginip = '', authid = '' WHERE username = ?", (username,))
				conn.commit()
				message = "Logged out user \"%s\"" % username
			elif action == 'changeadmin':
				admin_action = flask_request.form['admin']
				if "Remove" in admin_action:
					c.execute("UPDATE users SET admin = 'n' WHERE username = ?", (username,))
				else:
					c.execute("UPDATE users SET admin = 'y' WHERE username = ?", (username,))
				conn.commit()
		except KeyError:
			pass
			#ignore
			
	c.execute("SELECT username, loginip, admin FROM users")
	rows = c.fetchall()
	return render_template('users.html', redirecturl=redirectto, updatemessage=message, userrows=rows, loggedinuser=loggedinusername)

@app.route('/login', methods=['GET','POST'])
def login_user():
	redirectto = ''
	try:
		username = flask_request.form['username']
		password = flask_request.form['password']
		redirectto = flask_request.values['redirectto']
	except KeyError:
		pass
		#ignore

	if flask_request.method == 'GET':
		if redirectto:
			return redirect("/?redirectto=" + urllib.quote(redirectto, ''), code=303)
		else:
			return redirect("/", code=303)
	
	conn = sqlite3.connect('users.db')
	c = conn.cursor()
	c.execute("SELECT admin FROM users WHERE username = ? AND password = ?", (username, hash_user_password(username,password)))
	row = c.fetchone()
	if not row:
		return render_template('login.html',errormessage="Incorrect username or password")
	else:
		authid = random_id()
		c.execute("UPDATE users SET loginip = ?, authid = ? WHERE username = ?", (flask_request.remote_addr, authid, username))
		conn.commit()
		redirect_to_userpage = redirect("http://www.eskibars.com", code=303)
		if row[0] == 'y':
			if redirectto:
				redirect_to_userpage = redirect("/users?redirectto=" + urllib.quote(redirectto, ''), code=303)
			else:
				redirect_to_userpage = redirect("/users", code=303)
		else:
			if redirectto:
				redirect_to_userpage = redirect(redirectto, code=303)
			else:
				redirect_to_userpage = redirect("http://www.eskibars.com", code=303)
		response = app.make_response(redirect_to_userpage)
		response.set_cookie('auth',value=authid)
		return response

# Check if the given IP is allowed.  If so, we pass the request through.  If not, we redirect to the app
def request(context, flow):
	if flow.request.host == "users.proxy.eskibars.com":
		return
	conn = sqlite3.connect('users.db')
	c = conn.cursor()
	c.execute('SELECT username FROM users WHERE loginip = ?', (flow.client_conn.address.host,))
	row = c.fetchone()
	if not row:
		original_url = flow.request.url
		redirect_url = 'https://users.proxy.eskibars.com:443/?redirectto=' + urllib.quote(original_url, '')
		resp = HTTPResponse([1, 1], 303, 'Temporary Redirect', ODictCaseless([['Location', redirect_url]]), "")
		flow.reply(resp)

# Start up the application and check to see if a master admin password has been given.  If so, set it up 
def start(context, argv=[]):
	if len(argv) != 2:
		# no admin password was supplied in the start-up parameters.  check if there are already administrators
		conn = sqlite3.connect('users.db')
		c = conn.cursor()
		c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT, loginip TEXT, admin TEXT, authid TEXT)")
		conn.commit()
		
		# any admin account will do
		c.execute("SELECT password FROM users WHERE admin = 'y'")
		row = c.fetchone()
		if not row:
			raise ValueError('No admin password has been provided.  Use -s "pitm.py masterpassword" for initial set up')
	else:
		# password has been supplied here
		context.masterpassword = argv[1];
		conn = sqlite3.connect('users.db')
		c = conn.cursor()
		c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT, loginip TEXT, admin TEXT, authid TEXT)")
		conn.commit()
		
		# try to find the admin user
		c.execute("SELECT password FROM users WHERE username = 'admin'")
		row = c.fetchone()
		if not row:
			# there is no admin user.  create one
			c.execute("INSERT INTO users (username, password, loginip, admin, authid) VALUES ('admin', ?, '', 'y', '')", (hash_user_password("admin",context.masterpassword),))
			conn.commit()
		else:
			# there's already an admin user.  update their password with the provided password
			c.execute("UPDATE users SET password = ? WHERE username = 'admin'", (hash_user_password("admin",context.masterpassword),))
			conn.commit()
	conn.commit()
	conn.close()
	
	handler = RotatingFileHandler('usersdb.log', maxBytes=10000, backupCount=1)
	handler.setLevel(logging.INFO)
	app.logger.addHandler(handler)
	context.app_registry.add(app, "users.proxy.eskibars.com", 80)
	context.app_registry.add(app, "users.proxy.eskibars.com", 443)