from flask import Flask, redirect, url_for, session, request, jsonify, flash
from flask_oauthlib.client import OAuth
from flask import render_template

import pprint
import os

app = Flask(__name__)

app.debug = False #Change this to False for production

#comment out when done
# os.environ['OAUTHLIB_INSECURE_TRANSPORT']='1' 

app.secret_key = os.environ['SECRET_KEY']
oauth = OAuth(app)

#set up Github as the OAuth Provider
github = oauth.remote_app(
    'github',
    consumer_key=os.environ['GITHUB_CLIENT_ID'],
    consumer_secret=os.environ['GITHUB_CLIENT_SECRET'],
    request_token_params={'scope': 'user:email'}, #request read-only access to the user's email.  For a list of possible scopes, see developer.github.com/apps/building-oauth-apps/scopes-for-oauth-apps
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://github.com/login/oauth/access_token',  
    authorize_url='https://github.com/login/oauth/authorize' #URL for github's OAuth login
)

@app.context_processor
def inject_logged_in():
    return {"logged_in":('github_token' in session)}

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    return github.authorize(callback=url_for('authorized', _external=True, _scheme='https'))
    
@app.route('/page1')
def renderPage1():
    if 'user_data' in session and session['user_data']['location'] == 'Santa Barbara':
        secret = 'This is my secret.'
    else:
        secret = 'You need to live in Santa Barbara to see my secret.'
    return render_template('page1.html', secret=secret)

@app.route('/logout')
def logout():
    session.clear()
    flash('You were logged out.', "message")
    return render_template('home.html')

@app.route('/login/authorized')#the route should match the callback URL registered with the OAuth provider
def authorized():
    resp = github.authorized_response()
    if resp is None:
        session.clear()
        flash('Access denied: reason=' + request.args['error'] + ' error=' + request.args['error_description'] + ' full=' + pprint.pformat(request.args), "error")    
    else:
        try:
            #save user data and set log in message
            session['github_token'] = (resp['access_token'], '')
            session['user_data'] = github.get('user').data
            if github.get('user').data['location'] == 'Santa Barbara':
                flash("You were successfully logged in.", "message")
            else:
                session.clear()
                flash("You don't fill the requirements to log in.", "error")
        except Exception as inst:
            #clear the session and give error message
            session.clear()
            print(inst)
            flash("Unable to log in. Please try again.", "error")
    return render_template('home.html')
    
@github.tokengetter
def get_github_oauth_token():
    return session['github_token']


if __name__ == '__main__':
    app.run()