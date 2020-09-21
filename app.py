import configparser
import wtforms as wtf
import wtforms.validators as wtfv
import flask
import flask_sqlalchemy
import flask_wtf
import flask_login
import flask_bootstrap
# import werkzeug.security as ws

config = configparser.ConfigParser(interpolation=None)
config.read('secret.ini')
db_url = config.get('app', 'db')
db_args = config['connection']

app = flask.Flask(__name__)
app.config['SECRET_KEY'] = config.get('app', 'sha_key')
app.config['SQLALCHEMY_DATABASE_URI'] = db_url.format(**db_args)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = flask_bootstrap.Bootstrap(app)
db = flask_sqlalchemy.SQLAlchemy(app)
login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(flask_login.UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)

class TAB(db.Model):
    K = db.Column(db.Integer, primary_key=True)
    V = db.Column(db.String(256))

# class Jobs(db.Model):


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(flask_wtf.FlaskForm):
    username = wtf.StringField('username', validators=[wtfv.InputRequired(), wtfv.Length(min=1, max=15)])
    password = wtf.PasswordField('password', validators=[wtfv.InputRequired(), wtfv.Length(min=8, max=80)])
    remember = wtf.BooleanField('remember me')

class RegisterForm(flask_wtf.FlaskForm):
    # email = wtf.StringField('email', validators=[wtfv.InputRequired(), wtfv.Email(message='Invalid email'), wtfv.Length(max=50)])
    username = wtf.StringField('username', validators=[wtfv.InputRequired(), wtfv.Length(min=1, max=15)])
    password = wtf.PasswordField('password', validators=[wtfv.InputRequired(), wtfv.Length(min=8, max=80)])


@app.route('/get/', methods=['GET'])
@app.route('/get/<int:id>', methods=['GET'])
@flask_login.login_required
def get(id=None):
    if id:
        rows = TAB.query.filter_by(K=id).all() # or .all()
    else:
        rows = TAB.query.all()

    return flask.render_template(
        "get.html",
        rows=rows
    )

@app.route('/')
def index():
    return flask.render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        # TODO: actual auth
        if user:
            # if ws.check_password_hash(user.password, form.password.data):
            if form.password.data == 'hotstuff':
                flask_login.login_user(user, remember=form.remember.data)
                return flask.redirect(flask.url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        # return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return flask.render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        # hashed_password = ws.generate_password_hash(form.password.data, method='sha256')
        # new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        new_user = User(username=form.username.data)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return flask.render_template('signup.html', form=form)

@app.route('/dashboard')
@flask_login.login_required
def dashboard():
    return flask.render_template('dashboard.html', name=flask_login.current_user.username)

@app.route('/logout')
@flask_login.login_required
def logout():
    flask_login.logout_user()
    return flask.redirect(flask.url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
