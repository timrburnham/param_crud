import configparser
import wtforms as wtf
import wtforms.validators as wtfv
import flask
import flask_sqlalchemy
import flask_wtf
import flask_login
import flask_bootstrap
from pathlib import Path
# import werkzeug.security as ws

config = configparser.ConfigParser(interpolation=None)
config.read(Path.home() / 'secret.ini')

app = flask.Flask(__name__)
app.config['SECRET_KEY'] = config.get('app', 'flask_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = config.get('app', 'dsn')
bootstrap = flask_bootstrap.Bootstrap(app)
db = flask_sqlalchemy.SQLAlchemy(app)
login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Schema():
    __table_args__ = { "schema": config.get('app', 'schema') }

class SystemJobControl(Schema, db.Model):
    job_nme = db.Column(db.String(8), primary_key=True)
    batch_cfg_id = db.Column(db.String(8), primary_key=True)
    job_desc = db.Column(db.String(255))
    sys_load_dtm = db.Column(db.DateTime)
    sys_updt_dtm = db.Column(db.DateTime)
    sys_updt_by = db.Column(db.String(18))
    notify = db.Column(db.String(255))

class SystemJobParameterValue(Schema, db.Model):
    job_nme = db.Column(db.String(8), primary_key=True)
    batch_cfg_id = db.Column(db.String(8), primary_key=True)
    etl_job_nme = db.Column(db.String(150), primary_key=True)
    parm_nme = db.Column(db.String(100), primary_key=True)
    parm_val = db.Column(db.String(1024))
    sys_load_dtm = db.Column(db.DateTime)
    sys_updt_dtm = db.Column(db.DateTime)
    sys_updt_by = db.Column(db.String(18))
    parm_actv_flg = db.Column(db.String(1))

class User(Schema, flask_login.UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)


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


@app.route('/job/', methods=['GET'])
# @flask_login.login_required
def job():
    rows = SystemJobControl.query.all()
    return flask.render_template("job.html", rows=rows)

@app.route('/param/', methods=['GET'])
def param():
    job_nme = flask.request.args.get('job_nme')
    batch_cfg_id = flask.request.args.get('batch_cfg_id')
    if job_nme and batch_cfg_id:
        rows = SystemJobParameterValue.query.filter_by(job_nme=job_nme).filter_by(batch_cfg_id=batch_cfg_id).all()
    elif job_nme:
        rows = SystemJobParameterValue.query.filter_by(job_nme=job_nme).all()
    else:
        job_nme = "All params"
        rows = SystemJobParameterValue.query.all()
    return flask.render_template("param.html", job_nme=job_nme, rows=rows)

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
