import flask
import flask_login
import flask_bootstrap
import datatables
from models import db, User, SystemJobControl, SystemJobParameterValue
from forms import LoginForm, RegisterForm
from config import config

# Flask app
app = flask.Flask(__name__)
app.config['SECRET_KEY'] = config.get('app', 'flask_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = config.get('app', 'dsn')
bootstrap = flask_bootstrap.Bootstrap(app)
db.init_app(app)

# Flask login manager
login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/job/', methods=['GET'])
def job():
    """Serve /job/ page"""
    return flask.render_template('job.html')

@app.route('/param/', methods=['GET'])
@app.route('/param/<job_nme>/', methods=['GET'])
@app.route('/param/<job_nme>/<batch_cfg_id>', methods=['GET'])
def param(job_nme=None, batch_cfg_id=None):
    """Serve /param/ page"""
    return flask.render_template("param.html", job_nme=job_nme, batch_cfg_id=batch_cfg_id)

@app.route('/api/v1/job/')
def apiv1_job():
    """Return job list to DataTables AJAX client."""
    columns = [
        datatables.ColumnDT(SystemJobControl.job_nme),
        datatables.ColumnDT(SystemJobControl.batch_cfg_id),
        datatables.ColumnDT(SystemJobControl.job_desc)
    ]

    # build query
    query = db.session.query().select_from(SystemJobControl)

    params = flask.request.args.to_dict()
    rowTable = datatables.DataTables(params, query, columns)
    return flask.jsonify(rowTable.output_result())

@app.route('/api/v1/param/')
@app.route('/api/v1/param/<job_nme>/')
@app.route('/api/v1/param/<job_nme>/<batch_cfg_id>')
def apiv1_param(job_nme=None, batch_cfg_id=None):
    """Return job parameters to DataTables AJAX client."""
    columns = [
        datatables.ColumnDT(SystemJobParameterValue.job_nme),
        datatables.ColumnDT(SystemJobParameterValue.batch_cfg_id),
        datatables.ColumnDT(SystemJobParameterValue.etl_job_nme),
        datatables.ColumnDT(SystemJobParameterValue.parm_nme),
        datatables.ColumnDT(SystemJobParameterValue.parm_val),
        datatables.ColumnDT(SystemJobParameterValue.parm_actv_flg)
    ]

    # build query
    query = db.session.query().select_from(SystemJobParameterValue)
    if job_nme:
        query = query.filter_by(job_nme=job_nme)
    if batch_cfg_id:
        query = query.filter_by(batch_cfg_id=batch_cfg_id)

    params = flask.request.args.to_dict()
    rowTable = datatables.DataTables(params, query, columns)
    return flask.jsonify(rowTable.output_result())

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
