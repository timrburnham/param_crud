import flask_sqlalchemy
import flask_login
from config import config

db = flask_sqlalchemy.SQLAlchemy()


class Schema():
    # TODO! figure out how to get the config back
    # __table_args__ = { "schema": config.get('app', 'schema') }
    __table_args__ = { "schema": 'T41654B' }

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
