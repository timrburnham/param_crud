import flask_wtf
import wtforms as wtf
import wtforms.validators as wtfv


class LoginForm(flask_wtf.FlaskForm):
    username = wtf.StringField('username', validators=[wtfv.InputRequired(), wtfv.Length(min=1, max=15)])
    password = wtf.PasswordField('password', validators=[wtfv.InputRequired(), wtfv.Length(min=8, max=80)])
    remember = wtf.BooleanField('remember me')

class RegisterForm(flask_wtf.FlaskForm):
    # email = wtf.StringField('email', validators=[wtfv.InputRequired(), wtfv.Email(message='Invalid email'), wtfv.Length(max=50)])
    username = wtf.StringField('username', validators=[wtfv.InputRequired(), wtfv.Length(min=1, max=15)])
    password = wtf.PasswordField('password', validators=[wtfv.InputRequired(), wtfv.Length(min=8, max=80)])
