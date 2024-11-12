# coding=utf-8
import os
from datetime import datetime
from flask import Flask, render_template, session, redirect, \
    url_for, flash, current_app, request
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, LoginManager, login_required, \
    login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, \
    BooleanField, IntegerField, ValidationError
from wtforms.validators import DataRequired, Required, Length, Regexp
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash


from wtforms.validators import DataRequired, Length, EqualTo, ValidationError



import random
from xpinyin import Pinyin
from faker import Faker

fake = Faker('zh_CN')
total=15
'''
Config
'''
basedir = os.path.abspath(os.path.dirname(__file__))


def make_shell_context():
    return dict(app=app, db=db, Device=Device, User=User, Role=Role)


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = \
    'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['AdminPassword'] = 666666
app.config['SECRET_KEY'] = "this is a secret_key"
db = SQLAlchemy(app)
manager = Manager(app)
bootstrap = Bootstrap(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)
manager.add_command('shell', Shell(make_shell_context))
login_manager = LoginManager(app)

login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.login_message = u"你需要登录才能访问这个页面."

'''
Models
'''
class BorrowRecord(db.Model):
    __tablename__ = 'borrow_records'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    borrow_time = db.Column(db.DateTime, default=datetime.utcnow)
    return_time = db.Column(db.DateTime, nullable=True)

    # 定义外键关联
    device = db.relationship('Device', backref='borrow_records')
    user = db.relationship('User', backref='borrow_records')

    def __repr__(self):
        return '<BorrowRecord device_id=%r, user_id=%r>' % (self.device_id, self.user_id)


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role', lazy='dynamic')

    @staticmethod
    def insert_roles():
        roles = ('Student', 'Admin')
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %r>' % self.name


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.SmallInteger, unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128), unique=True, default=123456)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    devices = db.relationship('Device', backref='user', lazy='dynamic')
    can_del = db.Column(db.Boolean, default=False)  # 新增的权限属性，默认为 False

    # 添加新字段

    phone_number = db.Column(db.String(15), unique=True)

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            self.role = Role.query.filter_by(name='Student').first()


    def __repr__(self):
        return '<User %r>' % self.username

    def validate_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # 初次运行程序时生成初始管理员的静态方法
    @staticmethod
    def generate_admin():
        admin = Role.query.filter_by(name='Admin').first()
        u = User.query.filter_by(role=admin).first()
        if u is None:
            u = User(number='zhaowrenee@gmail.com', username='Admin', role=Role.query.filter_by(name='Admin').first())
            u.set_password('666666')
            db.session.add(u)
        db.session.commit()

    def verify_password(self, password):
        return self.password == password


class Device(UserMixin, db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), unique=True)
    lab = db.Column(db.String(64), unique=True, index=True)
    name = db.Column(db.String(64), index=True)
    time = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.String(64), db.ForeignKey('users.id'))

    # 添加 is_borrowed 字段
    is_borrowed = db.Column(db.Boolean, default=False)

    def __init__(self, **kwargs):
        super(Device, self).__init__(**kwargs)
        # 新添加的实验设备，初始其购置人为管理员。
        if self.user is None:
            self.user = User.query.filter_by(username='Admin').first()

    def __repr__(self):
        return '<Device %r>' % self.name

    def set_deviceID(self, str):
        self.device_id = str


'''
Forms
'''


class ProfileForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(1, 64)])
    number = StringField('邮箱', validators=[DataRequired(), Length(1, 64)])
    phone_number = StringField('手机号', validators=[DataRequired(), Length(1, 15)])
    password = PasswordField('新密码', validators=[Length(0, 32)])
    submit = SubmitField('保存更改')



class LoginForm(FlaskForm):
    number = StringField(u'账号', validators=[DataRequired(), Length(1, 32)])
    password_hash = PasswordField(u'密码', validators=[DataRequired(), Length(1, 32)])
    remember_me = BooleanField(u'记住我')
    submit = SubmitField(u'登录')


class RegisterForm(FlaskForm):
    number = StringField(u'账号', validators=[DataRequired(), Length(1, 32)])
    username = StringField(u'用户名', validators=[DataRequired(), Length(1, 64)])
    password = PasswordField(u'密码', validators=[DataRequired(), Length(1, 32)])
    confirm_password = PasswordField(u'确认密码', validators=[
        DataRequired(), Length(1, 32),
        EqualTo('password', message=u'密码必须匹配')  # 确保两次输入的密码一致
    ])
    submit = SubmitField(u'注册')






class PermissionForm(FlaskForm):
    user_id = IntegerField('用户ID', validators=[DataRequired()])
    can_del = BooleanField('删除权限')
    submit = SubmitField('更新权限')





class SearchForm(FlaskForm):
    name = StringField(u'设备名', validators=[DataRequired()])
    submit = SubmitField(u'搜索')


class DeviceForm(FlaskForm):
    name = StringField(u'设备名', validators=[DataRequired(), Length(1, 32)])
    lab = StringField(u'实验室名', validators=[DataRequired(), Length(1, 32)])
    user_name = StringField(u'购置人')
    # if not User.query.filter_by(username=user_name.data).first():
    #	raise ValidationError(u'用户不存在')
    # validate_name(user_name)
    # user_id = IntegerField(u'设备号', validators=[Required(message=u'请输入数字')])
    submit = SubmitField(u'添加')
    '''
    def validate_number(self, field):
        if Device.query.filter_by(id=field.data).first():
            raise ValidationError(u'此设备已存在，请检查考号！')
    '''

    def validate_user_name(self, field):
        if not User.query.filter_by(username=field.data).first():
            raise ValidationError(u'用户不存在')


'''
views
'''


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.number = form.number.data
        current_user.phone_number = form.phone_number.data
        if form.password.data:
            current_user.set_password(form.password.data)  # 更新密码
        db.session.commit()
        flash('您的信息已成功更新')
        return redirect(url_for('profile'))
    return render_template('profile.html', form=form)



@app.route('/my_borrowed_devices')
@login_required
def my_borrowed_devices():
    # 查询当前用户正在租借且未归还的设备
    borrowed_devices = BorrowRecord.query.filter_by(user_id=current_user.id, return_time=None).all()
    return render_template('my_borrowed_devices.html', borrowed_devices=borrowed_devices)






from datetime import datetime


@app.route('/borrow_device/<int:device_id>', methods=['POST'])
@login_required
def borrow_device(device_id):
    device = Device.query.get_or_404(device_id)
    if device.is_borrowed:
        flash(u'设备已被租借')
        return redirect(url_for('device_details', id=device_id))

    # 创建租借记录并更新设备状态
    record = BorrowRecord(device_id=device.id, user_id=current_user.id)
    device.is_borrowed = True
    db.session.add(record)
    db.session.commit()
    flash(u'设备已成功租借')
    return redirect(url_for('device_details', id=device_id))


@app.route('/return_device/<int:device_id>', methods=['POST'])
@login_required
def return_device(device_id):
    device = Device.query.get_or_404(device_id)
    if not device.is_borrowed:
        flash(u'设备未被租借')
        return redirect(url_for('device_details', id=device_id))

    # 查找最近的未归还记录并更新归还时间
    record = BorrowRecord.query.filter_by(device_id=device.id, return_time=None).first()
    record.return_time = datetime.utcnow()
    device.is_borrowed = False
    db.session.commit()
    flash(u'设备已成功归还')
    return redirect(url_for('device_details', id=device_id))


@app.route('/device/<int:id>', methods=['GET'])
@login_required
def device_details(id):
    device = Device.query.get_or_404(id)
    return render_template('device_details.html', device=device)











@app.route('/manage-permissions', methods=['GET', 'POST'])
@login_required
def manage_permissions():
    if not current_user.is_authenticated or current_user.role.name != 'Admin':
        flash(u'只有管理员可以访问此页面')
        return redirect(url_for('index'))

    form = PermissionForm()
    users = User.query.all()  # 获取所有用户

    if form.validate_on_submit():
        user = User.query.get(form.user_id.data)
        if user:
            user.can_del = form.can_del.data
            db.session.commit()
            flash(u'权限已更新')
        else:
            flash(u'用户不存在')
        return redirect(url_for('manage_permissions'))

    return render_template('manage_permissions.html', form=form, users=users)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # 检查用户名或账号是否已经存在
        if User.query.filter_by(number=form.number.data).first() or \
                User.query.filter_by(username=form.username.data).first():
            flash(u'账号或用户名已存在')
            return redirect(url_for('register'))

        # 创建新用户
        new_user = User(
            number=form.number.data,
            username=form.username.data,
            role=Role.query.filter_by(name='Student').first()
        )
        new_user.set_password(form.password.data)

        # 将用户保存到数据库
        db.session.add(new_user)
        try:
            db.session.commit()
            flash(u'注册成功！请登录')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash(u'注册失败，请重试')

    return render_template('register.html', form=form)


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    form = SearchForm()
    admin = Role.query.filter_by(name='Admin').first()
    if form.validate_on_submit():
        # 获得设备列表，其id包含form中的数字
        devices = Device.query.filter(Device.name.like('%{}%'.format(form.name.data))).all()
    else:
        devices = Device.query.order_by(Device.id.asc(), Device.name.desc()).all()
    return render_template('index.html', form=form, devices=devices, admin=admin)


# 增加新设备
@app.route('/add-device', methods=['GET', 'POST'])
@login_required
def add_device():
    form = DeviceForm()
    if form.validate_on_submit():
        global total
        total = total + 1
        print(total)
        device = Device(lab=form.lab.data, name=form.name.data,
                        user=User.query.filter_by(username=form.user_name.data).first())
        device.set_deviceID(
            "2020-" + Pinyin().get_initials(device.lab, u'')[0:2] + "-" + str(total).zfill(3))
        db.session.add(device)
        flash(u'成功添加设备')
        return redirect(url_for('index'))
    return render_template('add_device.html', form=form)


# 移除设备
@app.route('/remove-device/<int:id>', methods=['GET', 'POST'])
@login_required
def remove_device(id):
    device = Device.query.get_or_404(id)

    # 检查删除权限
    if not current_user.can_del:
        flash(u'没有权限删除设备')
        return redirect(url_for('index'))

    # 如果当前用户是管理员，可以删除设备
    if device.user == User.query.filter_by(username='Admin').first():
        flash(u'不能删除管理员添加的设备')
    else:
        db.session.delete(device)
        flash(u'成功删除此设备')

    return redirect(url_for('index'))



# 登录，系统只允许管理员登录
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(number=form.number.data).first()
        if user is not None and user.validate_password(
                form.password_hash.data):  # user.verify_password(form.password.data):
            if user.role != Role.query.filter_by(name='Admin').first():
                flash(u'系统只对管理员开放，请联系管理员获得权限！')
            else:
                login_user(user, form.remember_me.data)
                return redirect(url_for('index'))
        flash(u'用户名或密码错误！')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash(u'成功注销！')
    return redirect(url_for('login'))


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


# 加载用户的回调函数
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


'''
fake
'''

list = [u'联想启天2100', u'方正文祥600', u'DSP实验箱', u'功率变换器', u'双踪示波器', u'联想电脑845E', u'曙光天阔服务器', u'ZigBee开发套件', u'专业VR镜头',
        u'投影机']


def fake_user(count=10):
    for i in range(count):
        user = User(username=fake.name(),
                    number=fake.email(),
                    role_id=2)
        user.set_password('123456')
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()


def fake_device(count=10):
    #total = count
    for i in range(count):
        device = Device(name=random.choice(list),
                        user=User.query.get(random.randint(1, User.query.count())),
                        time=fake.date_time_this_year(),
                        lab=fake.company()[:-4] + "实验室")
        #device.set_deviceID(
        #    str(device.time[0:3]) + "-" + str(Pinyin().get_initials(device.lab[0:3], u'')) + "-" + str(i))
        device.set_deviceID(
            "2020-" + Pinyin().get_initials(device.lab, u'')[0:2] + "-" + str(i+1).zfill(3))
        #print("2020-" + Pinyin().get_initials(device.lab, u'')[0:2] + "-" + str(i+1))
        db.session.add(device)
        # print(str(device.time[0:3])+"-"+str(Pinyin().get_initials(device.lab[0:3],u''))+"-"+str(i))
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()

'''
增加命令'python app.py init' 
以增加身份与初始管理员帐号
'''


@manager.command
def init():
    from app import Role, User
    db.drop_all()
    db.create_all()
    Role.insert_roles()
    User.generate_admin()
    fake_user(10)
    fake_device(15)


if __name__ == '__main__':
    manager.run()
