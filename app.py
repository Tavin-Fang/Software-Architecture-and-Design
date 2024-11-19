# coding=utf-8
import os  # 导入操作系统模块
from datetime import datetime  # 导入日期时间模块的datetime类
from flask import Flask, render_template, session, redirect, \
    url_for, flash, current_app, request  # 从Flask框架中导入必要的类和函数
from flask_script import Manager, Shell  # 导入Flask-Script的Manager和Shell类
from flask_migrate import Migrate, MigrateCommand  # 导入Flask-Migrate的Migrate和MigrateCommand类
from flask_bootstrap import Bootstrap  # 导入Flask-Bootstrap扩展
from flask_login import UserMixin, LoginManager, login_required, \
    login_user, logout_user, current_user  # 导入Flask-Login相关的类和装饰器
from flask_wtf import FlaskForm  # 导入Flask-WTF的FlaskForm类
from wtforms import StringField, PasswordField, SubmitField, SelectField, \
    BooleanField, IntegerField, ValidationError  # 导入WTForms中的字段类型和验证器
from wtforms.validators import DataRequired, Required, Length, Regexp  # 导入WTForms中的验证器
from flask_sqlalchemy import SQLAlchemy  # 导入Flask-SQLAlchemy扩展
from sqlalchemy.exc import IntegrityError  # 导入SQLAlchemy的完整性错误异常
from werkzeug.security import generate_password_hash, check_password_hash  # 导入Werkzeug的密码哈希生成和验证函数

from wtforms.validators import DataRequired, Length, EqualTo, ValidationError  # 重复导入WTForms的验证器
from flask_mail import Mail, Message  # 导入Flask-Mail的Mail和Message类

import random  # 导入随机数模块
from xpinyin import Pinyin  # 导入xpinyin模块用于拼音转换
from faker import Faker  # 导入Faker模块用于生成假数据

fake = Faker('zh_CN')  # 创建一个Faker实例，用于生成中文假数据
total = 15  # 初始化总数为15

'''
Config
'''
basedir = os.path.abspath(os.path.dirname(__file__))  # 获取当前文件的绝对路径

def make_shell_context():
    return dict(app=app, db=db, Device=Device, User=User, Role=Role)  # 定义Shell上下文，便于在命令行中访问这些对象

app = Flask(__name__)  # 创建Flask应用实例
app.config['SQLALCHEMY_DATABASE_URI'] = \
    'sqlite:///' + os.path.join(basedir, 'data.sqlite')  # 配置SQLAlchemy数据库URI，使用SQLite数据库
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True  # 配置在请求结束时自动提交数据库会话
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 禁用SQLAlchemy的事件系统，减少开销
app.config['AdminPassword'] = 666666  # 配置管理员密码
app.config['SECRET_KEY'] = "this is a secret_key"  # 配置应用的密钥，用于会话和表单保护
db = SQLAlchemy(app)  # 初始化SQLAlchemy对象
manager = Manager(app)  # 初始化Flask-Script的Manager对象
bootstrap = Bootstrap(app)  # 初始化Flask-Bootstrap
migrate = Migrate(app, db)  # 初始化Flask-Migrate
manager.add_command('db', MigrateCommand)  # 添加数据库迁移命令
manager.add_command('shell', Shell(make_shell_context))  # 添加Shell命令，带有上下文
login_manager = LoginManager(app)  # 初始化Flask-Login的LoginManager

login_manager.session_protection = 'strong'  # 设置会话保护级别为strong
login_manager.login_view = 'login'  # 设置登录视图函数
login_manager.login_message = u"你需要登录才能访问这个页面."  # 设置未登录时的提示信息

# 配置企业微信邮箱的 SMTP 和 IMAP 设置

app.config['MAIL_SERVER'] = 'smtp.exmail.qq.com'  # 设置SMTP服务器地址
app.config['MAIL_PORT'] = 465  # 设置SMTP服务器端口，使用SSL
app.config['MAIL_USE_SSL'] = True  # 启用SSL
app.config['MAIL_USERNAME'] = 'Service@tavin.cn'  # 设置邮箱用户名
app.config['MAIL_PASSWORD'] = 'Cyq3kU7iYUyJiedD'  # 设置邮箱密码或授权码
app.config['MAIL_DEFAULT_SENDER'] = ('实验室设备', 'Service@tavin.cn')  # 设置默认发送者信息

mail = Mail(app)  # 初始化Flask-Mail
def send_email(to, subject, template, **kwargs):
    msg = Message(subject, recipients=[to])  # 创建邮件消息对象
    msg.body = render_template(template + '.txt', **kwargs)  # 渲染纯文本邮件内容
    msg.html = render_template(template + '.html', **kwargs)  # 渲染HTML邮件内容
    mail.send(msg)  # 发送邮件


# ```
# yiyan
# ```
from requests import Session
import diskcache as dc
from rich.console import Console
from rich.markdown import Markdown

class YiYan:
    def __init__(self, appid, ak, sk):
        self.appid = appid
        self.ak = ak
        self.sk = sk
        self.s = Session()
        headers = {'Content-Type': 'application/json'}
        self.s.headers.update(headers)
        self.cache = dc.Cache('./cache')

    def get_access_token(self):
        key = 'access_token'
        access_token = self.cache.get(key)
        if not access_token:
            response = self.s.post(
                f'https://aip.baidubce.com/oauth/2.0/token?grant_type=client_credentials&client_id={self.ak}&client_secret={self.sk}',
                json='""'
            )
            access_token = response.json()['access_token']
            self.cache.set(key, access_token, expire=60 * 60 * 24 * 1)
        return access_token

    def generate_content(self, question):
        access_token = self.get_access_token()
        url = f"https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/eb-instant?access_token={access_token}"
        data = {"messages": [{"role": "user", "content": question}]}
        response = self.s.post(url, json=data)
        result = response.json()['result']
        return result
yiyan = YiYan(
    appid='115657247',
    ak='ATB4TtphGuNszmaKf4aHEbJ3',
    sk='zgD67ytH43jOD8r7NkvPM3zeOGMb6Y9W'
)
@app.route('/chatbot', methods=['GET', 'POST'])
def chatbot():
    response = None
    if request.method == 'POST':
        user_input = request.form.get('user_input')  # 获取用户输入
        if user_input:
            response = yiyan.generate_content(user_input)  # 调用智能客服接口
    return render_template('chatbot.html', response=response)  # 渲染客服页面


from flask import jsonify

@app.route('/chatbot/ask', methods=['POST'])
def chatbot_ask():
    user_input = request.json.get('user_input')  # 获取用户输入
    if not user_input:
        return jsonify({'error': '问题不能为空'}), 400
    response = yiyan.generate_content(user_input)  # 调用智能客服接口
    return jsonify({'response': response})  # 返回响应




'''
Models
'''
class BorrowRecord(db.Model):
    __tablename__ = 'borrow_records'  # 定义表名为borrow_records
    id = db.Column(db.Integer, primary_key=True)  # 定义主键id
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'))  # 定义外键关联到devices表的id
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # 定义外键关联到users表的id
    borrow_time = db.Column(db.DateTime, default=datetime.utcnow)  # 借出时间，默认当前时间
    return_time = db.Column(db.DateTime, nullable=True)  # 归还时间，允许为空

    # 定义外键关联
    device = db.relationship('Device', backref='borrow_records')  # 与Device模型的关系
    user = db.relationship('User', backref='borrow_records')  # 与User模型的关系

    def __repr__(self):
        return '<BorrowRecord device_id=%r, user_id=%r>' % (self.device_id, self.user_id)  # 定义对象的字符串表示

class Role(db.Model):
    __tablename__ = 'roles'  # 定义表名为roles
    id = db.Column(db.Integer, primary_key=True)  # 定义主键id
    name = db.Column(db.String(64), unique=True)  # 角色名称，唯一
    users = db.relationship('User', backref='role', lazy='dynamic')  # 定义与User模型的关系

    @staticmethod
    def insert_roles():
        roles = ('Student', 'Admin')  # 定义角色名称
        for r in roles:
            role = Role.query.filter_by(name=r).first()  # 查询是否存在该角色
            if role is None:
                role = Role(name=r)  # 如果不存在，则创建
            db.session.add(role)  # 添加到数据库会话
        db.session.commit()  # 提交会话

    def __repr__(self):
        return '<Role %r>' % self.name  # 定义对象的字符串表示

class User(UserMixin, db.Model):
    __tablename__ = 'users'  # 定义表名为users
    id = db.Column(db.Integer, primary_key=True)  # 定义主键id
    number = db.Column(db.SmallInteger, unique=True, index=True)  # 用户号码，唯一并建立索引
    username = db.Column(db.String(64), unique=True, index=True)  # 用户名，唯一并建立索引
    password_hash = db.Column(db.String(128), unique=True, default=123456)  # 密码哈希，唯一，默认值为123456
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))  # 定义外键关联到roles表的id
    devices = db.relationship('Device', backref='user', lazy='dynamic')  # 定义与Device模型的关系
    can_del = db.Column(db.Boolean, default=False)  # 删除权限，默认为False

    # 添加新字段
    phone_number = db.Column(db.String(15), unique=True)  # 电话号码，唯一
    can_add_device = db.Column(db.Boolean, default=False) #1119

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)  # 调用父类的初始化方法
        if self.role is None:
            self.role = Role.query.filter_by(name='Student').first()  # 如果没有指定角色，默认设置为Student

    def __repr__(self):
        return '<User %r>' % self.username  # 定义对象的字符串表示

    def validate_password(self, password):
        return check_password_hash(self.password_hash, password)  # 验证密码是否正确

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)  # 设置密码哈希

    # 初次运行程序时生成初始管理员的静态方法
    @staticmethod
    def generate_admin():
        admin = Role.query.filter_by(name='Admin').first()  # 查询Admin角色
        u = User.query.filter_by(role=admin).first()  # 查询是否存在Admin用户
        if u is None:
            u = User(number='zhaowrenee@gmail.com', username='Admin', role=Role.query.filter_by(name='Admin').first())  # 创建Admin用户
            u.set_password('666666')  # 设置密码
            db.session.add(u)  # 添加到数据库会话
        db.session.commit()  # 提交会话

    def verify_password(self, password):
        return self.password == password  # 验证密码（此方法可能有误，应使用password_hash）

class Device(UserMixin, db.Model):
    __tablename__ = 'devices'  # 定义表名为devices
    id = db.Column(db.Integer, primary_key=True)  # 定义主键id
    device_id = db.Column(db.String(64), unique=True)  # 设备唯一ID，唯一
    lab = db.Column(db.String(64), unique=True, index=True)  # 实验室名称，唯一并建立索引
    name = db.Column(db.String(64), index=True)  # 设备名称，建立索引
    time = db.Column(db.DateTime, default=datetime.utcnow)  # 创建时间，默认当前时间
    user_id = db.Column(db.String(64), db.ForeignKey('users.id'))  # 定义外键关联到users表的id

    # 添加 is_borrowed 字段
    is_borrowed = db.Column(db.Boolean, default=False)  # 设备是否被借出，默认为False

    def __init__(self, **kwargs):
        super(Device, self).__init__(**kwargs)  # 调用父类的初始化方法
        # 新添加的实验设备，初始其购置人为管理员。
        if self.user is None:
            self.user = User.query.filter_by(username='Admin').first()  # 如果没有指定用户，默认设置为Admin

    def __repr__(self):
        return '<Device %r>' % self.name  # 定义对象的字符串表示

    def set_deviceID(self, str):
        self.device_id = str  # 设置设备ID

'''
Forms
'''

class ProfileForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(1, 64)])  # 用户名字段，必填，长度1-64
    number = StringField('邮箱', validators=[DataRequired(), Length(1, 64)])  # 邮箱字段，必填，长度1-64
    phone_number = StringField('手机号', validators=[DataRequired(), Length(1, 15)])  # 手机号字段，必填，长度1-15
    password = PasswordField('新密码', validators=[Length(0, 32)])  # 新密码字段，长度0-32
    submit = SubmitField('保存更改')  # 提交按钮

class LoginForm(FlaskForm):
    number = StringField(u'账号', validators=[DataRequired(), Length(1, 32)])  # 账号字段，必填，长度1-32
    password_hash = PasswordField(u'密码', validators=[DataRequired(), Length(1, 32)])  # 密码字段，必填，长度1-32
    remember_me = BooleanField(u'记住我')  # 记住我复选框
    submit = SubmitField(u'登录')  # 登录按钮

class RegisterForm(FlaskForm):
    number = StringField(u'账号', validators=[DataRequired(), Length(1, 32)])  # 账号字段，必填，长度1-32
    username = StringField(u'用户名', validators=[DataRequired(), Length(1, 64)])  # 用户名字段，必填，长度1-64
    password = PasswordField(u'密码', validators=[DataRequired(), Length(1, 32)])  # 密码字段，必填，长度1-32
    confirm_password = PasswordField(u'确认密码', validators=[
        DataRequired(), Length(1, 32),
        EqualTo('password', message=u'密码必须匹配')  # 确保两次输入的密码一致
    ])
    submit = SubmitField(u'注册')  # 注册按钮

#添加设备权限1119
class PermissionForm(FlaskForm):
    user_id = IntegerField('用户ID', validators=[DataRequired()])
    can_del = BooleanField('删除权限')
    can_add_device = BooleanField('添加设备权限')  # 1119
    submit = SubmitField('更新权限')

class SearchForm(FlaskForm):
    name = StringField(u'设备名', validators=[DataRequired()])  # 设备名字段，必填
    submit = SubmitField(u'搜索')  # 搜索按钮

class DeviceForm(FlaskForm):
    name = StringField(u'设备名', validators=[DataRequired(), Length(1, 32)])  # 设备名字段，必填，长度1-32
    lab = StringField(u'实验室名', validators=[DataRequired(), Length(1, 32)])  # 实验室名字段，必填，长度1-32
    user_name = StringField(u'购置人')  # 购置人字段
    # if not User.query.filter_by(username=user_name.data).first():
    #    raise ValidationError(u'用户不存在')
    # validate_name(user_name)
    # user_id = IntegerField(u'设备号', validators=[Required(message=u'请输入数字')])
    submit = SubmitField(u'添加')  # 添加按钮
    '''
    def validate_number(self, field):
        if Device.query.filter_by(id=field.data).first():
            raise ValidationError(u'此设备已存在，请检查考号！')
    '''
    def validate_user_name(self, field):
        if not User.query.filter_by(username=field.data).first():
            raise ValidationError(u'用户不存在')  # 验证购置人是否存在

'''
views
'''
@app.route('/admin/borrowed_devices', methods=['GET', 'POST'])
@login_required
def admin_borrowed_devices():
    # 检查管理员权限
    if current_user.role.name != 'Admin':
        flash(u'只有管理员可以访问这个页面')
        return redirect(url_for('index'))

    # 查询当前所有已借出的记录
    borrowed_devices = BorrowRecord.query.filter_by(return_time=None).all()

    # 查询所有用户的租借记录历史
    all_borrow_records = BorrowRecord.query.order_by(BorrowRecord.borrow_time.desc()).all()

    return render_template('admin_borrowed_devices.html',
                           borrowed_devices=borrowed_devices,
                           all_borrow_records=all_borrow_records)


def send_return_reminder(user, device):
    send_email(
        user.number,  # 假设用户的邮箱在 `number` 字段
        '设备归还提醒',  # 邮件主题
        'email/return_reminder',  # 模板名为 `return_reminder`
        user=user,  # 传递用户对象
        device=device  # 传递设备对象
    )

@app.route('/send_return_reminder/<int:user_id>/<int:device_id>', methods=['POST'])
@login_required  # 需要登录才能访问
def send_return_reminder1(user_id, device_id):
    # 检查管理员权限
    if current_user.role.name != 'Admin':
        flash(u'只有管理员可以访问这个页面')  # 提示信息
        return redirect(url_for('index'))  # 重定向到首页

    user = User.query.get_or_404(user_id)  # 获取用户，如果不存在则返回404
    device = Device.query.get_or_404(device_id)  # 获取设备，如果不存在则返回404

    # 发送归还提醒邮件
    send_return_reminder(user, device)
    flash(f'已向用户 {user.username} 发送设备归还提醒')  # 提示信息
    return redirect(url_for('admin_borrowed_devices'))  # 重定向到管理员借出设备页面

@app.route('/profile', methods=['GET', 'POST'])
@login_required  # 需要登录才能访问
def profile():
    form = ProfileForm(obj=current_user)  # 创建个人资料表单，预填充当前用户数据
    if form.validate_on_submit():
        current_user.username = form.username.data  # 更新用户名
        current_user.number = form.number.data  # 更新账号
        current_user.phone_number = form.phone_number.data  # 更新手机号
        if form.password.data:
            current_user.set_password(form.password.data)  # 如果填写了新密码，则更新密码
        db.session.commit()  # 提交更改
        flash('您的信息已成功更新')  # 提示信息
        return redirect(url_for('profile'))  # 重定向到个人资料页面
    return render_template('profile.html', form=form)  # 渲染个人资料模板

@app.route('/my_borrowed_devices')
@login_required
def my_borrowed_devices():
    # 当前租借的设备
    borrowed_devices = BorrowRecord.query.filter_by(user_id=current_user.id, return_time=None).all()

    # 租借历史记录，包括已归还的设备
    borrow_history = BorrowRecord.query.filter_by(user_id=current_user.id).all()

    return render_template(
        'my_borrowed_devices.html',
        borrowed_devices=borrowed_devices,
        borrow_history=borrow_history
    )
#1119

from datetime import datetime  # 重复导入datetime模块

@app.route('/borrow_device/<int:device_id>', methods=['POST'])
@login_required  # 需要登录才能访问
def borrow_device(device_id):
    device = Device.query.get_or_404(device_id)  # 获取设备，如果不存在则返回404
    if device.is_borrowed:
        flash(u'设备已被租借')  # 提示信息
        return redirect(url_for('device_details', id=device_id))  # 重定向到设备详情页面

    # 创建租借记录并更新设备状态
    record = BorrowRecord(device_id=device.id, user_id=current_user.id)  # 创建租借记录
    device.is_borrowed = True  # 设置设备为已借出
    db.session.add(record)  # 添加记录到会话
    db.session.commit()  # 提交会话

    # 发送租借提醒邮件，包含租借时间
    send_email(
        current_user.number,  # 假设 `number` 字段是用户的邮箱
        '设备租借提醒',  # 邮件主题
        'email/borrow_notification',  # 模板名为 `borrow_notification`
        user=current_user,  # 传递当前用户对象
        device=device,  # 传递设备对象
        borrow_time=record.borrow_time.strftime('%Y-%m-%d %H:%M:%S')  # 格式化租借时间
    )

    flash(u'设备已成功租借')  # 提示信息
    return redirect(url_for('device_details', id=device_id))  # 重定向到设备详情页面

@app.route('/return_device/<int:device_id>', methods=['POST'])
@login_required
def return_device(device_id):
    device = Device.query.get_or_404(device_id)
    if not device.is_borrowed:
        return jsonify({'error': '设备未被租借'}), 400

    # 查找最近的未归还记录并更新归还时间
    record = BorrowRecord.query.filter_by(device_id=device.id, return_time=None).first()
    record.return_time = datetime.utcnow()
    device.is_borrowed = False
    db.session.commit()

    return jsonify({'message': '设备已成功归还'}), 200
#1119

@app.route('/device/<int:id>', methods=['GET'])
@login_required  # 需要登录才能访问
def device_details(id):
    device = Device.query.get_or_404(id)  # 获取设备，如果不存在则返回404

    # 检查是否是当前用户借的设备
    current_borrow_record = BorrowRecord.query.filter_by(device_id=device.id, return_time=None).first()
    if current_borrow_record:
        is_borrowed_by_current_user = current_borrow_record.user_id == current_user.id  # 判断是否为当前用户借出
    else:
        is_borrowed_by_current_user = False  # 如果没有借出记录，则为False

    return render_template('device_details.html', device=device,
                           is_borrowed_by_current_user=is_borrowed_by_current_user)  # 渲染设备详情模板

@app.route('/manage-permissions', methods=['GET', 'POST'])
@login_required
def manage_permissions():
    if not current_user.is_authenticated or current_user.role.name != 'Admin':
        flash(u'只有管理员可以访问这个页面')
        return redirect(url_for('index'))

    form = PermissionForm()
    users = User.query.all()

    if form.validate_on_submit():
        user = User.query.get(form.user_id.data)
        if user:
            user.can_del = form.can_del.data
            user.can_add_device = form.can_add_device.data  # 更新添加设备权限
            db.session.commit()
            flash(u'权限已更新')
        else:
            flash(u'用户不存在')
        return redirect(url_for('manage_permissions'))

    return render_template('manage_permissions.html', form=form, users=users)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()  # 创建注册表单
    if form.validate_on_submit():
        # 检查用户名或账号是否已经存在
        if User.query.filter_by(number=form.number.data).first() or \
                User.query.filter_by(username=form.username.data).first():
            flash(u'账号或用户名已存在')  # 提示信息
            return redirect(url_for('register'))  # 重定向到注册页面

        # 创建新用户
        new_user = User(
            number=form.number.data,
            username=form.username.data,
            role=Role.query.filter_by(name='Student').first()  # 设置用户角色为Student
        )
        new_user.set_password(form.password.data)  # 设置用户密码

        # 将用户保存到数据库
        db.session.add(new_user)  # 添加新用户到会话
        try:
            db.session.commit()  # 提交会话
            flash(u'注册成功！请登录')  # 提示信息
            return redirect(url_for('login'))  # 重定向到登录页面
        except IntegrityError:
            db.session.rollback()  # 回滚会话
            flash(u'注册失败，请重试')  # 提示信息

    return render_template('register.html', form=form)  # 渲染注册页面模板

@app.route('/', methods=['GET', 'POST'])
@login_required  # 需要登录才能访问
def index():
    form = SearchForm()  # 创建搜索表单
    admin = Role.query.filter_by(name='Admin').first()  # 获取Admin角色
    if form.validate_on_submit():
        # 获得设备列表，其名称包含表单中的名称
        devices = Device.query.filter(Device.name.like('%{}%'.format(form.name.data))).all()
    else:
        devices = Device.query.order_by(Device.id.asc(), Device.name.desc()).all()  # 获取所有设备，按id升序和名称降序排序
    return render_template('index.html', form=form, devices=devices, admin=admin)  # 渲染首页模板

# 增加新设备
@app.route('/add-device', methods=['GET', 'POST'])
@login_required
def add_device():
    if not current_user.can_add_device:  # 检查权限
        flash(u'您没有权限添加设备')
        return redirect(url_for('index'))

    form = DeviceForm()
    if form.validate_on_submit():
        global total
        total += 1
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
@login_required  # 需要登录才能访问
def remove_device(id):
    device = Device.query.get_or_404(id)  # 获取设备，如果不存在则返回404

    # 检查删除权限
    if not current_user.can_del:
        flash(u'没有权限删除设备')  # 提示信息
        return redirect(url_for('index'))  # 重定向到首页

    # 如果当前用户是管理员，可以删除设备
    if device.user == User.query.filter_by(username='Admin').first():
        flash(u'不能删除管理员添加的设备')  # 提示信息
    else:
        db.session.delete(device)  # 删除设备
        flash(u'成功删除此设备')  # 提示信息

    return redirect(url_for('index'))  # 重定向到首页

# 登录，系统只允许管理员登录
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()  # 创建登录表单
    if form.validate_on_submit():
        user = User.query.filter_by(number=form.number.data).first()  # 根据账号查询用户
        if user is not None and user.validate_password(
                form.password_hash.data):  # 验证用户存在且密码正确
            # if user.role != Role.query.filter_by(name='Admin').first():
            #     flash(u'系统只对管理员开放，请联系管理员获得权限！')
            # else:
                login_user(user, form.remember_me.data)  # 登录用户，设置记住我
                return redirect(url_for('index'))  # 重定向到首页
        flash(u'用户名或密码错误！')  # 提示信息
    return render_template('login.html', form=form)  # 渲染登录页面模板

@app.route('/logout')
@login_required  # 需要登录才能访问
def logout():
    logout_user()  # 注销用户
    flash(u'成功注销！')  # 提示信息
    return redirect(url_for('login'))  # 重定向到登录页面

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404  # 渲染404错误页面

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500  # 渲染500错误页面

# 加载用户的回调函数
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # 根据用户ID加载用户对象

'''
fake
'''

list = [u'联想启天2100', u'方正文祥600', u'DSP实验箱', u'功率变换器', u'双踪示波器', u'联想电脑845E', u'曙光天阔服务器', u'ZigBee开发套件', u'专业VR镜头',
        u'投影机']  # 定义设备名称列表

def fake_user(count=10):
    for i in range(count):
        user = User(username=fake.name(),
                    number=fake.email(),
                    role_id=2)  # 创建假用户，角色ID为2（假设为Student）
        user.set_password('123456')  # 设置假用户密码
        db.session.add(user)  # 添加用户到会话
        try:
            db.session.commit()  # 提交会话
        except IntegrityError:
            db.session.rollback()  # 回滚会话以处理重复或错误

def fake_device(count=10):
    #total = count
    for i in range(count):
        device = Device(name=random.choice(list),
                        user=User.query.get(random.randint(1, User.query.count())),
                        time=fake.date_time_this_year(),
                        lab=fake.company()[:-4] + "实验室")  # 创建假设备对象
        #device.set_deviceID(
        #    str(device.time[0:3]) + "-" + str(Pinyin().get_initials(device.lab[0:3], u'')) + "-" + str(i))
        device.set_deviceID(
            "2020-" + Pinyin().get_initials(device.lab, u'')[0:2] + "-" + str(i+1).zfill(3))  # 设置设备ID
        #print("2020-" + Pinyin().get_initials(device.lab, u'') + "-" + str(i+1))
        db.session.add(device)  # 添加设备到会话
        # print(str(device.time[0:3])+"-"+str(Pinyin().get_initials(device.lab,u''))+"-"+str(i))
    try:
        db.session.commit()  # 提交会话
    except IntegrityError:
        db.session.rollback()  # 回滚会话以处理重复或错误

'''
增加命令'python app.py init' 
以增加身份与初始管理员帐号
'''

@manager.command
def init():
    from app import Role, User  # 导入Role和User模型
    db.drop_all()  # 删除所有数据库表
    db.create_all()  # 创建所有数据库表
    Role.insert_roles()  # 插入角色数据
    User.generate_admin()  # 生成初始管理员用户
    fake_user(10)  # 生成10个假用户
    fake_device(15)  # 生成15个假设备

if __name__ == '__main__':
    manager.run()  # 运行管理器
