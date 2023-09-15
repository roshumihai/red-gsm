from flask import Flask, render_template, url_for, redirect, request, jsonify, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, FloatField, TextAreaField, SelectField, SubmitField, validators, PasswordField, IntegerField
from wtforms.validators import InputRequired, Length, ValidationError, Regexp
from sqlalchemy import func, desc
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
import uuid as uuid
import pytz
import os
import re

basedir = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(basedir, 'static/uploads')

db = SQLAlchemy()
app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///"+ os.path.join(basedir, "database.db")
app.config["SECRET_KEY"] = "Abecedar1234"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db.init_app(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Database Models Admin, User

class Admin(db.Model):
    admin_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('admin', uselist=False))

    def __init__(self, user=None, *args, **kwargs):
        super(Admin, self).__init__(*args, **kwargs)
        if user:
            self.user = user
            self.username = user.username

    def __repr__(self):
        return f"<Admin id:{self.admin_id}, user_id: {self.user_id}, user_username:{self.username}>"


class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime(), default=datetime.now())

    def __init__(self, username, password):
        self.username = username.lower()
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def __repr__(self):
        return f"<User id:{self.user_id}, username: {self.username}, member since: {self.created_at}"

    def is_active(self):
        return True

    def get_id(self):
        return str(self.user_id)

    def is_authenticated(self):
        return True


class Product(db.Model):
    product_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(255))
    price = db.Column(db.Integer, nullable=False)
    sale_price = db.Column(db.Integer)
    sold = db.Column(db.Boolean, default=False)
    image_ref = db.Column(db.String())
    created_at = db.Column(db.DateTime, default=datetime.now)

    def __init__(self, name, category, description, price, sale_price, sold=False, image_ref=None):
        self.name = name.lower()
        self.category = category.lower()
        self.description = description
        self.price = price
        self.sale_price = sale_price
        self.sold = sold
        self.image_ref = image_ref

    def __repr__(self):
        return f"<Product id:{self.product_id}, name: {self.name}, category: {self.category}, price: {self.price}>"



# Classes for FlaskForm

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()

        if existing_user_username:
            raise ValidationError("Username already exists. Please choose a different username.")

        return True

    def validate_password(self, password):
        if not re.search(r'[A-Z]', password.data):
            raise ValidationError("Pasword must contain at least one uppercase letter.")

        if not re.search(r'\d', password.data):
            raise ValidationError("Password must contain at least one digit.")

        if len(password.data) < 8:
            raise ValidationError("Password must be at least 8 characters long.")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


class AddAdmin(FlaskForm):
    admin_user = TextAreaField(render_kw={"placeholder": "Enter username"})
    submit = SubmitField("Add")


class AddProductForm(FlaskForm):
    name = StringField('Name', validators=[validators.InputRequired()])
    category = SelectField('Category', choices=[
        ('choose', 'Choose from the list'),
        ('phones', 'Phones'),
        ('laptops', 'Laptops'),
        ('displays', 'Displays'),
        ('batteries', 'Batteries'),
        ('phonecases', 'Phone Cases'),
        ('others', 'Others')
    ], validators=[validators.InputRequired()], default='choose')
    description = TextAreaField('Description')
    photo = FileField('Photo')
    price = IntegerField('Price', validators=[validators.InputRequired()])
    sale_price = IntegerField('Sale Price')
    submit = SubmitField('Add Product')


# Routes

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return redirect('dashboard')


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    form= AddProductForm()

    search_results_data = session.get('search_results', [])
    print(search_results_data)
    search_results = []

    for data in search_results_data:
        product_id = data['product_id']
        name = data['name']
        category = data['category']
        description = data.get('description', '')  # Provide a default value
        price = data['price']
        sale_price = data.get('sale_price', 0)
        sold = data.get('sold')

        product = Product( name.lower(), category.lower(), description, price, sale_price, sold)
        product.product_id = product_id
        search_results.append(product)

    all_products = Product.query.order_by(Product.product_id.desc()).all()

    if current_user.admin or current_user.username.lower() == "roshu":
        return render_template('admin.html', form=form, products=search_results, all_products=all_products)
    else:
        return "Unauthorized", 401


@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        form.validate_password(form.password)

        new_user = User(username=form.username.data, password=form.password.data)

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():

        username = form.username.data.lower()
        user = User.query.filter_by(username=username).first()

        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)

                return redirect(url_for('home'))
            else:
                form.password.errors.append("Incorrect password. Please try again.")
        else:
            form.username.errors.append("User does not exist.")

    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('dashboard'))


@app.route('/add-product', methods=['GET', 'POST'])
@login_required
def add_product():
    form = AddProductForm()
    product = None  # Initialize product as None

    if form.validate_on_submit() or form.is_submitted():
        name = form.name.data
        category = form.category.data
        description = form.description.data
        price = form.price.data
        sale_price = form.sale_price.data
        image_ref = request.files['image']

        if image_ref:
            filename = secure_filename(image_ref.filename)

            # Create a unique filename with UUID and save the uploaded file
            filename = str(uuid.uuid4()) + '_' + filename
            image_ref.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_ref = filename


            if sale_price is None or sale_price == "":
                sale_price = 0

            new_product = Product(name=name.lower(), category=category.lower(), description=description, price=price, sale_price=sale_price, image_ref=image_ref)

        else:
            if sale_price is None or sale_price == "":
                sale_price = 0

            new_product = Product(name=name.lower(), category=category.lower(), description=description, price=price, sale_price=sale_price)

        db.session.add(new_product)
        db.session.commit()

        form.name.data = ""
        form.category.data = ""
        form.description.data = ""
        form.price.data = ""
        form.sale_price.data = ""

        # Retrieve the newly added product
        product = new_product

    return render_template('add-product.html', form=form, product=product)


@app.route('/search_product', methods=['GET', 'POST'])
@login_required
def search_product():
    if request.method == 'POST':
        product_id = request.form.get('product-id')
        product_name = request.form.get('product-name').lower()
        product_category = request.form.get('product-category').lower()

        products = []

        if product_id:
            # Search for the product by ID
            product = Product.query.filter_by(product_id=product_id).first()
            if product:
                products.append(product)
        elif product_name:
            # Search for the product by name
            products = Product.query.filter(Product.name.ilike(f'%{product_name}%')).all()
        elif product_category:
            # Search for the product by category
            products = Product.query.filter_by(category=product_category).all()

        products_data = []
        for product in products:
            product_data = {
                'product_id': product.product_id,
                'name': product.name,
                'category': product.category,
                'description': product.description,
                'price': product.price,
                'sold': product.sold
            }
            products_data.append(product_data)

        # Store the search results in the session
        session['search_results'] = products_data

        return redirect(url_for('admin'))
    return render_template('search_product.html')

@app.route('/sell_product', methods=['GET', 'POST'])
@login_required
def sell_product():
    if request.method == "POST":
        product_id = request.form.get('product_id_forsale')
        sale_price = request.form.get('sale-price')

        if product_id and sale_price:
            product = Product.query.get(product_id)
            if product:
                product.sale_price = sale_price
                product.sold = True

                db.session.commit()

    return redirect(url_for('admin'))

@app.route('/phone.html', methods=['POST', 'GET'])
def phone():
    phones = Product.query.filter_by(category='phones').order_by(Product.product_id.desc()).all()

    return render_template('phone.html', phones=phones)

@app.route('/laptop.html', methods=['POST', 'GET'])
def laptop():
    laptops = Product.query.filter_by(category='laptops').order_by(Product.product_id.desc()).all()
    return render_template('laptop.html', laptops=laptops)

@app.route('/display.html', methods=['POST', 'GET'])
def display():
    displays = Product.query.filter_by(category='displays')
    return render_template('display.html', displays=displays)

@app.route('/batterie.html', methods=['POST', 'GET'])
def batterie():
    batteries = Product.query.filter_by(category='batteries')
    return render_template('batterie.html', batteries=batteries)

@app.route('/phonecase.html', methods=['POST', 'GET'])
def phonecase():
    phonecases = Product.query.filter_by(category='phonecases')
    return render_template('phonecase.html', phonecases=phonecases)

@app.route('/other.html', methods=['POST', 'GET'])
def other():
    others = Product.query.filter_by(category='others')
    return render_template('other.html', others=others)


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)