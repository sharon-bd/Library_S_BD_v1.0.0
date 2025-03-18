# models/__init__.py

"""Initialize the database and import all models for the library system."""

from .book import Book, BookType
from .customer import Customer 
from .loan import Loan 
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

 