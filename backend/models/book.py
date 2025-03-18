from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.orm import relationship
from database import db
from enum import Enum
from sqlalchemy import event
from sqlalchemy.exc import StatementError

LOAN_PERIODS = {
    1: 'Up to 10 days',
    2: 'Up to 5 days',
    3: 'Up to 2 days'
}

class BookType(Enum):
    TYPE1 = 1  # Up to 10 days
    TYPE2 = 2  # Up to 5 days
    TYPE3 = 3  # Up to 2 days

class Book(db.Model):
    __tablename__ = 'books'
    
    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    author = Column(String, nullable=False)
    year_published = Column(Integer, nullable=True)
    type = Column(Integer, nullable=True)  # Remains as Integer
    is_active = Column(Boolean, default=True)
    loan_period = Column(Integer, nullable=True)
    is_loaned = Column(Boolean, default=False)

    loans = relationship('Loan', back_populates='book')

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'author': self.author,
            'year_published': self.year_published,
            'type': LOAN_PERIODS.get(self.type, 'Unknown'),
            'is_active': self.is_active,
            'loan_period': self.loan_period,
        }

    def set_loan_period(self):
        """Set loan period based on the 'type' of the book."""
        if self.type == 1:
            self.loan_period = 10
        elif self.type == 2:
            self.loan_period = 5
        elif self.type == 3:
            self.loan_period = 2
        else:
            self.loan_period = None  # If no valid type is defined


# During value conversion
def handle_enum_conversion(data):
    try:
        return BookType(int(data))  # Convert numeric value to Enum
    except ValueError:
        raise StatementError("Invalid type value provided", None, None)


# Event functions
def set_loan_period_before_insert(mapper, connection, target):
    """Set loan period before inserting a new book if 'type' is defined."""
    target.set_loan_period()

def set_loan_period_before_update(mapper, connection, target):
    """Set loan period before updating a book if 'type' is defined."""
    target.set_loan_period()

# Listen for events to set loan_period only if type changes
event.listen(Book, 'before_insert', set_loan_period_before_insert)
event.listen(Book, 'before_update', set_loan_period_before_update)
