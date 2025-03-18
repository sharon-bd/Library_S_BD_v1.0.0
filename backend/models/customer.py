
from database import db  # Importing db from the database module


class Customer(db.Model):
    __tablename__ = 'customers'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    city = db.Column(db.String)
    age = db.Column(db.Integer)
    birth_date = db.Column(db.Date)
    email = db.Column(db.String(100), nullable=False, unique=True)
    is_active = db.Column(db.Boolean, default=True)  # Added is_active column

    loans = db.relationship('Loan', back_populates='customer')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'city': self.city,
            'age': self.age,
            'birth_date': self.birth_date,
            'email': self.email,
            'is_active': self.is_active,  # Added is_active to to_dict
        }
