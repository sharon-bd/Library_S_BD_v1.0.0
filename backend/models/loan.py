from flask import Blueprint, jsonify, request 
from database import db
from datetime import datetime, timezone  # adding timezone
from sqlalchemy import event
from models.customer import Customer
from models.book import Book

loan_blueprint = Blueprint('loan', __name__)

class Loan(db.Model):
    __tablename__ = 'loans'
    
    id = db.Column(db.Integer, primary_key=True)
    cust_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)  
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False)  
    loan_date = db.Column(db.Date, nullable=False, default=lambda: datetime.now(timezone.utc).date())
    return_date = db.Column(db.Date, nullable=True)  # This is DUE DATE, not actual return date
    
    customer_name = db.Column(db.String, nullable=True)
    book_name = db.Column(db.String, nullable=True)

    customer = db.relationship('Customer', back_populates='loans', lazy="joined")
    book = db.relationship('Book', back_populates='loans', lazy="joined")

    def to_dict(self):
        # Convert loan object to dictionary for JSON response
        return {
            'id': self.id,
            'customer_name': self.customer_name or "Unknown",
            'book_title': self.book_name or "Unknown",
            'book_author': self.book.author if self.book else "Unknown",
            'loan_date': self.loan_date.strftime('%Y-%m-%d') if self.loan_date else None,
            'return_date': self.return_date.strftime('%Y-%m-%d') if self.return_date else None,  # Due date
            'book_id': self.book.id if self.book else None,
            'cust_id': self.cust_id
        }

def populate_loan_names(mapper, connection, target):
    # Update customer_name and book_name when creating/updating a loan
    customer = Customer.query.get(target.cust_id)
    book = Book.query.get(target.book_id)
    
    target.customer_name = customer.name if customer else None
    target.book_name = book.title if book else None

event.listen(Loan, 'before_insert', populate_loan_names)
event.listen(Loan, 'before_update', populate_loan_names)

# Define a GET route for retrieving all loans
# This route will be accessible at /api/loans when registered with the app

@loan_blueprint.route('/loans', methods=['GET'])
def get_loans_blueprint():
    # Get query parameters
    cust_id = request.args.get('cust_id')  # Optional filter by customer ID
    
    query = Loan.query
    if cust_id:
        query = query.filter(Loan.cust_id == cust_id)  # Filter by customer ID if provided
    
    # All loans in the table are active (not returned yet)
    loans = query.all()
    loans_list = [loan.to_dict() for loan in loans]

    return jsonify({"loans": loans_list}), 200