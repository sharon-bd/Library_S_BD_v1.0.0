import sys
import os
import logging
from datetime import datetime, timedelta

# Adding the backend directory path to Python
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Importing modules
from app import app, db
from models.book import Book
from models.customer import Customer
from models.loan import Loan  

# Set up logging
logging.basicConfig(
    filename='system.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger()

def calculate_due_date(loan_date, book_type):
    """ Calculate the expected return date based on the book type """
    loan_periods = {1: 10, 2: 5, 3: 2}  # Define the number of days for each type
    return loan_date + timedelta(days=loan_periods.get(book_type, 10))  # Default: 10 days

def calculate_age(birth_date):
    """Calculate age based on birth date and current date"""
    today = datetime.today().date()
    age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
    return age

def create_sample_db():
    """
    Function that cleans and creates sample data in the database
    """
    with app.app_context():
        print("Cleaning and creating a new database...")
        db.drop_all()  # Deleting all tables
        db.create_all()  # Creating them again

        # Creating 10 sample books
        books = [
            Book(title="To Kill a Mockingbird", author="Harper Lee", year_published=1960, type=1, is_active=True, is_loaned=False),
            Book(title="1984", author="George Orwell", year_published=1949, type=2, is_active=True, is_loaned=False),
            Book(title="The Great Gatsby", author="F. Scott Fitzgerald", year_published=1925, type=1, is_active=True, is_loaned=False),
            Book(title="Moby Dick", author="Herman Melville", year_published=1851, type=3, is_active=True, is_loaned=False),
            Book(title="Pride and Prejudice", author="Jane Austen", year_published=1813, type=1, is_active=True, is_loaned=False),
            Book(title="The Catcher in the Rye", author="J.D. Salinger", year_published=1951, type=2, is_active=True, is_loaned=False),
            Book(title="The Grapes of Wrath", author="John Steinbeck", year_published=1939, type=1, is_active=True, is_loaned=False),
            Book(title="Brave New World", author="Aldous Huxley", year_published=1932, type=3, is_active=True, is_loaned=False),
            Book(title="The Adventures of Huckleberry Finn", author="Mark Twain", year_published=1884, type=2, is_active=True, is_loaned=False),
            Book(title="Of Mice and Men", author="John Steinbeck", year_published=1937, type=3, is_active=True, is_loaned=False)
        ]

        # Birth dates for customers
        birth_dates = [
            datetime.strptime("1998-03-22", "%Y-%m-%d").date(),  # John Smith
            datetime.strptime("1993-06-15", "%Y-%m-%d").date(),  # Jane Doe
            datetime.strptime("1988-01-10", "%Y-%m-%d").date(),  # Michael Johnson
            datetime.strptime("1995-11-05", "%Y-%m-%d").date(),  # Emily Davis
            datetime.strptime("1983-09-18", "%Y-%m-%d").date()   # Chris Brown
        ]
        
        # Customer names
        customer_names = [
            "John Smith",
            "Jane Doe",
            "Michael Johnson", 
            "Emily Davis",
            "Chris Brown"
        ]
        
        # Creating 5 sample customers with calculated ages
        customers = []
        for i in range(5):
            birth_date = birth_dates[i]
            age = calculate_age(birth_date)
            name = customer_names[i]
            
            # Log the calculated age both to console and system log
            log_message = f"{name}: {age}"
            print(log_message)
            logger.info(log_message)
            
            # Create customer with calculated age
            customers.append(
                Customer(
                    name=name,
                    city=["New York", "Los Angeles", "Chicago", "Houston", "Phoenix"][i],
                    age=age,
                    birth_date=birth_date,
                    is_active=True,
                    email=f"{name.lower().replace(' ', '.')}@example.com"
                )
            )

        # Adding the books and customers to the database
        db.session.add_all(books)
        db.session.add_all(customers)
        db.session.commit()  # Saving the data

        # Getting the relevant books and customers for loans
        late_books = books[-2:]  # The last two books
        late_customers = customers[-2:]  # The last two customers

        # Creating loans with dates from previous years and calculated return dates
        late_loans = [
            Loan(
                cust_id=late_customers[0].id,
                book_id=late_books[0].id,
                loan_date=datetime.strptime("2022-06-15", "%Y-%m-%d").date(),
                return_date=calculate_due_date(datetime.strptime("2022-06-15", "%Y-%m-%d").date(), late_books[0].type),
                customer_name=late_customers[0].name,
                book_name=late_books[0].title
            ),
          Loan(
            cust_id=late_customers[1].id,
            book_id=late_books[1].id,
            loan_date=datetime.strptime("2023-07-10", "%Y-%m-%d").date(),
            # Calculate return_date (due date) based on the book's type
            return_date=calculate_due_date(datetime.strptime("2023-07-10", "%Y-%m-%d").date(), late_books[1].type),
            customer_name=late_customers[1].name,
            book_name=late_books[1].title
        )
        ]

        # Adding the loans to the database for late loans
        db.session.add_all(late_loans)

        # **Updating the books that are loaned** - marking `is_loaned=True` for books in late_books
        for book in late_books:
            book.is_loaned = True
        
        db.session.commit()  # Saving the data after updating the loaned books

        # ---------------------------------------------------------
        # Adding a new loan to an existing customer who has not borrowed yet:
        #
        # 1. Finding an existing customer who has not borrowed a book (according to the existing order in the customer list).
        # 2. Finding a book that has not been borrowed according to the existing order.
        # 3. Calculating the original loan date based on the book's TYPE:
        #    - A new loan will have the DUE DATE (return_date) as the current execution date,
        #      and the loan_date will be calculated as (today - loan_period) where loan_period depends on the book's TYPE.
        # ---------------------------------------------------------
        # Finding an existing customer who has not borrowed a book (not appearing in previous queries)
        existing_customer = None
        used_customer_ids = {loan.cust_id for loan in late_loans}
        for customer in customers:
            if customer.id not in used_customer_ids:
                existing_customer = customer
                break

        # Finding a book that has not been borrowed
        new_book = None
        for book in books:
            if not book.is_loaned:
                new_book = book
                break

        if existing_customer and new_book:
            today = datetime.today().date()  # Today's date (Due Date will be today)
            loan_period = {1: 10, 2: 5, 3: 2}.get(new_book.type, 10)
            # Calculating the original loan date so the Due Date = today
            new_loan_date = today - timedelta(days=loan_period)
            
            new_loan = Loan(
                cust_id=existing_customer.id,
                book_id=new_book.id,
                loan_date=new_loan_date,  # Original date based on the loan period
                return_date=today,        # Due Date = Return Date will be today
                customer_name=existing_customer.name,
                book_name=new_book.title
            )
            new_book.is_loaned = True  # Marking the book as loaned
            db.session.add(new_loan)
            db.session.commit()  # Saving the data after adding the new loan

        # ---------------------------------------------------------
        # Adding a new loan to the fourth customer who has not borrowed yet:
        # - Finding the fourth customer from the customer list (index 3)
        # - Finding a TYPE1 book that has not been borrowed according to the existing order
        # - Creating a new loan, where the LOAN DATE will be today and the RETURN DATE will be calculated based on the book's TYPE
        fourth_customer = None
        if len(customers) >= 4:
            fourth_customer = customers[3]  # Fourth customer
        new_book_type1 = None
        for book in books:
            if not book.is_loaned and book.type == 1:
                new_book_type1 = book
                break

        if fourth_customer and new_book_type1:
            today = datetime.today().date()  # Today's date - the file execution date
            new_loan_date = today  # LOAN DATE = today
            new_return_date = calculate_due_date(new_loan_date, new_book_type1.type)
            
            new_loan2 = Loan(
                cust_id=fourth_customer.id,
                book_id=new_book_type1.id,
                loan_date=new_loan_date,
                return_date=new_return_date,
                customer_name=fourth_customer.name,
                book_name=new_book_type1.title
            )
            new_book_type1.is_loaned = True  # Marking the book as loaned
            db.session.add(new_loan2)
            db.session.commit()  # Saving the data after adding the new loan

sys.stdout.reconfigure(encoding='utf-8')  # Set UTF-8 encoding for prints

print("The database was successfully created with 10 books, 5 customers, and two late loans with books marked as loaned!")

if __name__ == "__main__":
    create_sample_db()  # Creating the sample data