from dogtor.db import db
from sqlalchemy import Integer, String, DateTime
from sqlalchemy.orm import mapped_column


class User(db.Model):
    id = mapped_column(Integer, primary_key=True)
    first_name = db.Column(String(length=50), nullable=False)
    last_name = db.Column(String(length=50), nullable=True)
    email = db.Column(String, unique=True, nullable=False)
    password = db.Column(String, nullable=False)


class Owner(db.Model):
    """Pet owner object"""

    id = db.Column(Integer, primary_key=True)
    first_name = db.Column(String(length=50))
    last_name = db.Column(String(length=50))
    phone = db.Column(String(length=15))
    mobile = db.Column(String(length=15))
    email = db.Column(String)
    pets = db.relationship("Pet", bac_populates="owner")


class Species(db.Model):
    """Pet species object"""

    id = db.Column(Integer, primary_key=True)
    name = db.Column(String(length=20))
    pets = db.relationship("Pet", back_populates="species")


class Pet(db.Model):
    """Pet object"""

    id = db.Column(Integer, primary_key=True)
    name = db.Column(String(length=20))
    owner_id = db.Column(Integer, db.ForeignKey("owner.id"))
    age = db.Column(Integer)
    species_id = db.Column(Integer, db.ForeignKey("species.id"))
    record_id = db.Column(Integer, db.ForeignKey("record.id"))
    species = db.relationship("Species", back_populates="pets")
    owner = db.relationship("Owner", back_populates="pets")
    records = db.relationship("Record", back_populates="pets")


record_category_m2m = db.Table(
    "record_category",
    db.Column("record_id", Integer, db.ForeignKey("record.id")),
    db.Column("category_id", Integer, db.ForeignKey("category.id")),
)


class Record(db.Model):
    """Pet record object"""

    id = db.Column(Integer, primary_key=True)
    procedure = db.Column(String(length=255))
    pet = db.relationship("Pet", back_populates="records")
    date = db.Column(DateTime)
    categories = db.relationship(
        "Category", secondary=record_category_m2m, back_populates="records"
    )


class Category(db.Model):
    """Record category object"""

    id = db.Column(Integer, primary_key=True)
    name = db.Column(String(length=20))
    records = db.relationship(
        "Record", secondary=record_category_m2m, back_populates="categories"
    )
