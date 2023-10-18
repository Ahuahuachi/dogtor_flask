from datetime import datetime, timedelta
from functools import wraps

import jwt
from flask import request
from werkzeug.security import check_password_hash, generate_password_hash

from dogtor.config import Config
from dogtor.db import db

from . import api, models


def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        authorization = request.headers.get("Authorization")
        prefix = "Bearer "

        if not authorization:
            return {"detail": 'Missing "Authorization" header'}, 401

        if not authorization.startswith(prefix):
            return {"detail": "Invalid token prefix"}, 401

        token = authorization.split(" ")[1]
        if not token:
            return {"detail": "Missing token"}, 401

        try:
            payload = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
        except jwt.exceptions.ExpiredSignatureError:
            return {"detail": "Token expired"}, 401
        except jwt.exceptions.InvalidTokenError:
            return {"detail": "Invalid token"}, 401

        request.user = db.session.execute(
            db.select(models.User).where(models.User.id == payload["sub"])
        ).scalar_one()

        return func(*args, **kwargs)

    return wrapper


@api.route("/profile/", methods=["POST"])
@token_required
def profile():
    """Returns current user details"""
    user = request.user
    return {
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
    }


@api.route("/users/<int:user_id>", methods=["GET", "PUT", "DELETE"])
@api.route("/users/", methods=["GET", "POST"])
def users(user_id=None):
    if user_id is not None:
        found_user = None
        for user in users_data:
            if user["id"] == user_id:
                found_user = user

        if request.method == "PUT":
            return {"detail": f"user {found_user['username']} modified"}
        if request.method == "DELETE":
            return {"detail": f"user {found_user['username']} deleted"}

        return found_user

    if request.method == "POST":
        data = request.data
        return {"detail": f"user {data['username']} created"}
    return users_data


@api.route("/pets/")
def pets():
    return []


@api.route("/owners/", methods=["POST"])
@token_required
def owners():
    return []


@api.route("/procedures/")
def procedures():
    return []


@api.get("/species/")
@token_required
def get_all_species():
    """Returns all pet species"""
    query = db.select(models.Species)
    result = db.session.execute(query).scalars()

    return [species.to_dict() for species in result]


@api.get("/species/<int:species_id>")
@token_required
def get_one_species(species_id):
    """Returns a single species"""
    query = db.select(models.Species).where(models.Species.id == species_id)
    species = db.session.execute(query).scalar()
    if species is None:
        return {"detail": "Species not found"}, 404
    return species.to_dict()


@api.post("/species/")
@token_required
def create_species():
    """Create a new pet species"""
    data = request.get_json()
    if "name" not in data:
        return {"detail": 'Field "name" is required'}, 400

    query = db.select(models.Species).where(
        db.func.lower(models.Species.name) == db.func.lower(data["name"])
    )
    if db.session.execute(query).scalar():
        return {"detail": "Species already exists"}, 409

    species = models.Species(name=data["name"])
    db.session.add(species)
    db.session.commit()

    return species.to_dict(), 201


@api.put("/species/<int:species_id>")
@token_required
def update_species(species_id):
    """Update a pet species"""
    data = request.get_json()
    if "name" not in data:
        return {"detail": 'Field "name" is required'}, 400

    species = db.session.execute(
        db.select(models.Species).where(models.Species.id == species_id)
    ).scalar()
    species.name = data["name"]
    db.session.commit()

    return species.to_dict()


@api.delete("/species/<int:species_id>")
@token_required
def delete_species(species_id):
    """Delete a pet species"""
    species = db.session.execute(
        db.select(models.Species).where(models.Species.id == species_id)
    ).scalar()
    if not species:
        return {"detail": "Species not found"}, 404

    db.session.delete(species)
    db.session.commit()

    return {"detail": "Species deleted"}, 200


@api.route("/signup/", methods=["POST"])
def signup():
    data = request.get_json()
    email = data.get("email")

    if not email:
        return {"detail": "email is required"}, 400

    user_exists = db.session.execute(
        db.select(models.User).where(models.User.email == email)
    ).scalar_one_or_none()

    if user_exists:
        return {"detail": "email already taken"}, 400

    password = data.get("password")

    user = models.User(
        first_name=data.get("first_name"),
        last_name=data.get("last_name"),
        email=email,
        password=generate_password_hash(password),
    )
    db.session.add(user)
    db.session.commit()
    return {"detail": "user created successfully"}, 201


@api.route("/login/", methods=["POST"])
def login():
    """Login an app user"""
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return {"detail": "missing email or password"}, 400

    user = db.session.execute(
        db.select(models.User).where(models.User.email == email)
    ).scalar_one_or_none()

    if not user or not check_password_hash(user.password, password):
        return {"detail": "invalid email or password"}, 401

    token = jwt.encode(
        {
            "sub": user.id,
            "exp": datetime.utcnow() + timedelta(minutes=30),
        },
        Config.SECRET_KEY,
    )

    return {"token": token}
