from datetime import datetime, timedelta
from functools import wraps
import jwt
from flask import request
from werkzeug.security import generate_password_hash, check_password_hash
from dogtor.db import db
from dogtor.config import Config

from . import api, models

users_data = [
    {"id": 1, "username": "user0", "email": "user0@kodemia.mx"},
    {"id": 2, "username": "user1", "email": "user1@kodemia.mx"},
    {"id": 3, "username": "user2", "email": "user2@kodemia.mx"},
]


def token_required(func):
    @wraps(func)
    def wrapper():
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

        return func()

    return wrapper


@api.route("/profile/", methods=["POST"])
@token_required
def profile():
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


@api.route("/species/<int:species_id>", methods=["GET", "PUT", "DELETE"])
@api.route("/species/", methods=["GET", "POST"])
def species_endpoint(species_id=None):
    try:
        data = request.get_json()
    except:
        pass

    if species_id is not None:
        species = models.Species.query.get_or_404(species_id, "Species not found")
        if request.method == "GET":
            return {"id": species.id, "name": species.name}

        if request.method == "PUT":
            species.name = data["name"]
            msg = f"species {species.name} modified"

        if request.method == "DELETE":
            db.session.delete(species)
            msg = f"species {species.name} deleted"

        db.session.commit()
        return {"detail": msg}

    if request.method == "GET":
        species = models.Species.query.all()
        return [{"id": species.id, "name": species.name} for species in species]

    if request.method == "POST":
        species = models.Species(name=data["name"])

        db.session.add(species)
        db.session.commit()

        return {"detail": f"species {species.name} created successfully"}


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
