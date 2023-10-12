from flask import request
from dogtor.db import db

from . import api, models

users_data = [
    {"id": 1, "username": "user0", "email": "user0@kodemia.mx"},
    {"id": 2, "username": "user1", "email": "user1@kodemia.mx"},
    {"id": 3, "username": "user2", "email": "user2@kodemia.mx"},
]


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


@api.route("/owners/")
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
