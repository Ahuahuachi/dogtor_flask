from flask import request

from . import api

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


@api.route("/species/")
def species():
    return []
