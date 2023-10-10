from flask import Flask, request


def create_app():
    app = Flask(__name__)

    users = [
        {"id": 1, "username": "user0", "email": "user0@kodemia.mx"},
        {"id": 2, "username": "user1", "email": "user1@kodemia.mx"},
        {"id": 3, "username": "user2", "email": "user2@kodemia.mx"},
    ]

    @app.post("/users/auth")
    def auth():
        data = request.data
        return data

    @app.route("/users/<int:user_id>", methods=["GET", "PUT", "DELETE"])
    @app.route("/users/", methods=["GET", "POST"])
    def users_endpoint(user_id=None):
        if user_id is not None:
            found_user = None
            for user in users:
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
        return users

    @app.route("/home")
    @app.route("/")
    def hello():
        return "Hello Koders!"

    return app


# owners
# pets
# species
# procedures
