from flask import Flask

from .api import api
from .config import Config
from .db import db


def create_app():
    app = Flask(__name__)

    app.config.from_object(Config)

    db.init_app(app)

    app.register_blueprint(api)

    return app


# owners
# pets
# species
# procedures
