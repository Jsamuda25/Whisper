from flask import Flask

def create_app():
    app = Flask(__name__)

    # Register blueprints (for routes)
    from .routes import app_routes
    app.register_blueprint(app_routes)

    return app
