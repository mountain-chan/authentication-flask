from app.app import create_app
from app.settings import DevConfig, ProdConfig, os

# call config service
CONFIG = DevConfig if os.environ.get('FLASK_DEBUG') == '1' else ProdConfig

app = create_app(config_object=DevConfig)

if __name__ == '__main__':
    """Main Application
    python manage.py
    """
    app.run(host='0.0.0.0', port=5012, threaded=True, use_reloader=True)
