import sys
import os

project_home = '/home/<your-username>/libas'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

os.environ['SECRET_KEY'] = 'random-secret'

from app import app as application
