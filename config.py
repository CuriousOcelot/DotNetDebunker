import os.path
from pathlib import Path

PROJECT_PATH=str(Path(__file__).parent.absolute())
RESOURCE_PATH=os.path.join(PROJECT_PATH, 'rsc')
TMP_PATH=os.path.join(PROJECT_PATH, 'tmp')
os.makedirs(RESOURCE_PATH, exist_ok=True)
os.makedirs(TMP_PATH, exist_ok=True)

PATH_TO_DNLIB_DLL=str(os.path.join(RESOURCE_PATH, 'lib',"dnlib.dll"))