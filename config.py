from dotenv import load_dotenv
import os

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VI_API_KEY")