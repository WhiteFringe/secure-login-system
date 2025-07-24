import requests
from getmac import get_mac_address as get_mac_lib

def get_gps_location():
    try:
        response = requests.get("https://ipinfo.io/json")
        data = response.json()
        return data["loc"]
    except Exception as e:
        print("Error fetching GPS:", e)
        return "0.0,0.0"

def get_mac():
    mac = get_mac_lib()
    return mac or "00:00:00:00:00:00"
