

# api_key = 'AIzaSyBO0HZnIuHmIB7qalDQ-jTsT4bXbkcFLZM' 
from geopy.geocoders import GoogleV3
import requests


def address_decorator(func):
    def wrapper(self, request, *args, **kwargs):
        api_key = 'AIzaSyBO0HZnIuHmIB7qalDQ-jTsT4bXbkcFLZM'  # Replace with your actual Google Maps API key
        geolocator = GoogleV3(api_key=api_key)
        
        latitude = request.GET.get('latitude', None)
        longitude = request.GET.get('longitude', None)
        
        if latitude is not None and longitude is not None:
            location = f"{latitude}, {longitude}"
            
            try:
                address = geolocator.reverse(location)
                result = address.address if address else "Address not found"
                return func(self, request, *args, latitude=latitude, longitude=longitude, result=result, **kwargs)
            except Exception as e:
                return func(self, request, *args, latitude=latitude, longitude=longitude, result=f"Error: {str(e)}", **kwargs)
        else:
            return func(self, request, *args, latitude=None, longitude=None, result="Latitude or longitude not provided", **kwargs)

    return wrapper


def calculate_distance(lat1, lon1, lat2, lon2):
   
    google_api="AIzaSyBO0HZnIuHmIB7qalDQ-jTsT4bXbkcFLZM"
    url= f"https://maps.googleapis.com/maps/api/directions/json?origin={lat1},{lon1}&destination={lat2},{lon2}&key={google_api}"
    response = requests.get(url)
    data = response.json()
    if data["status"] == "OK":
        distance = data["routes"][0]["legs"][0]["distance"]["text"]
        maps_link = f"https://www.google.com/maps/dir/?api=1&origin={lat1},{lon1}&destination={lat2},{lon2}"
        return distance, maps_link
    else:
        return None


# Example coordinates (replace with user input or actual values)
input_latitude = 17.435548150158517
input_longitude = 78.38823573864391

