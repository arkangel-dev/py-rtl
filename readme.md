# py-rtl
Python wrapper for RTL API (https://bo.rtl.mv). Implemented by intercepting traffic from RTL app. You can use this to purchase tickets programatically or check the location of RTL buses live.

### Usage
Purchasing a ticket
```py
from rtl import RtlWrapper, Constants

client = RtlWrapper('your-email-here', 'and-your-password-here')
client.LoginIfExpired()

product = client.GetProduct(
    route='Vilimale Ferry', 
    product='Villimale Single Trip',
    type=Constants.VehicleType.VESSEL
)
# Purchase a ticket
product.PurchaseTicket() 

# Turn this into a QR code to use it with the terminals
# on the buses / ferry terminals
print(product.tickets[0].qrContent) 
```

Example to monitor live location and call a function when vehicle enters a specific location 
```py
from rtl import RtlWrapper, Constants, LiveMonitoring

client = RtlWrapper('your-email-here', 'and-your-password-here')
client.LoginIfExpired()

def OnEntryOfRange(event:LiveMonitoring.Event):
    print("Bus {} is within range".format(event.vehicleCode))

if __name__ == '__main__':
    param = LiveMonitoring.Parameter()
    param.routes = ['145', '131']               # Select the routes to monitor
    param.coordinates = (4.174107, 73.486815)   # Select the point to monitor
    param.distance = 0.05                      # Trigger radius (In KM, defaults to 35 meters) 
    param.callback = OnEntryOfRange             # Method to call when bus enters 
    client.OnBusEntry(param)                    # Register the event
    input()                                     # Wait it out
```



### Note
The additonal optional parameters for constructor (`login_enc_key` and `login_enc_iv`) are the encryption parameters for the login and registration endpoint. What's happening is that before the login endpoint is called the payload is encrypted with the aforementioned encryption key and the server decrypts the payload to verify the login and send a JWT token. The key was extracted from an Android build of the RTL app.