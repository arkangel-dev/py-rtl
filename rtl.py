import base64
import json
import requests
import jwt
import time
import os

from typing import List, Optional
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from dataclasses import dataclass, fields, MISSING
from dacite import from_dict, Config

class Exceptions:
    class BlankDataException(Exception):
        def __init__(self, message):
            super().__init__(message)
            
    class NoCardAvailable(Exception):
        def __init__(self, message):
            super().__init__(message)

class DtoModels:

    @dataclass
    class GetBusRoutes:
        routeResponse: List["DtoModels.GetBusRoutes.BusLines"]

        @dataclass
        class AtollLines:
            name: str
            code: str
            routeResponse: List["DtoModels.GetBusRoutes.BusLines"]

        @dataclass
        class BusLines:
            id: int
            code: str
            name: str
            routeNumber: str
            busRouteStopList: List["DtoModels.GetBusRoutes.StopLine"]
            _wrapper:'Optional[RtlWrapper]'
            
            def GetProducts(self) -> 'DtoModels.GetProductDetails':
                return self._wrapper.GetProductDetails(routeCode=self.code, type='bus')
        

        @dataclass
        class StopLine:
            id: int
            order: int
            name: str
            latitude: str
            longitude: str
            timings: List["DtoModels.GetBusRoutes.Timings"]

        @dataclass
        class Timings:
            order: int
            timing: str

    @dataclass
    class GetVesselRoutes:
        routeResponse:List['DtoModels.GetVesselRoutes.Line']
        
        @dataclass
        class Line:
            id:int
            code:str
            name:str
            routeNumber:str
            fare:float
            stopList:List['DtoModels.GetVesselRoutes.StopLine']
            _wrapper:'Optional[RtlWrapper]'
            
            def GetProducts(self) -> 'DtoModels.GetProductDetails':
                return self._wrapper.GetProductDetails(routeCode=self.code, type='vessel')
        
        @dataclass
        class StopLine:
            id:int
            order:int
            code:str
            name:str
            latitude:str
            longitude:str
        
    @dataclass
    class GetLiveCoordinates:
        busList: List["DtoModels.GetLiveCoordinates.Line"]

        @dataclass
        class Line:
            busCode: str
            plateNumber: str
            latitude: float
            longitude: float

    @dataclass
    class GetProductDetails:
        id: int
        code: str
        name: str
        routeNumber: str
        products: List["DtoModels.GetProductDetails.Products"]

        @dataclass
        class Products:
            id: int
            code: str
            label: str
            validityTime: int
            productType: int
            qrTicketType: int
            cscTicketType: Optional[str]
            isTripFinite: int
            tripCount: int
            vehicleType: int
            description: Optional[str]
            fare: float
            isDistanceFareType: Optional[int]
            distanceFareComponent: Optional[str]
            validRoutes: List["DtoModels.GetProductDetails.Routes"]
            _wrapper:'Optional[RtlWrapper]'
            _parent:'Optional[DtoModels.GetProductDetails]'
            
            def PurchaseTicket(self):
                ticket = self._wrapper.BookTicket(productCode=self.code, routeCode=self._parent.code)
                url_resp = self._wrapper.PayBooking(ticket=ticket)
                print(ticket.bookingId)
                try:
                    requests.get(url_resp.url, timeout=10)
                except requests.exceptions.InvalidSchema:
                    pass

        @dataclass
        class Routes:
            id: int
            code: str
            name: str
            routeNumber: str

    @dataclass
    class BookTicketResult:
        message:str
        bookingId:str
        bookingDate:str
        isTokenized:int
        walletStatus:int
        walletBalance:Optional[str]
        paddedCardNumbers:'List[DtoModels.BookTicketResult.CardNumber]'
        
        @dataclass
        class CardNumber:
            cardId:int
            cardNumber:str

    @dataclass
    class PaymentResult:
        url:str

class RtlWrapper:
    login_enc_key: str
    login_enc_iv: str
    email: str
    password: str
    jwt_token: str
    token_file: str = "rtl.token"

    def __init__(
        self,
        email: str,
        password: str,
        login_enc_key="2023SCS@FT2840MOB6732947",
        login_enc_iv="JqxEoZbRvTfWgPmL",
    ) -> None:
        """Constructor

        Args:
            email (str): Email to login with
            password (str): Password to login with
            login_enc_key (str, optional): The encryption key the RTL dev thought would be a good idea to ship with the RTL app. Defaults to '2023SCS@FT2840MOB6732947'.
            login_enc_iv (str, optional): Initialization vector for the aforementioned encryption key. Defaults to 'JqxEoZbRvTfWgPmL'.
        """
        self.login_enc_key = login_enc_key
        self.login_enc_iv = login_enc_iv
        self.email = email
        self.password = password

    def _encrypt_data(self, data: str) -> str:
        """Encryption method used by the RTL app to 'secure' their traffic

        Args:
            data (str): data to encrypt

        Returns:
            str: Encrypted data
        """
        key = self.login_enc_key.encode("utf-8")
        iv = self.login_enc_iv.encode("utf-8")

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode("utf-8")) + padder.finalize()
        encrypted_bytes = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_base64 = base64.b64encode(encrypted_bytes).decode("utf-8")
        return encrypted_base64

    def _is_token_expired(self, token: str) -> bool:
        """Check if the token is expired

        Args:
            token (str): Token to check if expired

        Returns:
            bool: Indication to check if the token is expired
        """
        try:
            decoded_token = jwt.decode(
                self.jwt_token,
                verify=False,
                algorithms=["HS512"],
                options={"verify_signature": False},
            )
            exp = decoded_token.get("exp")
            if exp and time.time() > exp:
                return True
            return False
        except jwt.ExpiredSignatureError:
            return True
        except jwt.InvalidTokenError:
            return True

    def _read_token_from_file(self) -> str:
        """Read the token from the file

        Returns:
            str: File content
        """
        if os.path.exists(self.token_file):
            with open(self.token_file, "r") as file:
                token = file.read().strip()
            return token
        return None

    def _write_token_to_file(self, token:str) -> None:
        """Write a token to file

        Args:
            token (str): Token to save
        """
        with open(self.token_file, "w") as file:
            file.write(token)

    def _get_headers(self, payload: Optional[str] = None) -> dict:
        headers = {
            "Host": "bo.rtl.mv:4455",
            "Authorization": "Bearer " + self.jwt_token
        }
        if payload:
            headers["Content-Length"] = str(len(payload))
            headers["Content-Type"] = "application/json"
        return headers

    def LoginIfExpired(self):
        """Check if the cached token is valid. And if it is not, login"""
        self.jwt_token = self._read_token_from_file()
        if self.jwt_token and not self._is_token_expired(self.jwt_token):
            print("Token is valid.")
        else:
            print("Token is expired or doesn't exist. Logging in again.")
            new_token = self.Login()
            self._write_token_to_file(new_token)
            print("New token saved.")

    def Login(self) -> str:
        """Login and get a JWT key

        Returns:
            str: JWT key
        """
        request_data = {
            "email": self.email,
            "password": self.password,
            "channelId": 0,
            "versionName": "0.9.93",
        }
        json_string = json.dumps(request_data)
        encrypted_data = self._encrypt_data(json_string)
        endpoint = "https://bo.rtl.mv:4455/maldives/api/mobile/v3/customers/login"
        response = requests.put(endpoint, data=encrypted_data, timeout=10)
        self.jwt_token = response.json()["jwt"]
        return self.jwt_token

    def GetBusRoutes(self) -> DtoModels.GetBusRoutes:
        endpoint = "https://bo.rtl.mv:4455/maldives/api/booking/v2/bus/routedetails".format(type)
        headers = self._get_headers()
        response = requests.get(endpoint, headers=headers, timeout=10)
        return_obj = from_dict(
            data_class=DtoModels.GetBusRoutes,
            data=response.json(),
            config=Config(strict_unions_match=False),
        )
        for x in return_obj.routeResponse: x._wrapper = self
        return return_obj
        
    def GetVesselRoutes(self) -> DtoModels.GetVesselRoutes:
        endpoint = "https://bo.rtl.mv:4455/maldives/api/booking/v2/vessel/routedetails".format(type)
        headers = self._get_headers()
        response = requests.get(endpoint, headers=headers, timeout=10)
        return_obj = from_dict(
            data_class=DtoModels.GetVesselRoutes,
            data=response.json(),
            config=Config(strict_unions_match=False),
        )
        for x in return_obj.routeResponse: x._wrapper = self
        return return_obj

    def GetLiveCoordinates(self, routeCode: str) -> DtoModels.GetLiveCoordinates:
        endpoint = "https://bo.rtl.mv:4455/maldives/api/booking/v1/bus/livecoordinates"
        payload = json.dumps({"routeCode": routeCode})
        headers = self._get_headers(payload)
        response = requests.post(endpoint, data=payload, headers=headers, timeout=10)
        return from_dict(
            data_class=DtoModels.GetLiveCoordinates,
            data=response.json(),
            config=Config(strict_unions_match=False),
        )

    def GetProductDetails(self, routeCode: str, type:str = 'bus') -> DtoModels.GetProductDetails:
        endpoint = "https://bo.rtl.mv:4455/maldives/api/booking/v1/{}/productdetails".format(type)
        payload = json.dumps({"routeCode": routeCode, "deviceType": 0})
        headers = self._get_headers(payload)
        response = requests.post(endpoint, data=payload, headers=headers, timeout=10)
        if response.status_code == 500:
            raise Exceptions.BlankDataException("[500] You probably sent an invalid route code")
        return_obj = from_dict(
            data_class=DtoModels.GetProductDetails,
            data=response.json(),
            config=Config(strict_unions_match=False),
        )
        for p in return_obj.products:
            p._parent = return_obj
            p._wrapper = self
        return return_obj
    
    def BookTicket(self, routeCode: str, productCode:str, count:int = 1) -> DtoModels.BookTicketResult:
        endpoint = "https://bo.rtl.mv:4455/maldives/api/booking/v1/vessel/bookticket"
        payload = json.dumps({
                "routeCode": routeCode,
                "productCode": productCode,
                "ticketCount": count,
                "email": self.email,
                "deviceType": 0,
            })
        headers = self._get_headers(payload)
        response = requests.post(endpoint, data=payload, headers=headers, timeout=10)
        return_obj = from_dict(
            data_class=DtoModels.BookTicketResult,
            data=response.json(),
            config=Config(strict_unions_match=False),
        )
        return return_obj
    
    def PayBooking(self, ticket:DtoModels.BookTicketResult, cardId:Optional[int] = None):
        endpoint = "https://bo.rtl.mv:4455/maldives/api/booking/v1/vessel/payment"
        if cardId is None:
            firstCard = next(iter(ticket.paddedCardNumbers), None)
            if firstCard is None: raise Exceptions.NoCardAvailable('There are no cards available')
            cardId = firstCard.cardId
        payload = json.dumps({
            "bookingId": ticket.bookingId,
            "cardId": cardId,
            "paymentType": 1,
            "tokenize": 2
        })
        headers = self._get_headers(payload)
        response = requests.post(endpoint, data=payload, headers=headers, timeout=10)
        print(payload)
        print(response.content)
        return_obj = from_dict(
            data_class=DtoModels.PaymentResult,
            data=response.json(),
            config=Config(strict_unions_match=False),
        )
        return return_obj
