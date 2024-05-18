from __future__ import annotations
from typing import (
    Optional, 
    Dict, 
    Union, 
    Any, 
    ClassVar, 
    TypedDict
)

from datetime import datetime
from tls_client import Session
import re

from .exceptions import *
from .constants import HEADERS
from .util import is_email, score_password
from .crypt import dec, enc

session: Session = Session(
    client_identifier="chrome_119",
    random_tls_extension_order=True
)

class Settings(TypedDict):
    data_type: str
    has_manual_pass: str
    duration_hours: int
    dont_ask: str
    notify_email: str
    notify_ref: str

class PrivMessage:
    _password: Optional[bytes]
    _is_crypted: ClassVar[bool] = False
    _settings: Optional[Settings]

    def __init__(self, data: str = "", settings: Optional[Settings] = None) -> None:
        self._plain_text = data
        self._crypt_text: Optional[bytes] = None
        self._link: Optional[str] = None
        self._id: Optional[str] = None
        self._password = None
        self._response: Optional[Dict[str, Any]] = None
        self._settings = settings or {}

    @property
    def password(self) -> str:
        if self._password is None:
            raise ValueError("No password set, this note requires a password!")
            
        return self._password.decode()

    @password.setter
    def password(self, value: Union[str, bytes]) -> None:
        self._password = value.encode("utf-8") if isinstance(value, str) else value

    @property
    def link(self) -> str:
        return self._response['note_link'] if self._response and self._response["has_manual_pass"] else f"{self._response['note_link']}#{self.password}"

    @link.setter
    def link(self, value: str) -> None:
        match = re.match(r'https://privnote.com/([^#]+)(#.+)?', value)
        self._id, self._password = match.groups() if match else (value, None)
        self._link = value

    @property
    def id(self) -> str:
        return self._id or self._response['note_link'].replace("https://privnote.com/", "")

    @id.setter
    def id(self, value: str) -> None:
        self._id = value
        self._link = f"https://privnote.com/{value}"

    @property
    def plain_text(self) -> str:
        return self._plain_text

    def read_and_destroy(self) -> None:
        resp = session.delete(self.link, headers=HEADERS)
        self._response = resp.json()
        
        if not self._response.get("data") and self._response.get("destroyed"):
            raise NoteDestroyedException(
                note_id=self._id, 
                destroyed=datetime.fromisoformat(self._response["destroyed"])
            )
            
        self._crypt_text = self._response['data']

    def set_settings(
        self, 
        data: str, 
        manual_pass: Union[str, bytes] = False, 
        duration_hours: Optional[int] = None, 
        ask_confirm: bool = True, 
        notify_email: Union[str, bool] = False, 
        email_ref_name: str = ''
    ) -> None:
        password = manual_pass if isinstance(manual_pass, (str, bytes)) else score_password()
        self.password = password
        
        self._settings = Settings(
            data_type='T',
            has_manual_pass='true' if manual_pass else 'false',
            duration_hours=duration_hours or 0,
            dont_ask=str(not ask_confirm),
            notify_email=notify_email if isinstance(notify_email, str) and is_email(notify_email) else '',
            notify_ref=email_ref_name
        )
        self._plain_text = data
        self.encrypt()

    def decrypt(self) -> None:
        if self._password is None:
            raise IncorrectPasswordException(note_id=self._id)
            
        self._plain_text = dec(self._crypt_text, self._password)

    def encrypt(self) -> None:
        if self._password is None:
            raise IncorrectPasswordException(note_id=self._id)
            
        self._crypt_text = enc(self._plain_text, self._password)

    def send(self) -> None:
        self._settings.update({'data': self._crypt_text.decode()})
        response = session.post("https://privnote.com/legacy/", data=self._settings, headers=HEADERS)
        self._response = response.json()

# priv_note = PrivMessage("This is a secret message.")
# priv_note.set_settings(
#     manual_pass="my_secure_password",
#     duration_hours=24,
#     ask_confirm=False,
#     notify_email="example@example.com",
#     email_ref_name="Important Note"
# )
# priv_note.send()
# print(priv_note.link)
