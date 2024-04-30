#!/usr/bin/python
# -*- coding: utf-8 -*-

from typing import Union, Optional, Dict

from datetime import datetime
from tls_client import Session 

from .exceptions import *
from .constants import HEADERS
from .util import is_email, score_password
from .crypt import dec, enc

session = Session(
    client_identifier="chrome_119",
    random_tls_extension_order=True
)

class PrivMessage(object):
    def __init__(self) -> None:
        self._plain_text: Optional[str] = None
        self._crypt_text: Optional[bytes] = None
        
        self._link: Optional[str] = None
        self._id: Optional[str] = None
        
        self._password: Optional[bytes] = None
        self._is_crypted: bool = False
        
        self._settings: Optional[Dict[str, Union[str, int, bool]]] = None
        self._response: Optional[Dict[str, Union[str, bool]]] = None

    @property
    def password(self) -> str:
        if not self._password:
            raise ValueError("No password set, this note requires a password!")

        return self._password.decode()

    @password.setter
    def password(self, value: Union[str, bytes]) -> None:
        if isinstance(value, str):
            self._password = value.encode("utf-8")
        elif isinstance(value, (bytes, bytearray)):
            self._password = value

    @property
    def link(self) -> str:
        """
        Form link fallowing privnote rules
        :return: str
            Link to read the note. If no manual_password was given then password concatenates to link with '#' sep
        """
        return self._response['note_link'] if self._response and self._response["has_manual_pass"] else f"{self._response['note_link']}#{self.password}"

    @link.setter
    def link(self, value: str) -> None:
        """Set link and parse"""

        value = value.split("https://privnote.com/")[1] if value.startswith("privnote.com/") else value
        self._id, self._password = value.split("#", maxsplit=1) if "#" in value else (value, None)

    @property
    def id(self) -> str:
        return self._id or self._response['note_link'].replace("https://privnote.com/", "")

    @id.setter
    def id(self, value: str) -> None:
        self._id = value
        self._link = "https://privnote.com/" + value

    @property
    def plain_text(self) -> str:
        return self._plain_text

    def read_and_destroy(self) -> None:
        """
        Receives note from privnote.com thereby destroy note and nobody can read it anymore
        :raises
            NoteDestroyedException if note already readed or self-destructed
            IncorrectIDException if note with id cant be fond

        """
        resp = requests.delete(self.link, headers=HEADERS)
        
        try:
            self._response = resp.json()
        except ValueError:
            raise IncorrectIDException(note_id=self._id)
            
        if not self._response.get("data"):
            if self._response.get("destroyed"):
                raise NoteDestroyedException(
                    note_id=self._id, 
                    destroyed=datetime.strptime(self._response["destroyed"], "%Y-%m-%dT%H:%M:%S.%f")
                )
            else:
                raise PrivnoteException("No data in response")
                
        self._crypt_text = self._response['data']

    def set_settings(
        self, 
        data: str, 
        manual_pass: Union[str, bytes] = False, 
        duration_hours: Optional[int] = None, 
        ask_confirm: bool = True, 
        notify_email: Union[str, bool] = False, 
        email_ref_name: str = ''
    ) -> str:
        """
        Parse and stores arguments. Forms settings dict to send. Forms data and password to encrypt

        :param data: str
            String data for noting

        :param manual_pass: str, byte-like
            Every false value means auto generating pass 9 alphadigit chars
            manual password must be str or byte-like object. Using byte-like object may cause inability
            to read note via privnote web interface.

        :param duration_hours: integer [0-720]
            Hours of life for note, that will self-destroyed on expiry. 0 or every false value
            means self-destruct after reading. Anyway note life can't be more then 720 hours (30 days)

        :param ask_confirm: boolean
            Every true value means ask for confirmation before showing and destroying the note.
            Every false value means do not ask for confirmation (Privnote Classic behaviour)

        :param notify_email: str
            E-mail to notify when note is destroyed. Every false value means no notification

        :param email_ref_name: str
            Reference name for the note that will be sent to notification email when it destruct

        :return: str
            Notelink for reading Note. If manual_pass was given, autogenerating password concatenate to link
        """

        settings = {'data_type': 'T'}
        password = manual_pass if isinstance(manual_pass, (str, bytes)) else score_password()
        settings['has_manual_pass'] = "true" if manual_pass else "false"

        if duration_hours is not None and duration_hours > 720:
            raise ValueError("Duration hours cannot exceed 720.")
            
        settings['duration_hours'] = duration_hours or 0
        settings['dont_ask'] = str(not ask_confirm)
        
        if notify_email:
            if is_email(notify_email):
                settings['notify_email'] = notify_email
                settings['notify_ref'] = email_ref_name
            else:
                raise ValueError("Notify email is incorrect!")
        else:
            settings['notify_email'] = settings['notify_ref'] = ""
            
        self._plain_text = data
        self.password = password
        self._settings = settings

    def decrypt(self) -> None:
        """Decrypts note"""

        try:
            self._plain_text = dec(self._crypt_text, self._password)
        except ValueError:
            raise IncorrectPasswordException(note_id=self._id)

    def encrypt(self) -> None:
        """Encrypts note"""

        try:
            self._crypt_text = enc(self._plain_text, self._password)
        except ValueError:
            raise IncorrectPasswordException(note_id=self._id)

    def send(self) -> None:
        """Sends data with note settings to privnote server and stores response"""

        data_to_send = {
            **self._settings, 
            'data': self._crypt_text.decode()
        }
        response = requests.post(
            "https://privnote.com/legacy/", 
            data=data_to_send, 
            headers=HEADERS
        )
        self._response = response.json()
