1)AES-256-GCM

Authenticated encryption provides:

Confidentiality
Integrity
Authentication of ciphertext

2)Key management

Each encrypted file has its own AES key.
The AES key is protected before being stored.

Original key length: 32
Protected key length: 140
Recovered key length: 32
KEY MANAGEMENT TEST PASSED


3)CSRF protection

tested removing the CSRF token and received:

Bad Request
The CSRF token is missing.


4)Authorization

User 2 attempting to access User 1's encrypted file produced:

File not found or access denied
application logged:
ACCESS_DENIED


5)Tamper detection

modified one byte of the encrypted file.

AES-GCM rejected it:
DECRYPTION_FAILED

and the browser reported:
Decryption failed.
The file may have been modified or the key is invalid.



