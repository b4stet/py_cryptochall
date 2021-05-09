# py_cryptochall

Implementation of cryptopals challenges (https://cryptopals.com/) in python3.

Modularity added to allow reuse in other challenges:
- encoders (integer to bytes, to hex, to ascii, to base64 etc) in `utils`
- oracles as web servers
- attacks
- xor and aes encryption in `crypter` 

To run:
```
$ pip3 install -r requirements.txt
$ python3 main_set1.py
$ python3 main_set2.py
```