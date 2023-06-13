### PASSWORDHASH ###

## Hashing & Verifying ##
# The main activities applications will need to perform are hashing and verifying passwords. This can be done with the PasswordHash.hash() and PasswordHash.verify() methods. #
# Import the desired hasher #
from passlib.hash import pbkdf2_sha256

pbkdf2_sha256_hash = pbkdf2_sha256.hash("password")
print("\n" + pbkdf2_sha256_hash)
print("Verify hash: " + str(pbkdf2_sha256.verify("password", pbkdf2_sha256_hash)))

pbkdf2_sha256_hash2 = pbkdf2_sha256.hash("password")
print(pbkdf2_sha256_hash2)
print("Verify hash: " + str(pbkdf2_sha256.verify("password", pbkdf2_sha256_hash2)) + "\n")


## Customizing the Configuration ##
# All the hashes offer a PasswordHash.using() method. This is a powerful method which accepts most hash informational attributes, as well as some other hash-specific configuration keywords; and returns a subclass of the original hasher #
print("pbkdf2_sha256 setting keywords: " + str(pbkdf2_sha256.setting_kwds))
custom_pbkdf2 = pbkdf2_sha256.using(salt_size=32, rounds=100000)
print(custom_pbkdf2.hash("123456") + "\n")


## Context Keywords ##
# While the PasswordHash.hash() example above works for most hashes, a small number of algorithms require you provide external data (such as a username) every time a hash is calculated. #
# An example of this is the oracle10 hash, where hashing requires a username. #
from passlib.hash import oracle10
oracle10_hash = oracle10.hash("secret", user="admin")
print("oracle10 context keywords: " + str(oracle10.context_kwds))
print(oracle10_hash)
print("Verify hash for admin: " + str(oracle10.verify("secret", oracle10_hash, user="admin")))
print("Verify hash for wronguser: " + str(oracle10.verify("secret", oracle10_hash, user="wronguser")) + "\n")


## Identifying Hashes ##
# One of the rarer use-cases is the need to identify whether a string recognizably belongs to a given hasher class. This can be important in some cases, because attempting to call PasswordHash.verify() with another algorithm’s hash will result in a ValueError. #
from passlib.hash import md5_crypt
md5_crypt_hash = md5_crypt.hash("password")
try:
    print("Verify hash: " + str(pbkdf2_sha256.verify("password", md5_crypt_hash)))
except Exception as exc:
    print(exc)
print(str(pbkdf2_sha256.identify(md5_crypt_hash)))
print(str(md5_crypt.identify(md5_crypt_hash)) + "\n")

######

### CRYPTCONTEXT ###

## Basic Usage ##
# At its base, the CryptContext class is just a collection of PasswordHash objects, imported by name from the passlib.hash module. #
from passlib.context import CryptContext
cryptctx = CryptContext(schemes=["sha256_crypt", "md5_crypt", "des_crypt"])
# This loads first algorithm in the schemes list (sha256_crypt), generates a new salt, and hashes the password.
hash1 = cryptctx.hash("password")
print(hash1)

# When verifying a password, the algorithm is identified automatically.
print(str(cryptctx.verify("bruh", hash1)))
print(str(cryptctx.verify("password", hash1)))

# Alternately, you can explicitly pick one of the configured algorithms, through this is rarely needed in practice.
hash2 = cryptctx.hash("secret", scheme="md5_crypt")
print(hash2)
try:
    print(str(cryptctx.verify("secret", hash2, scheme="sha256_crypt")))
except Exception as exc:
    print(exc)
print(str(cryptctx.verify("secret", hash2)))

# If not told otherwise, the context object will use the first algorithm listed in schemes when creating new hashes. This default can be changed by using the default keyword. #
cryptctx2 = CryptContext(schemes=["sha256_crypt", "md5_crypt", "des_crypt"], default= "des_crypt")
hash3 = cryptctx2.hash("password")
print(hash3)
print(cryptctx2.identify(hash3) + "\n")

## Using Default Settings ##
# While creating and verifying hashes is useful enough, it’s not much more than could be done by importing the objects into a list. The next feature of the CryptContext class is that it can store various customized settings for the different algorithms, instead of hardcoding them into each hash() call. #
# As an example, the sha256_crypt algorithm supports a rounds parameter which defaults to 80000, and the ldap_salted_md5 algorithm uses 8-byte salts by default. #
cryptctx3 = CryptContext(schemes=["sha256_crypt", "ldap_salted_md5"])
hash4 = cryptctx3.hash("password", scheme="sha256_crypt")
print(hash4)
hash5 = cryptctx3.hash("password", scheme="ldap_salted_md5")
print(hash5)
# Instead of having to pass rounds=91234 or salt_size=16 every time encrypt() is called, CryptContext supports setting algorithm-specific defaults which will be used every time a CryptContext method is invoked. These is done by passing the CryptContext constructor a keyword with the format scheme__setting. #
cryptctx3.update(sha256_crypt__default_rounds=91234, ldap_salted_md5__salt_size=16)
print(cryptctx3.hash("password", scheme="sha256_crypt"))
print(cryptctx3.hash("password", scheme="ldap_salted_md5"))

## Loading & Saving a CryptContext ##
# The previous example built up a CryptContext instance in two stages, first by calling the constructor, and then the update() method to make some additional changes. The same configuration could of course be done in one step. #
cryptctx4 = CryptContext(schemes=["sha256_crypt", "ldap_salted_md5"], sha256_crypt__default_rounds=91234, ldap_salted_md5__salt_size=16)
# This is not much more useful, since these settings still have to be hardcoded somewhere in the application. This is where the CryptContext’s serialization abilities come into play. As a starting point, every CryptContext object can dump its configuration as a dictionary suitable for passing back into its constructor. #
cryptctx4_dict = cryptctx4.to_dict()
# However, this has been taken a step further, as CryptContext objects can also dump their configuration into a ConfigParser-compatible string, allowing the configuration to be written to a file. #
cryptctx4_string = cryptctx4.to_string()
print(cryptctx4_string)
# This “INI” format consists of a section named "[passlib]", following by key/value pairs which correspond exactly to the CryptContext constructor keywords (Keywords which accepts lists of names (such as schemes) are automatically converted to/from a comma-separated string) This format allows CryptContext configurations to be created in a separate file (say as part of an application’s larger config file), and loaded into the CryptContext at runtime. Such strings can be loaded directly when creating the context object #
# Using the special from_string() constructor to load the exported configuration created in the previous step. #
cryptctx4_from_string = CryptContext.from_string(cryptctx4_string)
# Or it can be loaded from a local file.
cryptctx4_from_string2 = CryptContext.from_path("./cryptcontext.ini")

## Deprecation & Hash Migration ##
# The final and possibly most useful feature of the CryptContext class is that it can take care of deprecating and migrating existing hashes, re-hashing them using the current default algorithm and settings. All that is required is that a few settings be added to the configuration, and that the application call one extra method whenever a user logs in. #
cryptctx5 = CryptContext(schemes=["sha256_crypt", "md5_crypt", "des_crypt"], deprecated=["md5_crypt", "des_crypt"])
# Internally, this is not the only thing needs_update() does. It also checks for other issues, such as rounds / salts which are known to be weak under certain algorithms, improperly encoded hash strings, and other configurable behaviors. #
hash6= cryptctx5.hash("password", scheme="sha256_crypt")
print(cryptctx5.needs_update(hash6))
hash7 = cryptctx5.hash("password", scheme="md5_crypt")
print(cryptctx5.needs_update(hash7))
# To summarize the process described in the previous section, all the actions an application would usually need to perform can be combined into the following bit of skeleton code. #
""" hash = get_hash_from_user(user)
valid, new_hash = pass_ctx.verify_and_update(password, hash)
if valid:
    if new_hash:
        replace_user_hash(user, new_hash)
    do_successful_things()
else:
    reject_user_login() """
# In addition to deprecating entire algorithms, the deprecations system also allows you to place limits on algorithms that support the variable time-cost parameter rounds. #
# As an example, take a typical system containing a number of user passwords, all stored using sha256_crypt. As computers get faster, the minimum number of rounds that should be used gets larger, yet the existing passwords will remain in the system hashed using their original value. To solve this, the CryptContext object lets you place minimum bounds on what rounds values are allowed, using the scheme__min_rounds set of keywords… any hashes whose rounds are outside this limit are considered deprecated, and in need of re-encoding using the current policy #
cryptctx6 = CryptContext(schemes=["sha256_crypt"], sha256_crypt__min_rounds=131072, sha256_crypt__default_rounds=131073)
hash8 = cryptctx6.hash("password")
print(cryptctx6.needs_update(hash8))
hash9 = "$5$rounds=80000$qoCFY.akJr.flB7V$8cIZXLwSTzuCRLcJbgHlxqYKEK0cVCENy6nFIlROj05"
print(cryptctx6.needs_update(hash9))
print(cryptctx6.verify_and_update("wrong", hash9))
print(cryptctx6.verify_and_update("password", hash9))
print(cryptctx6.to_string())

######

### TOTP - Time-based One-time Passwrod ###

## Generate an Application Secret ##

# First, generate a strong application secret to use when encrypting TOTP keys for storage. Passlib offers a generate_secret() method to help with this. #
from passlib.totp import generate_secret
# This key should be assigned a numeric tag (e.g. “1”, a timestamp, or an iso date such as “2016-11-10”); and should be stored in a file separate from your application’s configuration. Ideally, after this file has been loaded by the TOTP constructor below, the application should give up access permissions to the file. #
# Example file contents: 2016-11-10: pO7SwEFcUPvIDeAJr7INBj0TjsSZJr1d2ddsFL9r5eq #
# This key will be used in a later step to encrypt TOTP keys for storage in your database. The sequential tag is used so that if your database (or the application secrets) are ever compromised, you can add a new application secret (with a newer tag), and gracefully migrate the compromised TOTP keys. #
print(generate_secret())

## TOTP Factory Initialization ##
# When your application is being initialized, create a TOTP factory which is configured for your application, and is set up to use the application secrets defined in step 1. You can also set a default issuer here, instead of having to provide one explicitly in step 4. #
from passlib.totp import TOTP
TotpFactory = TOTP.using(secrets_path='./totpsecret.txt', issuer="myapp.example.org")

## Setting up TOTP for a User ##
# To set up TOTP for a new user: create a new TOTP object and key using TOTP.new(). This can then be rendered into a provisioning URI, and transferred to the user’s TOTP client of choice. #
# Rendering to a provisioning URI using TOTP.to_uri() requires picking an “issuer” string to uniquely identify your application, and a “label” string to uniquely identify the user. The following example creates a new TOTP instance with a new key, and renders it to a URI, plugging in application-specific information. #
# Using the TotpFactory object set up in step 2. #
totp = TotpFactory.new()
# This URI is generally passed to a QRCode renderer, though as fallback it’s recommended to also display the key using TOTP.pretty_key(). #
uri = totp.to_uri(issuer="myapp.example.org", label="username")
print(uri)

## Storing the TOTP object ##
# Before enabling TOTP for the user’s account, it’s good practice to first have the user successfully verify a token (per step 6); thus confirming their client h as been correctly configured. #
# Once this is done, you can store the TOTP object in your database. This can be done via the TOTP.to_json() method. #
totp.to_json()
print(totp.to_json())

## Verifying a Token ##
# Whenever attempting to verify a token provided by the user, first load the serialized TOTP object from the database (stored step 5), as well as the last counter value from the cache (set up in step 3). You should use these values to call the TOTP.verify() method. #
# If verify() succeeds, it will return a TotpMatch object. This object contains information about the match, including TotpMatch.counter (a time-dependant integer tied to this token), and TotpMatch.cache_seconds (minimum time this counter should be cached). #
# If verify() fails, it will raise one of the passlib.exc.TokenError subclasses indicating what went wrong. This will be one of three cases: the token was malformed (e.g. too few digits), the token was invalid (didn’t match), or a recent token was reused. #
""" A skeleton example of how this should function:
from passlib.exc import TokenError, MalformedTokenError

# pull information from your application
token = # ... token string provided by user ...
source = # ... load totp json string from database ...
last_counter = # ... load counter value from cache ...

# ... check attempt rate limit for this account / address (per step 3 above) ...

# using the TotpFactory object defined in step 2, invoke verify
try:
    match = TotpFactory.verify(token, source, last_counter=last_counter)
except MalformedTokenError as err:
    # --- malformed token ---
    # * inform user, e.g. by displaying str(err)
except TokenError as err:
    # --- invalid or reused token ---
    # * add to rate limit counter
    # * inform user, e.g. by displaying str(err)
else:
    # --- successful match ---
    # * reset rate-limit counter
    # * store 'match.counter' in per-user cache for at least 'match.cache_seconds' """

## Reserializing Existing Objects ##
# An organization’s security policy may require that a developer periodically change the application secret key used to decrypt/encrypt TOTP objects. Alternately, the application secret may become compromised. #
# In either case, a new application secret will need to be created, and a new tag assigned (per step 1). Any deprecated secret(s) will need to be retained in the collection passed to the TotpFactory, in order to be able to decrypt existing TOTP objects. #
# Once the new secret has been added, you will need to update all the serialized TOTP objects in the database, decrypting them using the old secret, and encrypting them with the new one. #
# This can be done in a few ways. The following skeleton example gives a simple loop that can be used, which would ideally be run in a process that’s separate from your normal application. #
""" # presuming query_user_totp() queries your database for all user rows,
# and update_user_totp() updates a specific row.
for user_id, totp_source in query_user_totp():
    totp = TotpFactory.from_source(totp_source)
    if totp.changed:
        update_user_totp(user_id, totp.to_json()) """

## Creating TOTP Instances ##
## Direct Creation ##
# Creating TOTP instances is straightforward: The TOTP class can be called directly to constructor a TOTP instance from it’s component configuration. #
totp2 = TOTP(key="GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM", digits=9)
print(totp2.generate().token)
# You can also use a number of the alternate constructors, such as TOTP.new() or TOTP.from_source(). #
totp3 = TOTP.new()
totp4 = TOTP.from_source('{"key":"D6RZI4ROAUQKJNAWQKYPN7W7LNV43GOT","type":"totp","v":1}')
# Once created, you can inspect the object for it’s configuration and key. #
print(totp4.base32_key, totp4.alg, totp4.period)
# If you want a non-standard alg or period, you can specify it via the constructor. You can also create TOTP instances from an existing key (see the TOTP constructor’s key and format options for more details). #
totp5 = TOTP(new=True, period=60, alg="sha256")
print(totp5.base32_key, totp5.alg, totp5.period)

## Using a Factory ##
# Most applications will have some default configuration which they want all TOTP instances to have. This includes application secrets (for encrypting TOTP keys for storage), or setting a default issuer label (for rendering URIs). #
# Instead of having to call the TOTP constructor each time and provide all these options, you can use the TOTP.using() method. This method takes in a number of the same options as the TOTP constructor, and returns a TOTP subclass which has these options pre-programmed in as defaults. #
TotpFactory2 = TOTP.using(issuer="myapp.example.org", secrets={"1": generate_secret()})
totp6 = TotpFactory.new()
print(totp6.issuer)
print(totp6.to_json())

## Configuring Clients ##
# Once a TOTP instance & key has been generated on the server, it needs to be transferred to the client TOTP program for installation. This can be done by having the user manually type the key into their TOTP client, but an easier method is to render the TOTP configuration to a URI stored in a QR Code. #
## Rendering URIs ##
# The KeyUriFormat is a de facto standard for encoding TOTP keys & configuration information into a string. Once the URI is rendered as a QR Code, it can easily be imported into many smartphone clients (such as Authy and Google Authenticator) via the smartphone’s camera. #
# When transferring the TOTP configuration this way, you will need to provide unique identifiers for both your application, and the user’s account. This allows TOTP clients to distinguish this key from the others in it’s database. This can be done via the issuer and label parameters of the TOTP.to_uri() method. #
# The issuer string should be a globally unique label for your application (e.g. it’s domain name). Since the issuer string shouldn’t change across users, you can create a customized TOTP factory, and provide it with a default issuer. (If you skip this step, the issuer will need to be provided at every TOTP.to_uri() call). #
TotpFactory3 = TOTP.using(issuer="myapp.example.org")
# Once this is done, rendering to a provisioning URI just requires picking a label for the URI. This label should identify the user within your application (e.g. their login or their email). #
totp7 = TotpFactory3.new()
uri2 = totp7.to_uri(label="demo-user")
print(uri)

## Rendering QR Codes ##
# This URI can then be encoded as a QR Code, using various python & javascript qrcode libraries. As an example, the following uses PyQrCode to render the URI to the console as a text-based QR code. #
import pyqrcode
print(pyqrcode.create(uri2).terminal(quiet_zone=1))
print(totp7.pretty_key())

## Parsing URIs ##
# On the client side, passlib offers the TOTP.from_uri() constructor creating a TOTP object from a provisioning URI. This can also be useful for testing URI encoding & output during development #
totp8 = TOTP.from_uri('otpauth://totp/demo-user?secret=GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM&issuer=myapp.example.org')
print(totp8.base32_key, totp8.alg, totp8.generate().token)

## Storing TOTP instances ##
# Once a TOTP object has been created, it inevitably needs to be stored in a database. Using to_uri() to serialize it to a URI has a few disadvantages - it always includes an issuer & a label (wasting storage space), and it stores the key in an unencrypted format. #
## JSON Serialization ##
# To help with this passlib offers a way to serialize TOTP objects to and from a simple JSON format, which can optionally encrypt the keys for storage. #
# To serialize a TOTP object to a string, use TOTP.to_json(). #
totp9 = TOTP.new()
data = totp9.to_json()
print(data)
totp10 = TOTP.from_json(data)
print(totp10.base32_key)

## Application Secrets ##
# The one thing lacking about the example above is that the resulting data contained the plaintext key. If the server were compromised, the TOTP keys could be used directly to impersonate the user. To solve this, Passlib offers a method for providing an application-wide secret that TOTP.to_json() will use to encrypt keys. #
# Per Step 1 of the walkthrough (above), applications can use the generate_secret() helper to create new secrets. All existing secrets (the current one, and any deprecated / compromised ones) should be assigned an identifying tag, and stored in a dict or file. #
# Ideally, these secrets should be stored in a location which the application’s process does not have access to once it has been initialized. Once this data is loaded, applications can create a factory function using TOTP.using(), and provide these secrets as part of it’s arguments. This can take the form of a file path, a loaded string, or a dictionary. #
TotpFactory4 = TOTP.using(secrets={"1": "'pO7SwEFcUPvIDeAJr7INBj0TjsSZJr1d2ddsFL9r5eq'"})
TotpFactory5 = TOTP.using(secrets_path="./totpsecret.txt")
totp11 = TotpFactory4.new()
data2 = totp11.to_json()
data3 = '{"enckey":{"c":14,"k":"FLEQC3VO6SIT3T7GN2GIG6ONPXADG5CZ","s":"UL2J4MZG4SONHOWXLKFQ","t":"1","v":1},"type":"totp","v":1}'
totp12 = TotpFactory4.from_source(data)
totp13 = TOTP.from_source(data) # TypeError: no application secrets present, can't decrypt TOTP key

## Generating Tokens (Client-Side Only) ##
# Finally, the whole point of TOTP: generating and verifying tokens. The TOTP protocol generates a new time & key -dependant token every <period> seconds (usually 30). #
# Generating a totp token is done with the TOTP.generate() method, which returns a TotpToken instance. This object looks and acts like a tuple of (token, expire_time), but offers some additional informational attributes. #
from passlib import totp
otp = TOTP(key="GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM")
otp.generate()
print(otp.generate().token)
print(otp.generate(time=1475338840))

## Verifying Tokens ##
# In order for successful authentication, the user must generate the token on the client, and provide it to your server before the TOTP.period ends. #
# Since this there will always be a little transmission delay (and sometimes client clock drift) TOTP verification usually uses a small verification window, allowing a user to enter a token a few seconds after the period has ended. This window is usually kept as small as possible, and in passlib defaults to 30 seconds. #

## Match & Verify ##
# To verify a token a user has provided, you can use the TOTP.match() method. If unsuccessful, a passlib.exc.TokenError subclass will be raised. If successful, this will return a TotpMatch instance, with details about the match. This object acts like a tuple of (counter, timestamp), but offers some additional informational attributes. #
otp2 = TOTP(key='GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM')
# otp2.match('359', time=1475338840) MalformedTokenError: Token must have exactly 6 digits #
# otp2.match('123456', time=1475338840) InvalidTokenError: Token did not match #
# otp2.match('359275', time=1475338840) <TotpMatch counter=49177961 time=1475338840 cache_seconds=60> #
# As a further optimization, the TOTP.verify() method allows deserializing and matching a token in a single step. Not only does this save a little code, it has a signature much more similar to that of Passlib’s passlib.ifc.PasswordHash.verify(). #
# Typically applications will provide the TOTP key in whatever format it’s stored by the server. This will usually be a JSON string (as output by TOTP.to_json()), but can be any format accepted by TOTP.from_source(). As an example. #
totp_source = '{"v": 1, "type": "totp", "key": "otxl2f5cctbprpzx"}'
match = TOTP.verify('123456', totp_source)

## Preventing Token Reuse ##
# Even if an attacker is able to observe a user entering a TOTP token, it will do them no good once period + window seconds have passed (typically 60). This is because the current time will now have advanced far enough that TOTP.match() will never match against the stolen token. #
# However, this leaves a small window in which the attacker can observe and replay a token, successfully impersonating the user. To prevent this, applications are strongly encouraged to record the latest TotpMatch.counter value that’s returned by the TOTP.match() method. #
# This value should be stored per-user in a temporary cache for at least period + window seconds. (This is typically 60 seconds, but for an exact value, applications may check the TotpMatch.cache_seconds value returned by the TOTP.match() method). #
# Any subsequent calls to verify should check this cache, and pass in that value to TOTP.match()’s “last_counter” parameter (or None if no value found). Doing so will ensure that tokens can only be used once, preventing replay attacks. #
""" otp3 = TOTP(key="GVDOQ7NP6XPJWE4CWCLFFSXZH6DTAZWM")
last_counter = ...consult application cache...
match = otp.match('359275', last_counter=last_counter, time=1475338830)
match.counter = last_counter (49177961)
match = otp.match('359275', last_counter=last_counter, time=1475338840)
UsedTokenError: Token has already been used, please wait for another. """
