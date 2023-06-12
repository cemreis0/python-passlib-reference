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