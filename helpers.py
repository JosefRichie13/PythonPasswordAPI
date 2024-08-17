import shortuuid
import time
import hashlib
import cryptocode



# Generates a UUID, which is used as an ID for all comments and replies
def generateID():
    return shortuuid.uuid()


# Generates the current time in Epoch
def currentEpochTime():
    return int(time.time())

# Hashes the Admin password using SHA256. It uses 2 salts, one static and one dynamic.
# Static salt is the User ID and the Dynamic Salt is the timestamp in Epoch 
def hashTheAdminPasswordUsingSHA(userid, password, timstamp):
    saltedPassword = userid + password + str(timstamp)
    hashedPassword = hashlib.sha256(saltedPassword.encode())
    return hashedPassword.hexdigest()

# Encrypts a UserID and returns it
def encryptAUserID(ID, userid, timestamp):
    keyToEncrypt = ID + str(timestamp)
    return cryptocode.encrypt(userid, keyToEncrypt)

# Decrypts a UserID and returns it
def decryptAUserID(ID, userid, timestamp):
    keyToDecrypt = ID + str(timestamp)
    return cryptocode.decrypt(userid, keyToDecrypt)

# Encrypts a Password and returns it
def encryptAPassword(ID, password, timestamp):
    keyToEncrypt = str(timestamp) + ID
    return cryptocode.encrypt(password, keyToEncrypt)

# Decrypts a Password and returns it
def decryptAPassword(ID, password, timestamp):
    keyToDecrypt = str(timestamp) + ID
    return cryptocode.decrypt(password, keyToDecrypt)