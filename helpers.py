import shortuuid
import time
import hashlib


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
