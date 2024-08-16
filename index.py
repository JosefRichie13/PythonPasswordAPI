import sqlite3
from fastapi import FastAPI, Response, status
from pydantic import BaseModel
from helpers import *

app = FastAPI()


# Returns the hash of the current Password admin password 
def currentPasswordAdminPassword(passwordToCheck):

    connection = sqlite3.connect("PASSWORDDB.db")
    cur = connection.cursor()

    queryToCheckCurrentTimeStamp = "SELECT TIMESTAMP FROM PASSWORDDB WHERE USERID = 'PASSWORDADMIN' AND DOMAIN = 'PASSWORDADMIN' AND ID = 'PASSWORDADMIN'"
    existingTimeStamp = cur.execute(queryToCheckCurrentTimeStamp).fetchone()

    hashedPassword = hashTheAdminPasswordUsingSHA('PASSWORDADMIN', passwordToCheck, existingTimeStamp[0])

    return hashedPassword


# Body for the Password Admin's Password updation
class updatePasswordAdminData(BaseModel):
    oldPassword : str
    newPassword : str
    

# Updates the Password of the Password Admin
@app.put("/updatePasswordAdmin")
def updatePasswordAdmin(updatePasswordAdminBody: updatePasswordAdminData, response:Response):

    putConnection = sqlite3.connect("PASSWORDDB.db")
    cur = putConnection.cursor()

    # Gets the current password stored as a hash from the DB
    queryToCheckAdminPassword = "SELECT PASSWORD FROM PASSWORDDB WHERE USERID = 'PASSWORDADMIN' AND DOMAIN = 'PASSWORDADMIN' AND ID = 'PASSWORDADMIN'"
    adminPasswordCheck = cur.execute(queryToCheckAdminPassword).fetchone()

    # Checks if the current password's hash is the same as the one stores
    if currentPasswordAdminPassword(updatePasswordAdminBody.oldPassword) == adminPasswordCheck[0]:

        # If yes, gets the current epoch time and stores it
        currentTime = currentEpochTime()
        
        # Hashes the new password
        hashedPassword = hashTheAdminPasswordUsingSHA('PASSWORDADMIN', updatePasswordAdminBody.newPassword, currentTime)

        # Updates the password
        queryToUpdateAdminPassword = "UPDATE PASSWORDDB SET PASSWORD = ?, TIMESTAMP = ? WHERE USERID = 'PASSWORDADMIN' AND DOMAIN = 'PASSWORDADMIN' AND ID = 'PASSWORDADMIN'"
        valueToUpdateAdminPassword = (hashedPassword, currentTime)
        cur.execute(queryToUpdateAdminPassword, valueToUpdateAdminPassword)
        putConnection.commit()
        return {"status" : "The password of the Password Admin user is changed"}

    # If the current password is not the same, reject with a 403
    response.status_code = status.HTTP_403_FORBIDDEN
    return {"status" : "Your password is incorrect"}