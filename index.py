import sqlite3
from fastapi import FastAPI, Response, status
from pydantic import BaseModel
from helpers import *

app = FastAPI()

@app.get("/")
def landingPage():
    return ("Hello, welcome to Password API in Python. The default password to do any REST API operations"
            " is ADMIN or ADMIN1, please be sure to change it as soon as you setup.")

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

    # Checks if the current password's hash is the same as the one stored
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



# Body for POST
class addLoginData(BaseModel):
    adminPassword : str
    domain : str
    userID : str
    password: str

# Body for PUT
class updateLoginData(BaseModel):
    adminPassword : str
    userID : str
    password: str

# Body for GET and DELETE 
class getLoginData(BaseModel):
    adminPassword : str



# Adds a Login detail record
@app.post("/addLoginDetail")
def addALoginDetail(addLoginBody: addLoginData, response: Response):

    postConnection = sqlite3.connect("PASSWORDDB.db")
    cur = postConnection.cursor()

    # Gets the current password stored as a hash from the DB
    queryToCheckAdminPassword = "SELECT PASSWORD FROM PASSWORDDB WHERE USERID = 'PASSWORDADMIN' AND DOMAIN = 'PASSWORDADMIN' AND ID = 'PASSWORDADMIN'"
    adminPasswordCheck = cur.execute(queryToCheckAdminPassword).fetchone()

    # Checks if the current password's hash is the same as the one stored
    if currentPasswordAdminPassword(addLoginBody.adminPassword) == adminPasswordCheck[0]:

        # If the Admin password is correct, it checks if the supplied domain already exists in the DB 
        queryToCheckExistingDomain = "SELECT DOMAIN FROM PASSWORDDB WHERE DOMAIN = ?"
        valueToCheckExistingDomain = [addLoginBody.domain]
        existingDomainCheck = cur.execute(queryToCheckExistingDomain, valueToCheckExistingDomain).fetchone()
        
        # If the supplied domain is not in the DB, add the login details to the DB 
        if existingDomainCheck is None:

            generatedIDForLogin = generateID()
            generatedTimestamp = currentEpochTime()
            encryptedUserID = encryptAUserID(generatedIDForLogin, addLoginBody.userID, generatedTimestamp)
            encryptedPassword = encryptAPassword(generatedIDForLogin, addLoginBody.password, generatedTimestamp)

            queryToAddALogin = "INSERT INTO PASSWORDDB (ID, DOMAIN, USERID, PASSWORD, TIMESTAMP) Values (?, ?, ?, ?, ?)"
            valuesToAddALogin = (generatedIDForLogin, addLoginBody.domain, encryptedUserID, encryptedPassword, generatedTimestamp)
            cur.execute(queryToAddALogin, valuesToAddALogin)
            postConnection.commit()

            return {"status" : "Login added for " + addLoginBody.domain}

    # If the Admin password is wrong or the supplied domain already exists in the DB, reject with 403 
    response.status_code = status.HTTP_403_FORBIDDEN
    return {"status" : "Your admin password is incorrect or a login already exists for " + addLoginBody.domain + ". Please recheck"}



# Retrieves the password by the Domain
@app.post("/getPassword")
def getPasswordByDomain(domain: str, getLoginBody: getLoginData, response: Response):

    getConnection = sqlite3.connect("PASSWORDDB.db")
    cur = getConnection.cursor()

    # Gets the current password stored as a hash from the DB
    queryToCheckAdminPassword = "SELECT PASSWORD FROM PASSWORDDB WHERE USERID = 'PASSWORDADMIN' AND DOMAIN = 'PASSWORDADMIN' AND ID = 'PASSWORDADMIN'"
    adminPasswordCheck = cur.execute(queryToCheckAdminPassword).fetchone()

    # Checks if the current password's hash is the same as the one stored
    if currentPasswordAdminPassword(getLoginBody.adminPassword) == adminPasswordCheck[0]:

        # If the Admin password is correct, it checks if the supplied domain exists in the DB 
        queryToCheckExistingDomain = "SELECT * FROM PASSWORDDB WHERE DOMAIN = ?"
        valueToCheckExistingDomain = [domain]
        existingDomainCheck = cur.execute(queryToCheckExistingDomain, valueToCheckExistingDomain).fetchone()

        # If the supplied domain exists in the DB, return the password
        # Else, reject with a 404
        if existingDomainCheck is not None:
            decryptedPassword = decryptAPassword(existingDomainCheck[0], existingDomainCheck[3], existingDomainCheck[4])
            return {"password" : decryptedPassword, "domain": domain}
        else:
            response.status_code = status.HTTP_404_NOT_FOUND
            return {"status" : "There is no record for " + domain + ". Please recheck"}

    # If the Admin password is wrong reject with 403 
    response.status_code = status.HTTP_403_FORBIDDEN
    return {"status" : "Your admin password is incorrect. Please recheck"}



# Retrieves the UserID by the Domain
@app.post("/getUserID")
def getUserIDByDomain(domain: str, getLoginBody: getLoginData, response: Response):

    getConnection = sqlite3.connect("PASSWORDDB.db")
    cur = getConnection.cursor()

    # Gets the current password stored as a hash from the DB
    queryToCheckAdminPassword = "SELECT PASSWORD FROM PASSWORDDB WHERE USERID = 'PASSWORDADMIN' AND DOMAIN = 'PASSWORDADMIN' AND ID = 'PASSWORDADMIN'"
    adminPasswordCheck = cur.execute(queryToCheckAdminPassword).fetchone()

    # Checks if the current password's hash is the same as the one stored
    if currentPasswordAdminPassword(getLoginBody.adminPassword) == adminPasswordCheck[0]:

        # If the Admin password is correct, it checks if the supplied domain exists in the DB 
        queryToCheckExistingDomain = "SELECT * FROM PASSWORDDB WHERE DOMAIN = ?"
        valueToCheckExistingDomain = [domain]
        existingDomainCheck = cur.execute(queryToCheckExistingDomain, valueToCheckExistingDomain).fetchone()

        # If the supplied domain exists in the DB, return the UserID
        # Else, reject with a 404
        if existingDomainCheck is not None:
            decryptedUserID = decryptAUserID(existingDomainCheck[0], existingDomainCheck[2], existingDomainCheck[4])
            return {"userID" : decryptedUserID, "domain": domain}
        else:
            response.status_code = status.HTTP_404_NOT_FOUND
            return {"status" : "There is no record for " + domain + ". Please recheck"}

    # If the Admin password is wrong reject with 403 
    response.status_code = status.HTTP_403_FORBIDDEN
    return {"status" : "Your admin password is incorrect. Please recheck"}



# Retrieves the Crendentials (UserID and Password) by the Domain
@app.post("/getCredentials")
def getCredentialsdByDomain(domain: str, getLoginBody: getLoginData, response: Response):

    getConnection = sqlite3.connect("PASSWORDDB.db")
    cur = getConnection.cursor()

    # Gets the current password stored as a hash from the DB
    queryToCheckAdminPassword = "SELECT PASSWORD FROM PASSWORDDB WHERE USERID = 'PASSWORDADMIN' AND DOMAIN = 'PASSWORDADMIN' AND ID = 'PASSWORDADMIN'"
    adminPasswordCheck = cur.execute(queryToCheckAdminPassword).fetchone()

    # Checks if the current password's hash is the same as the one stored
    if currentPasswordAdminPassword(getLoginBody.adminPassword) == adminPasswordCheck[0]:

        # If the Admin password is correct, it checks if the supplied domain exists in the DB 
        queryToCheckExistingDomain = "SELECT * FROM PASSWORDDB WHERE DOMAIN = ?"
        valueToCheckExistingDomain = [domain]
        existingDomainCheck = cur.execute(queryToCheckExistingDomain, valueToCheckExistingDomain).fetchone()

        # If the supplied domain exists in the DB, return the UserID and Password
        # Else, reject with a 404
        if existingDomainCheck is not None:
            decryptedUserID = decryptAUserID(existingDomainCheck[0], existingDomainCheck[2], existingDomainCheck[4])
            decryptedPassword = decryptAPassword(existingDomainCheck[0], existingDomainCheck[3], existingDomainCheck[4])
            return {"userID" : decryptedUserID, "password" : decryptedPassword, "domain" : domain}
        else:
            response.status_code = status.HTTP_404_NOT_FOUND
            return {"status" : "There is no record for " + domain + ". Please recheck"}

    # If the Admin password is wrong reject with 403 
    response.status_code = status.HTTP_403_FORBIDDEN
    return {"status" : "Your admin password is incorrect. Please recheck"}



# Retrieves all the available crendentials (UserID and Password)
@app.post("/getAllCredentials")
def getAllCredentials(getLoginBody: getLoginData, response: Response):

    getConnection = sqlite3.connect("PASSWORDDB.db")
    cur = getConnection.cursor()

    # Gets the current password stored as a hash from the DB
    queryToCheckAdminPassword = "SELECT PASSWORD FROM PASSWORDDB WHERE USERID = 'PASSWORDADMIN' AND DOMAIN = 'PASSWORDADMIN' AND ID = 'PASSWORDADMIN'"
    adminPasswordCheck = cur.execute(queryToCheckAdminPassword).fetchone()

    # Checks if the current password's hash is the same as the one stored
    if currentPasswordAdminPassword(getLoginBody.adminPassword) == adminPasswordCheck[0]:

        # If the Admin password is correct, gets all the domains from the DB and returns it
        queryToGetAllCredentials = "SELECT ID, DOMAIN, USERID, PASSWORD, TIMESTAMP FROM PASSWORDDB WHERE ID IS NOT 'PASSWORDADMIN' AND DOMAIN IS NOT 'PASSWORDADMIN' AND USERID IS NOT 'PASSWORDADMIN'"
        allCredentials = cur.execute(queryToGetAllCredentials).fetchall()

        formattedCredentials = []
        for ID, DOMAIN, USERID, PASSWORD, TIMESTAMP in allCredentials:
            decryptedUserID = decryptAUserID(ID, USERID, TIMESTAMP)
            decryptedPassword = decryptAPassword(ID, PASSWORD, TIMESTAMP)
            formattedCredentials.append({"userID": decryptedUserID, "password": decryptedPassword, "domain": DOMAIN})

        return formattedCredentials

    # If the Admin password is wrong reject with 403 
    response.status_code = status.HTTP_403_FORBIDDEN
    return {"status" : "Your admin password is incorrect. Please recheck"}



# Updates a Login detail (UserID and/or Password) record
@app.put("/updateCredentials")
def updateTheLoginDetails(domain: str, updateLoginBody: updateLoginData, response: Response):

    putConnection = sqlite3.connect("PASSWORDDB.db")
    cur = putConnection.cursor()

    # Gets the current password stored as a hash from the DB
    queryToCheckAdminPassword = "SELECT PASSWORD FROM PASSWORDDB WHERE USERID = 'PASSWORDADMIN' AND DOMAIN = 'PASSWORDADMIN' AND ID = 'PASSWORDADMIN'"
    adminPasswordCheck = cur.execute(queryToCheckAdminPassword).fetchone()

    # Checks if the current password's hash is the same as the one stored
    if currentPasswordAdminPassword(updateLoginBody.adminPassword) == adminPasswordCheck[0]:

        # If the Admin password is correct, it checks if the supplied domain exists in the DB 
        queryToCheckExistingDomain = "SELECT * FROM PASSWORDDB WHERE DOMAIN = ?"
        valueToCheckExistingDomain = [domain]
        existingDomainCheck = cur.execute(queryToCheckExistingDomain, valueToCheckExistingDomain).fetchone()

        # If the supplied domain exists in the DB, update the credentials (UserID and Password)
        # Else, reject with a 404
        if existingDomainCheck is not None:

            generatedIDForLogin = generateID()
            generatedTimestamp = currentEpochTime()
            encryptedUserID = encryptAUserID(generatedIDForLogin, updateLoginBody.userID, generatedTimestamp)
            encryptedPassword = encryptAPassword(generatedIDForLogin, updateLoginBody.password, generatedTimestamp)

            queryToUpdateALogin = "UPDATE PASSWORDDB SET ID = ?, USERID = ?,  PASSWORD = ?, TIMESTAMP = ? WHERE DOMAIN = ?"
            valuesToUpdateALogin = (generatedIDForLogin, encryptedUserID, encryptedPassword, generatedTimestamp, domain)
            cur.execute(queryToUpdateALogin, valuesToUpdateALogin)
            putConnection.commit()

            return {"status" : "Credentials updated for " + domain}
        else:
            response.status_code = status.HTTP_404_NOT_FOUND
            return {"status" : "There is no record for " + domain + ". Please recheck"}
    
    # If the Admin password is wrong reject with 403 
    response.status_code = status.HTTP_403_FORBIDDEN
    return {"status" : "Your admin password is incorrect. Please recheck"}



# Deletes a Login detail record
@app.delete("/deleteCredentials")
def deleteTheLoginDetails(domain: str, getLoginBody: getLoginData, response: Response):

    delConnection = sqlite3.connect("PASSWORDDB.db")
    cur = delConnection.cursor()

    # Gets the current password stored as a hash from the DB
    queryToCheckAdminPassword = "SELECT PASSWORD FROM PASSWORDDB WHERE USERID = 'PASSWORDADMIN' AND DOMAIN = 'PASSWORDADMIN' AND ID = 'PASSWORDADMIN'"
    adminPasswordCheck = cur.execute(queryToCheckAdminPassword).fetchone()

    # Checks if the current password's hash is the same as the one stored
    if currentPasswordAdminPassword(getLoginBody.adminPassword) == adminPasswordCheck[0]:

        # If the Admin password is correct, it checks if the supplied domain exists in the DB 
        queryToCheckExistingDomain = "SELECT * FROM PASSWORDDB WHERE DOMAIN = ?"
        valueToCheckExistingDomain = [domain]
        existingDomainCheck = cur.execute(queryToCheckExistingDomain, valueToCheckExistingDomain).fetchone()

        # If the supplied domain exists in the DB, deletes the record
        # Else, reject with a 404
        if existingDomainCheck is not None:

            queryToDeleteALogin = "DELETE FROM PASSWORDDB WHERE DOMAIN = ?"
            valueToDeleteALogin = [domain]
            cur.execute(queryToDeleteALogin, valueToDeleteALogin)
            delConnection.commit()

            return {"status" : "Credentials for " + domain + " are deleted"}
        else:
            response.status_code = status.HTTP_404_NOT_FOUND
            return {"status" : "There is no record for " + domain + ". Please recheck"}
    
    # If the Admin password is wrong reject with 403 
    response.status_code = status.HTTP_403_FORBIDDEN
    return {"status" : "Your admin password is incorrect. Please recheck"}