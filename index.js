var AWS = require('aws-sdk');
var dynamodb = new AWS.DynamoDB();
var https = require('https');
var crypto = require('crypto');

exports.handler = function(event, context) {
    var network = event.body.network;
    var token = event.body.accessToken;
    var clientId = event.body.clientId;
    var userId = null;
    var hashName = "userHash";
    
    validate(function(isValid) {
        if (isValid) {
            loginUser();
        } else {
            console.log('Invalid token or credentials');
            context.done('Invalid token or credentials');
        }
    });
    
    function validate(callback) {
        if (typeof token !== "undefined") {
            validateToken(callback);
        } else {
            validateCredentials(callback);
        }
    }
    
    function validateToken(callback) {
        var isValid = {
            'facebook': validateTokenWithFacebook,
            'google': validateTokenWithGoogle,
            'twitter': validateTokenWithTwitter
        };
        
        if (isValid[network]) {
            isValid[network](callback);
        } else {
            console.log('Unsupported network. Validation failed.');
            callback && callback(false);
        }
    }
    
    function validateTokenWithFacebook(callback) {
        console.log('Validating token with Facebook...');
        
        get('https://graph.facebook.com/me?access_token=' + token, function(responseJson) {
            if (!responseJson.error) {
                console.log('Facebook token is valid', responseJson);
                userId = responseJson.id;
                callback && callback(true);
            } else {
                console.log('Facebook token is invalid', responseJson);
                callback && callback(false);
            }
        });
    }
    
    function validateTokenWithGoogle(callback) {
        console.log("Validating token with Google...");
        
        get('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=' + token, function(responseJson) {
            if (!responseJson.error) {
                console.log('Google token is valid');
                userId = responseJson.id;
                callback && callback(true);
            } else {
                console.log('Google token is invalid');
                callback && callback(false);
            }
        });
    }
    
    function validateTokenWithTwitter(callback) {
        console.log("Twitter validation not implemented");
        callback && callback(false);
    }
    
    function get(url, callback) {
        https.get(url, function(res) {
            res.setEncoding('utf-8');
               
            var responseString = '';
            res.on('data', function(data) {
                responseString += data;
            });
            
            res.on('end', function() {
                callback && callback(JSON.parse(responseString));
            });
        }).on('error', function(e) {
            console.error(e);
        });
    }
    
    function validateCredentials(callback) {
        if (event.body.email && event.body.password) {
            callback && callback(true);
        } else {
            console.log("Missing credentials. Validation failed.");
            callback && callback(false);
        }
    }
    
    function loginUser() {
        
        dynamodb.getItem({
            "TableName": "ldanUsers",
            "Key": getUserHashKey()
        }, function(err, data) {
            if (err) {
                console.log("Error with getItem");
            } else if (!Object.keys(data).length) {
                console.log("User does not exist");        
                loginUserWithNewAccount();
            } else {
                console.log("User exists");
                loginUserWithExistingAccount(data)
            }
        });
    }
    
    function loginUserWithNewAccount() {
        var item = getUserCreateItem(event);
        
        dynamodb.putItem({
            "TableName": "ldanUsers",
            "Item": item
        }, function (err, data) {
            if (err) {
                console.log("Error with putItem", err, item);
                context.done('error', 'Putting new user into dynamodb failed: ' + err);
            } else {
                console.log("Success with creating new user");
                context.succeed(getResponse());        
            }
        });
    }
    
    function getUserCreateItem() {
        console.log("Build user item from event");
        
        var item = {
            "origin": { "S" : getValueOrDefault(event.headers.Origin) },
            "email": { "S" : getValueOrDefault(event.body.email) },
            "firstName": { "S" : getValueOrDefault(event.body.firstName) },
            "lastName": { "S" : getValueOrDefault(event.body.lastName) },
            "thumbnail": { "S" : getValueOrDefault(event.body.thumbnail) }
        };
        
        if (token) {
            item[network + '_clientId'] = { "S" : getValueOrDefault(clientId) };
            item[network + '_accessToken'] = { "S" : getValueOrDefault(token) };
            item[network + '_userId'] = { "S" : getValueOrDefault(userId) };
        } else if (event.body.password) {
            item.password = { "S" : saltHashPassword(event.body.password) };
        }
        
        item[hashName] = getUserHashValue();
        
        item = deleteEmptyProperties(item);
        
        return item;
    }
    
    function getValueOrDefault(str) {
        if (typeof str === "undefined") {
            return "";
        }
        
        return str;
    }
    
    function deleteEmptyProperties(item) {
        for (var i in item) {
            if (item[i] === null 
                || item[i] === "" 
                || ('S' in item[i] && (item[i].S === "" || item[i].S === null))) {
                delete item[i];
            }    
        }
        
        return item;
    }
    
    function loginUserWithExistingAccount(databaseUser) {
        var item = {
            "TableName": "ldanUsers",
            "Key": getUserHashKey(),
            "UpdateExpression": "set " + network + "_accessToken = :accessToken",
            "ConditionExpression": network + "_clientId = :clientId",
            "ExpressionAttributeValues": {
                ":accessToken": { "S": token },
                ":clientId": { "S": clientId }
            }
        };

        dynamodb.updateItem(item, function (err, data) {
            if (err) {
                console.log("Error with updateItem", err);
                context.done('error', 'Updating user failed: ' + err);
            } else {
                console.log("Success with updating existing user");
                context.succeed(getResponse());
            }
        });
    }
    
    function getUserHashKey() {
        var key = {};
        
        key[hashName] = getUserHashValue();
        
        return key;
    }
    
    function getUserHashValue() {
        if (token) {
            return { "S" : network + "_" + userId + "_" + clientId  };
        } else if (event.body.email && event.body.password) {
            return { "S" : "native_email_" + event.body.email };
        } else {
            return null;
        }
    }
    
    function getResponse() {
        return {
            "origin": event.headers.Origin,
            "userId": userId,
            "network": network,
            "clientId": clientId,
            "accessToken": token,
            "email": event.body.email,
            "firstName": event.body.firstName,
            "lastName": event.body.lastName,
            "thumbnail": event.body.thumbnail
        };
    }
    
    //
    // node.js password hashing method via
    // http://code.ciphertrick.com/2016/01/18/salt-hash-passwords-using-nodejs-crypto/
    //
    function saltHashPassword(userpassword) {
        
        return sha512(userpassword, genRandomString(16));
 
        function genRandomString(length) {
            return crypto.randomBytes(Math.ceil(length/2))
                .toString('hex')
                .slice(0, length);
        }
        
        function sha512(password, salt) {
            var hash = crypto.createHmac('sha512', salt);
            hash.update(password);
            var value = hash.digest('hex');
            
            return salt + ":" + value;
        }
    }
};