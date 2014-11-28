##OAuth Server Creation Tutorial
These instructions are for creating an OAuth server the “Sails way” using Sails.js. In this tutorial we will cover:

- create a centralize authentication server (single sign-on)
- using an industry standard solution to for apps to communicate to a single sign-on
- registering clients (“apps”)
- registering users
- exchanging credentials for tokens
- exchanging token for identity
- email verification to decrease spam user creation
- doing it the “Sails way”


### Instructions

1. Install SailsJS beta (rc9+) if not installed already.

    ```shell
    sudo npm install sails@beta -g
    ```

2. Generate a new SailsJS app by running the following in terminal:

    ```shell
    sails new oauth-server --no-frontend && cd oauth-server
    ```

3. Install Dependencies

    ```shell
    npm install nodemailer oauth2orize passport passport-http-bearer passport-oauth2-public-client rand-token sails-mongo@beta bluebird bcrypt-nodejs --save
    ```

    TIP: Sometimes it helps to run `sudo npm cache clear` when dependencies fail to install.

4. Configure local

    1. Edit config/local.js

        ```shell
        vim config/local.js
        ```

    2. Find the line that contains the `port` expression, uncomment and set to use port 1336:

        ```js
        port: process.env.PORT || 1336,
        ```
5. Configure security settings:

    1. Create and edit security config file:

        ```shell
        touch config/security.js && vim $_
        ```

    2. Add the following, replacing the email credentials (Gmail only atm) as appropriate:

        ```shell
        module.exports.security = {
            oauth : {
                version : '2.0',
                token : {
                    length: 32,
                    expiration: 3600
                }
            },
            admin: {
                email: {
                    address: 'xxxxxxxxxxxx@xxxxx.xxx',
                    password: 'xxxxxxxxxx'
                },

            },
            server: {
                url: 'http://localhost:1336'
            }
        };
        ```
6. Configure http

    1. Edit the config/http.js

        ```shell
        vim config/http.js
        ```
    2. Uncomment the `middleware` object and the `order` array. After `middleware` expression, add the following:

        ```js
        passportInit: require('passport').initialize(),
        passportSession: require('passport').session(),
        ```

    3. In the order array, add the following (before router):

        ```js
        'passportInit',
        'passportSession',
        ```

7. Configure policies

    1. Edit the config/policies.js
        
        ```shell
        vim config/policies.js
        ```

    2. Find the following:

        ```js
        '*': true,
        ```


        And change to:
        ```js
        '*': 'OAuthValidateAccessToken',
        ```

    3. Add the following after the above:

        ```js
        OAuthController: {
            '*' :  'OAuthValidateAccessToken',
            token: 'OAuthPublicClient'
        },
        UsersController: {
           '*' : 'OAuthValidateAccessToken',
           'register' : true,
           'verify/:email' : true
        },
        ClientsController: {
            '*' : 'OAuthValidateAccessToken',
            'register' : true,
            'verify/:email' : true
        }
        ```

8. Configure CORS

    1. Edit config/cors.js

        ```shell
        vim config/cors.js
        ```

    2. Find the following:
        
        ```js
        allRoutes: false,
        ```

        Uncomment and change to:
        ```js
        allRoutes: true,
        ```

    3. Find the following:

        ```js
        headers: 'content-type'
        ```

        Uncomment and change to:

        ```js
        headers: 'content-type,authorization'
        ```

9. Configure Database Connection

    1. Edit config/connections.js

        ```shell
        vim config/connections.js
        ```

    2. Replace the entire contents with the following:

        ```js
        /**
         * Connections
         * (sails.config.connections)
         *
         * `Connections` are like "saved settings" for your adapters.  What's the difference between
         * a connection and an adapter, you might ask?  An adapter (e.g. `sails-mysql`) is generic--
         * it needs some additional information to work (e.g. your database host, password, user, etc.)
         * A `connection` is that additional information.
         *
         * Each model must have a `connection` property (a string) which is references the name of one
         * of these connections.  If it doesn't, the default `connection` configured in `config/models.js`
         * will be applied.  Of course, a connection can (and usually is) shared by multiple models.
         * .
         * Note: If you're using version control, you should put your passwords/api keys
         * in `config/local.js`, environment variables, or use another strategy.
         * (this is to prevent you inadvertently sensitive credentials up to your repository.)
         *
         * For more information on configuration, check out:
         * http://links.sailsjs.org/docs/config/connections
         */

        module.exports.connections = {

            mongo: {
                adapter: 'sails-mongo',
                host: 'YOUR_HOST',
                port: 'YOUR_PORT',
                user: 'YOUR_USER_NAME',
                password: 'YOUR_PASSWORD',
                database: 'YOUR_MONGO_DB_NAME_HERE'
            }
        };
        ```

    3. Fill in your host, port, username, password and database name as appropriate.

10. Configure models

    1. Edit config/models.js

        ```shell
        vim config/models.js
        ```

    2. Change line ~15-17 as follows:

        ```js
        connection: 'mongo',
        autoCreatedAt: false,
        autoUpdatedAt: false
        ```

11. Create Some Models

    1. In terminal, run the following commands:

        ```shell
        sails generate model clients

        info: Created a new model ("Clients") at api/models/Clients.js!
        ```

        ```shell
        sails generate model tokens

        info: Created a new model ("tokens") at api/models/Tokens.js!
        ```

        ```shell
        sails generate model users

        info: Created a new model ("users") at api/models/Users.js!
        ```

12. Define our Models

    1. Define Clients.js 

        1. Edit api/models/Clients.js

            ```shell
            vim api/models/Clients.js
            ```

        2. Replace contents with:

            ```js
            /**
             * Clients.js
             */

            var promisify = require('bluebird').promisify,
                bcrypt = require('bcrypt-nodejs');
            module.exports = {


                attributes: {


                    name: {
                        type: 'string'
                    },

                    organization: {
                        type: 'string'
                    },

                    email: {
                        type: 'string'
                    },

                    client_id: {
                        type: 'string',
                        required: true,
                        unique: true
                    },

                    client_secret: {
                        type: 'string',
                        required: true
                    },

                    trust_level: {
                        type: 'string'
                    },

                    redirect_uri: {
                        type: 'string',
                        urlish: true
                    },

                    date_registered: {
                        type: 'string'

                    },
                    date_verified: {
                        type: 'string'
                    },

                    compareSecret: function(clientSecret) {
                        return bcrypt.compareSync(clientSecret, this.client_secret);
                    },

                    toJSON: function () {
                        var obj = this.toObject();
                        delete obj.client_secret;

                        return obj;
                    }

                },


                beforeCreate: function (client, next) {
                    if (client.hasOwnProperty('client_secret')) {
                        client.clientSecret = bcrypt.hashSync(client.client_secret, bcrypt.genSaltSync(10));
                        next(false, client);

                    } else {
                        next(null, client);
                    }
                },

                beforeUpdate: function (client, next) {
                    if (client.hasOwnProperty('client_secret')) {
                        client.clientSecret = bcrypt.hashSync(client.client_secret, bcrypt.genSaltSync(10));
                        next(false, client);
                    } else {
                        next(null, client);
                    }
                },


                authenticate: function (clientId, clientSecret) {
                    return API.Model(Clients).findOne({client_id: clientId}).then(function (client) {
                        return (client && client.compareSecret(clientSecret) ) ? client : null;
                    });
                }

            };
            ```

    2. Define Tokens.js

        1. Edit api/models/Tokens.js

            ```shell
            vim api/models/Tokens.js
            ```

        2. Replace the contents with:

            ```js
            /**
             * Tokens.js
             */

            var Promise = require('bluebird'),
                promisify = Promise.promisify,
                randToken = require('rand-token');


            module.exports = {


                attributes: {

                    access_token: {
                        type: 'string',
                        required: true,
                        unique: true
                    },

                    refresh_token: {
                        type: 'string',
                        required: true,
                        unique: true
                    },

                    code: {
                        type: 'string',
                        unique: true
                    },

                    user_id: {
                        type: 'string'
                    },

                    expiration_date: {
                        type: 'date'
                    },

                    client_id: {
                        type: 'string',
                        required: true
                    },

                    security_level: {
                        type: 'string'
                    },

                    scope: {
                        type: 'string'
                    },

                    calc_expires_in: function () {
                        return Math.floor(new Date(this.expiration_date).getTime() / 1000 - new Date().getTime() / 1000);
                    },

                    toJSON: function () {
                        var hiddenProperties = ['id','access_token','refresh_token','code','user_id','client_id'],
                            obj = this.toObject();

                        obj.expires_in = this.expires_in();

                        hiddenProperties.forEach(function(property){
                            delete obj[property];
                        });

                        return obj;
                    }

                },


                authenticate: function (criteria) {
                    var tokenInfo,
                        $Tokens = API.Model(Tokens),
                        $Users = API.Model(Users),
                        $Clients = API.Model(Clients),
                        $result;

                    if (criteria.access_token) {
                        $result = $Tokens.findOne({access_token: criteria.access_token});
                    }
                    else if (criteria.code) {
                        $result = $Tokens.findOne({code: criteria.code});
                    }
                    else {
                        //Bad Token Criteria
                        return Promise.reject("Unauthorized");
                    }

                    return $result.then(function (token) {

                        if (!token) return null;

                        // Handle expired token
                        if (token.expiration_date && new Date() > token.expiration_date) {
                            return $Tokens.destroy({access_token: token}).then(function () {
                                return null
                            });
                        }

                        tokenInfo = token;
                        if (token.user_id != null) {
                            return $Users.findOne({id: token.user_id});
                        }
                        else {
                            //The request came from a client only since userID is null
                            //therefore the client is passed back instead of a user
                            return $Clients.findOne({client_id: token.client_id});
                        }

                    }).then(function (identity) {

                        // to keep this example simple, restricted scopes are not implemented,
                        // and this is just for illustrative purposes


                        if (!identity) return null;
                        else if (criteria.type == 'verification') {
                            if (identity.email != criteria.email) return null;
                        }
                        // Otherwise if criteria.type != 'verfication'
                        else if (!identity.date_verified) return null;

                        return {
                            identity: identity,
                            authorization: {
                                scope: tokenInfo.scope,
                                token: tokenInfo
                            }
                        };
                    });
                },

                generateTokenString: function () {
                    return randToken.generate(sails.config.security.oauth.token.length);
                },
                generateToken: function (criteria) {

                    //if (err) return next(err);

                    var token = {},
                        accessToken,
                        $Tokens = API.Model(Tokens);

                    if (!criteria.client_id) return Promise.resolve(null);

                    token.client_id = criteria.client_id;
                    token.user_id = criteria.user_id || undefined;


                    token.access_token = accessToken = Tokens.generateTokenString();

                    token.refresh_token = Tokens.generateTokenString();
                    token.code = Tokens.generateTokenString();

                    if (!criteria.expiration_date) {
                        token.expiration_date = new Date();
                        token.expiration_date.setTime(token.expiration_date.getTime() + sails.config.security.oauth.token.expiration * 1000 + 999);
                    }


                    return $Tokens.findOrCreate(criteria, token).then(function (retrievedToken) {


                        if (retrievedToken.access_token != accessToken) {
                            return $Tokens.update(criteria, token).then(function (updatedTokens) {
                                return updatedTokens[0];
                            });
                        }
                        return retrievedToken;
                    });

                }
            };
            ```

    3. Define Users.js

        1. Edit api/models/Users.js

            ```shell
            vim api/models/Users.js
            ```

        2. Replace contents with the following:

            ```js
            /**
             * Users.js
             */

            var promisify = require('bluebird').promisify,
                bcrypt = require('bcrypt-nodejs');
            module.exports = {


                attributes: {


                    username: {
                        type: 'string',
                        unique: true,
                        required: true
                    },

                    email: {
                        type: 'email',
                        unique: true,
                        required: true
                    },

                    password: {
                        type: 'string',
                        required: true,
                        columnName: 'encrypted_password',
                        minLength: 8
                    },

                    first_name: {
                        type: 'string'
                    },

                    last_name: {
                        type: 'string'
                    },

                    location: {
                        type: 'string'
                    },

                    date_registered: {
                        type: 'date'
                    },

                    date_verified: {
                        type : 'date'
                    },

                    comparePassword: function(password) {
                        return bcrypt.compareSync(password, this.password);
                    },

                    toJSON: function() {

                        var obj = this.toObject();
                        delete obj.password;

                        return obj;
                    }

                },

                beforeCreate: function(user, next) {
                    if (user.hasOwnProperty('password')) {
                        user.password = bcrypt.hashSync(user.password, bcrypt.genSaltSync(10));
                        next(false, user);

                    } else {
                        next(null, user);
                    }
                },


                beforeUpdate: function(user, next) {
                    if (user.hasOwnProperty('password')) {
                        user.password = bcrypt.hashSync(user.password, bcrypt.genSaltSync(10));
                        next(false, user);
                    } else {
                        next(null, user);
                    }
                },

                authenticate: function (username, password) {
                    return API.Model(Users).findOne({username: username}).then(function(user){
                        return (user && user.date_verified && user.comparePassword(password))? user : null;
                    });
                }

            };
            ```

13. Create New Controllers

    ```shell
    sails generate controller OAuth
    ```

    ```shell
    sails generate controller users
    ```

    ```shell
    sails generate controller clients
    ```

14. Define Controllers

    1. Define OAuthController.js

        1. Edit api/controllers/OAuthController.js

            ```shell
            vim api/controllers/OAuthController.js
            ```
            
        2. Replace contents with the following:

            ```js
            /**
             * OAuthController
             */

            module.exports = {
                token: function(req,res){
                    API(OAuth.sendToken,req,res);
                },

                'token-info': function(req,res){
                    API(OAuth.tokenInfo,req,res);
                }

            };
            ```

    2. Define UsersController.js

        1. Edit api/controllers/UsersController.js

            ```shell
            vim api/controllers/UsersController.js
            ```

        2. Replace contents with the following:

            ```js
            /**
             * UsersController
             *
             * @description :: Server-side logic for managing users
             * @help        :: See http://links.sailsjs.org/docs/controllers
             */

            module.exports = {
                register: function(req,res){
                    API(Registration.registerUser,req,res);
                },
                'verify/:email': function(req,res){
                    API(Registration.verifyUser,req,res);
                },
                current: function(req,res){
                        API(Registration.currentUser,req,res);
                }
            };
            ```

    3. Define ClientsController.js 

        1. Edit api/controllers/ClientsController.js

            ```shell
            vim api/controllers/ClientsController.js
            ```

        2. Replace contents with the following:

            ```js
            /**
             * ClientsController
             *
             * @description :: Server-side logic for managing clients
             * @help        :: See http://links.sailsjs.org/docs/controllers
             */

            module.exports = {
                register: function(req,res){
                    API(Registration.registerClient,req,res);
                },
                'verify/:email': function(req,res){
                    API(Registration.verifyClient,req,res);
                }
            };
            ```

15. Define Policies

    1. Create OAuthPublicClient.js

        1. Create and edit api/policies/OAuthPublicClient.js

            ```shell
            touch api/policies/OAuthPublicClient.js && vim $_
            ```

        2. Add the following content:

            ```js
            module.exports = function (req, res, next) {
                OAuth.authenticator.authenticate(
                    ['oauth2-public-client'],
                    { session: false })(req,res,next);
            };
            ```

    2. Create OAuthValidateAccessToken.js

    
        1. Create and edit api/policies/OAuthValidateAccessToken.js

            ```shell
            touch api/policies/OAuthValidateAccessToken.js && vim $_
            ```

        2. Add the following content:

            ```js
            module.exports = function (req, res, next) {
                OAuth.authenticator.authenticate('bearer', { session: false }, function(err,identity,authorization) {
                    if (!identity ) return res.send(401);

                    req.identity = identity;
                    req.authorization = authorization;

                    next();
                })(req,res);
            };
            ```

16. Create Services

   
    1. Create API.js

        1. Create and edit api/services/API.js

            ```shell
            touch api/services/API.js && vim $_
            ```

        2. Add the following content

            ```js
            var Promise = require('bluebird'),
                promisify = Promise.promisify,
                sendResult,
                sendError,
                Model,
                API;

            sendResult = function (request, response) {
                return function (result) {
                    // Assume the response has already been sent if a null(ish) result
                    if (result == null) return;

                    //Ensure JSON Formatted Response
                    if (typeof(result) != 'object') {
                        result = {result: result};
                    }
                    response.json(result);
                }
            };

            sendError = function (request, response) {
                return function (err) {
                    var str,
                        errTypes = ['unauthorized', 'forbidden', 'invalid', 'internal'],
                        lineSeparator = "\n-------------------------------------------------------------------------\n",
                        type = typeof(err);

                    if (type != 'object') {

                        //Wrap the error in an object
                        err = {message: err};
                    }

                    else if (err instanceof Error) {
                        err = {
                            name: err.name || undefined,
                            message: err.message || undefined,
                            raw: err
                        };
                    }

                    if (type == 'string' || typeof err.message == 'string') {
                        //Check if the error is more specific
                        str = err.message.toLowerCase();
                        if (errTypes.indexOf(str) > -1) {
                            err[str] = true;
                        }
                        else if (err.code == "E_VALIDATION") {
                            err.invalid = true;
                        }
                        else {
                            err.internal = true;
                        }
                    }

                    //Decide error response

                    if (err.unauthorized) {
                        response.send(401, err);
                    }
                    else if (err.forbidden) {
                        response.forbidden(err);
                    }
                    else if (err.invalid) {
                        response.send(422, err);
                    }
                    else if (err.internal) {
                        response.serverError(err);
                    }
                    else {
                        err.request = true;
                        response.badRequest(err);
                    }

                    // Output error to server log
                    console.log(lineSeparator);
                    console.error(err);
                    if (err.raw) console.error(err.raw);
                    console.log("\nError Date: ", new Date());
                    console.log(lineSeparator);
                    //throw err.raw;
                }
            };

            Model = function (model) {
                this.model = model;
            };

            Model.prototype = {

                create: function (attributes) {
                    return promisify(this.model.create)(attributes);
                },

                findOne: function (criteria) {
                    return promisify(this.model.findOne)(criteria);
                },

                findOrCreate: function (criteria, attributes) {
                    return promisify(this.model.findOrCreate)(criteria, attributes);
                },



                update: function (criteria, attributes) {
                    return promisify(this.model.update)(criteria, attributes);
                },



                destroy: function (criteria) {
                    return promisify(this.model.destroy)(criteria);
                }
            };

            API = function (action, req, res) {
                var data, context;

                //Validate Arguments
                if (!res || !req || !action) {
                    throw {
                        internal: true,
                        message: "API Call Problem",
                        parameters: {
                            action: (action && "OK") || "BAD",
                            request: (req && "OK") || "BAD",
                            response: (res && "OK") || "BAD"
                        }
                    };

                }

                context = req.context || {};

                //Setup User Identity and Authorization data for ease of access
                context.identity = req.identity;
                context.authorization = req.authorization;

                data = req.params.all();

                return Promise.method(action)(data, context, req, res)
                    .then(sendResult(req, res))
                    .catch(sendError(req, res));
            };

            API.Model = function (model) {
                return new Model(model);
            };

            module.exports = API;
            ```

 2. Create OAuth.js

        1. Create and edit api/services/OAuth.js

            ```shell
            touch api/services/OAuth.js && vim $_
            ```

        2. Add the following content

            ```js
            /**
             * Module dependencies.
             */
            var promisify = require('bluebird').promisify,
            passport = require('passport'),
            oauth2orize = require('oauth2orize'),

            PublicClientPasswordStrategy = require('passport-oauth2-public-client').Strategy,
            BearerStrategy = require('passport-http-bearer').Strategy,

            server = oauth2orize.createServer(), // create OAuth 2.0 server service
            validateAndSendToken = promisify(server.token()),
            tokenErrorMessage = server.errorHandler(),

            //Handlers
            publicClientVerifyHandler,
            bearerVerifyHandler,
            exchangePasswordHandler,
            exchangeRefreshTokenHandler;

            /**
             * Public Client strategy
             *
             * The OAuth 2.0 public client authentication strategy authenticates clients
             * using a client ID. The strategy requires a verify callback,
             * which accepts those credentials and calls done providing a client.
             */

            publicClientVerifyHandler = function (clientId, next) {
                process.nextTick(function () {
                    API.Model(Clients).findOne({client_id: clientId}).nodeify(next);
                });
            };

            /**
             * BearerStrategy
             *
             * This strategy is used to authenticate either users or clients based on an access token
             * (aka a bearer token).  If a user, they must have previously authorized a client
             * application, which is issued an access token to make requests on behalf of
             * the authorizing user.
             */
            bearerVerifyHandler = function(token, next) {
                process.nextTick(function () {
                    Tokens.authenticate({access_token:token}).nodeify(function (err, info) {
                        if (!info || !info.identity) return next(null, null);
                        next(null, info.identity, info.authorization);
                    });
                });
            };

            /**
             * Exchange user id and password for access tokens.
             *
             * The callback accepts the `client`, which is exchanging the user's name and password
             * from the token request for verification. If these values are validated, the
             * application issues an access token on behalf of the user who authorized the code.
             */
            exchangePasswordHandler = function(client, username, password, scope, next) {
                if (!client) return next(null, false); //passport-oauth2-client-password needs to be configured
                //Validate the user
                Users.authenticate(username, password).then(function (user) {
                    if (!user) return next(null, false);
                    return Tokens.generateToken({
                        client_id: client.client_id,
                        user_id: user.id
                    }).then(function (token) {
                        return next(null, token.access_token, token.refresh_token, {
                            expires_in: token.calc_expires_in()
                        });
                    });
                });
            };

            /**
             * Exchange the refresh token for an access token.
             *
             * The callback accepts the `client`, which is exchanging the client's id from the token
             * request for verification.  If this value is validated, the application issues an access
             * token on behalf of the client who authorized the code
             */
            exchangeRefreshTokenHandler = function (client, refreshToken, scope, done) {

                API.Model(Tokens).findOne({
                    refresh_token: refreshToken
                }).then(function (token) {
                    if (!token) return done(null, null);

                    return Tokens.generateToken({
                        user_id: token.user_id,
                        client_id: token.client_id
                    }).then(function (token) {
                        return done(null, token.access_token, token.refresh_token, {
                            expires_in: token.calc_expires_in()
                        });

                    });
                }).catch(function (err) {
                    console.error(err);
                    done(err);
                });

            };

            //Initialize Passport Strategies
            passport.use(new PublicClientPasswordStrategy(publicClientVerifyHandler));
            passport.use(new BearerStrategy(bearerVerifyHandler));
            server.exchange(oauth2orize.exchange.password(exchangePasswordHandler));
            server.exchange(oauth2orize.exchange.refreshToken(exchangeRefreshTokenHandler));

            module.exports = {
                authenticator: passport,
                server: server,

                //OAuth Token Services
                sendToken: function (data, context, req, res) {
                    if (req.method != 'POST') throw 'Unsupported method';

                    return validateAndSendToken(req, res).catch(function (err) {
                        tokenErrorMessage(err, req, res);
                    });
                },

                tokenInfo: function (data, context) {
                    var token = context.authorization.token;
                    token.expires_in = token.calc_expires_in();
                    return {
                        identity: context.identity,
                        authorization: context.authorization
                    };
                }
            };
            ```
			
    3. Create Registration.js

        1. Create and edit api/services/Registration.js

            ```shell
            touch api/services/Registration.js && vim $_
            ```

        2. Add the following content

            ```js
            var Promise = require('bluebird'),
                promisify = Promise.promisify,
                mailer = require('nodemailer'),
                emailGeneratedCode,
                transporter;


            transporter = mailer.createTransport({
                service: 'gmail',
                auth: {
                    user: sails.config.security.admin.email.address,
                    pass: sails.config.security.admin.email.password
                }
            });

            emailGeneratedCode = function (options) {
                var url = options.verifyURL,
                    email = options.email;


                message = 'Hello!';
                message += '<br/>';
                message += 'Please visit the verification link to complete the registration process.';
                message += '<br/><br/>';
                message += 'Account with ' + options.type + " : " + options.id;
                message += '<br/><br/>';
                message += '<a href="';
                message += url;
                message += '">Verification Link</a>';
                message += '<br/>';

                transporter.sendMail({
                    from: sails.config.security.admin.email.address,
                    to: email,
                    subject: 'Canadian Tire App Account Registration',
                    html: message
                }, function (err, info) {
                    console.log("Email Response:", info);
                });

                return {
                    url: url
                }
            };

            module.exports = {
                emailGeneratedCode: emailGeneratedCode,
                currentUser: function(data,context){
                  return context.identity;
                },
                registerUser: function (data, context) {
                    var date = new Date();
                    return API.Model(Users).create({
                        username: data.username,
                        email: data.email,
                        password: data.password,
                        date_registered: date
                    }).then(function (user) {
                        context.id = user.username;
                        context.type = 'Username';
                        return Tokens.generateToken({
                            user_id: user.id,
                            client_id: Tokens.generateTokenString()
                        });
                    }).then(function (token) {
                        return emailGeneratedCode({
                            id: context.id,
                            type: context.type,
                            verifyURL: sails.config.security.server.url + "/users/verify/" + data.email + "?code=" + token.code,
                            email: data.email
                        });
                    });

                },

                verifyUser: function (data, context) {
                    return Tokens.authenticate({
                        code: data.code,
                        type: 'verification',
                        email: data.email
                    }).then(function (info) {
                        var date = new Date();
                        if (!info) return Promise.reject('Unauthorized');

                        API.Model(Users).update(
                            {
                                username: info.identity.username
                            },
                            {
                                date_verified: date
                            }
                        );

                        return {
                            verified: true,
                            email: info.identity.email
                        }
                    });
                },

                registerClient: function (data, context) {
                    return API.Model(Clients).create({
                        client_id: Tokens.generateTokenString(),
                        client_secret: Tokens.generateTokenString(),
                        email: data.email
                    }).then(function (client) {
                        context.id = client.client_id;
                        context.type = 'Client ID';

                        return Tokens.generateToken({
                            client_id: client.client_id
                        });
                    }).then(function (token) {
                        return emailGeneratedCode({
                            id: context.id,
                            type: context.type,
                            verifyURL: sails.config.security.server.url + "/clients/verify/" + data.email + "?code=" + token.code,
                            email: data.email
                        });
                    });
                },


                verifyClient: function (data, context) {
                    return Tokens.authenticate({
                        type: 'verification',
                        code: data.code,
                        email: data.email
                    }).then(function (info) {
                        var date = new Date();
                        if (!info) return Promise.reject('Unauthorized');

                        API.Model(Clients).update(
                            {
                                client_id: info.identity.client_id
                            },
                            {
                                date_verified: date
                            }
                        );

                        return {
                            verified: true,
                            email: info.identity.email
                        };
                    });
                }
            };
            ```
    
##PART II : Test Auth Service

###Section A. Basic Test

1. In terminal, run `sails lift`

2. In your browser, go to `http://localhost:1336/users`

3. If you see the message `Unauthorized`, then you have succeeded.


###Section B. Advanced Test

1. Launch Server

    1. In terminal, run:

     ```shell
     sails lift
     ```

2. Register a “Client”

    1. Ensure that the custom settings are completed
        1. Security Config (Step 5) contains valid GMail credentials
        2. Connections Config (Step 9) contains valid Mongo server details

    2. Using Postman, post to `http://localhost:1336/clients/register` with `x-www-form-urlencoded` key:value pairs:

        ```shell
        email : <your email>
        ```

        where `<your email>` is your actual email (without the < >s).

    3. You should receive a response as such:

        ```json
        {
            "url": "http://localhost:1336/clients/verify/<your email>?code=gqjH6igH6Z89ROEoVRFmEiVYuEfEZ1kQ"
        }
        ```

    4. Provided you set the correct credentials in step 5.ii you should now receive an email that reads as such:

        ```text
        Hello!
        Please visit the verification link to complete the registration process.

        Account with Client ID : <received client id>

        Verification Link
        ```

    5. You can click the verification link now. The resulting page in your browser should read as such:

        ```json
        {
          "verified": true,
          "email":    "<your email>"
        }
        ```

3. Register a User

    1. Using Postman, post to `http://localhost:1336/users/register` with `x-www-form-urlencoded` key:value pairs:

        ```shell
        username : <your username>
        password : <your password>
        email    : <your email>
        ```

        Filling out the credentials as appropriate (without the < >s).

    2. You should receive a response as such:

        ```json
        {
            "url": "http://localhost:1336/users/verify/<your email>?code=Y087VfF3bbHmNrQaRsAfOB8srfNB0gDW"
        }
        ```

    3.  You should now receive an email that reads as such:

        ```text
        Hello!
        Please visit the verification link to complete the registration process.

        Account with Username : <your username>

        Verification Link
        ```

    4. You can click the verification link now. The resulting page in your browser should read as such:

        ```json
        {
          "verified": true,
          "email":    "<your email>"
        }
        ```

4. Request Token

    1. In order to request a token, you require a registered client and a registered user (see above).

    2. Using Postman, post to `http://localhost:1336/oauth/token` with `x-www-form-urlencoded` key:value pairs:

        ```shell
        grant_type : password
        client_id  : <received client id>
        username   : <your username>
        password   : <your password>
        ```

        Filling out the credentials as appropriate, but leaving the grant_type as “password”.

    3.  Make note of the access_token value (`<received access token>`). You should receive a response as such:

        ```json
        {
            "access_token":  "<received access token>",
            "refresh_token": "<received refresh token>",
            "expires_in":    3600,
            "token_type":    "Bearer"
        }
        ```

5. Request Resource with Token

    1. Using Postman, request with GET `http://localhost:1336/users/current` with custom authorization header key:value pair:

        ```shell
        Authorization : Bearer <received access token>
        ```

        Replacing the `<received access token>` value with the one you received.

    2.  You should receive a response similar to:

        ```json
        {
            "identity": {
                "username": "<your username>",
                "email":    "<your email>"
            }
        }
        ```


