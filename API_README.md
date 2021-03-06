##Resource API Server Auth Consumer Documentation

###Instructions
1. Install SailsJS beta (rc9+) if not installed already.

    ```shell
    sudo npm install sails@beta -g
    ```

2. Generate a new SailsJS app by running the following in terminal (you should be inside the project root folder):

    ```shell
    sails new sample-api-server --no-frontend && cd sample-api-server
    ```

3. Install Dependencies

    ```shell
    npm install sails-mongo@beta passport passport-http-bearer bluebird request --save
    ```

    TIP: Sometimes it helps to run `sudo npm cache clear` when dependencies fail to install.


4. Configure http

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

5. Configure policies

    1. Edit the config/policies.js

        ```shell
        vim config/policies.js
        ```

    2. Find the following:

        ```shell
        '*': true,
        ```

        And change to:

        ```shell
        '*': 'OAuth',
        ```

6. Configure Database Connection

    1. Edit config/connections.js

        ```shell
        vim config/connections.js
        ```

    2. Replace contents with the following:

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

    3. Fill in your host, port, username, password and database name as appropriate (should be different from oauth database).
        Example:
        ```js
        module.exports.connections = {

            mongo: {
                adapter: 'sails-mongo',
                host: 'localhost',
                port: '27017',
                database: 'sample-app'
            }
        };
        ```

 7. Create Policy OAuth.js

    1. Create and edit api/policies/OAuth.js

        ```shell
        touch api/policies/OAuth.js && vim $_
        ```

    2. Add the following content:

        ```js
        var passport = require('passport'),
            request = require('request'),
            BearerStrategy = require('passport-http-bearer').Strategy,
            bearerVerifyHandler;
        /**
         * BearerStrategy
         *
         * This strategy is used to authenticate either users or clients based on an access token
         * (aka a bearer token).  If a user, they must have previously authorized a client
         * application, which is issued an access token to make requests on behalf of
         * the authorizing user.
         */
        bearerVerifyHandler = function(req, token, next) {
            process.nextTick(function() {
                var options = {
                        url: 'http://localhost:1336/oauth/token-info',
                        json: true,
                        headers: {
                            'Authorization': 'Bearer ' + token
                        }
                    },

                    callback = function (error, response, info){
                        if (error) next(error);
                        next(null,info.identity,info.authorization);
                    };

                request.post(options,callback);
            });
        };

        passport.use(new BearerStrategy({ passReqToCallback: true},bearerVerifyHandler));

        module.exports = function (req, res, next) {
            passport.authenticate('bearer', { session: false}, function(err,identity,authorization) {

                req.identity = identity;
                req.authorization = authorization;

                next();
            })(req,res);
        };
        ```

8. Create Test Resource Endpoint

    1.  Create Test Controller

        ```shell
        sails generate controller test
        ```



    2. Edit api/controllers/TestController.js

        ```shell
        vim api/controllers/TestController.js
        ```

    3. Replace contents with the following:

        ```js
          /**
         * TestController
         *
         * @description :: Test Controller
         * @help        :: See http://links.sailsjs.org/docs/controllers
         */

        module.exports = {
            action: function(req,res){
                res.json({success: true});
            }

        };
        ```
9. Test Resource Service

    1. The following tests assume that there is a Sails OAuth Server running at `http://localhost:1336/oauth/token`
       (If the OAuth server is running at a separate URL, please update the references in the code as necessary).

        Also, this tutorial assumes that the API server is on port 1337 (replace as neccessary).

    2. Launch the API Server
        ```shell
            sails lift
        ```

    3. Using Postman, post to `http://localhost:1336/oauth/token` with `x-www-form-urlencoded` key:value pairs:

        ```shell
        grant_type : password
        client_id  : <received client id>
        username   : <your username>
        password   : <your password>
        ```

        Filling out the credentials as appropriate, but leaving the grant_type as “password”.

    4.  Make note of the access_token value (`<received access token>`). You should receive a response as such:

        ```json
        {
            "access_token":  "<received access token>",
            "refresh_token": "<received refresh token>",
            "expires_in":    3600,
            "token_type":    "Bearer"
        }
        ```


    6. Using Postman, perform a GET request to `http://localhost:1337/test/action` with custom authorization header key:value pair:

       ```shell
       Authorization : Bearer <received access token>
       ```

        Replacing the `<received access token>` value with the one you received.

    7. You should receive the following response:

        ```json
        {
            "success" : true
        }
        ```
