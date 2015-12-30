# Auth0 + Java API Seed
This is the seed project you need to use if you're going to create a Java API. You'll mostly use this API either for a SPA or a Mobile app. If you just want to create a Regular Java WebApp, please check [this other seed project](https://github.com/auth0/auth0-java/tree/master/examples/java-regular-webapp)

This example is deployed at Heroku at http://auth0-javaapi-sample.herokuapp.com/ping

#Running the example
In order to run the example you need to have maven and java installed.

You also need to set the ClientSecret and ClientId for your Auth0 app as enviroment variables with the following names respectively: `AUTH0_CLIENT_SECRET` and `AUTH0_CLIENT_ID`.

For that, you can set them and run the example with the following command

````bash
mvn -DAUTH0_CLIENT_ID=myClientId -DAUTH0_CLIENT_SECRET=myClientSecret clean install jetty:run -Djetty.port=3001
````

Try calling [http://localhost:3001/ping](http://localhost:3001/ping)

You can then try to do a GET to [http://localhost:3001/secured/ping](http://localhost:3001/secured/ping) which will throw an error if you don't send the JWT in the header.
