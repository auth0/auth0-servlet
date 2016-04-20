## Partner Web App SSO using Java Servlets and JSP

### Prerequisites

In order to run this example you will need to have Java 8 and Maven installed. You can install Maven with [brew](http://brew.sh/):

```sh
brew install maven
```

Check that your maven version is 3.0.x or above:
```sh
mvn -v
```

### Update configuration information

Enter your:

`client_id`, `client_secret`, `domain`, and `connection` information into `src/main/webapp/WEB-INF/web.xml`


### Build and Run

In order to build and run the project you must execute:
```sh
mvn clean install tomcat7:run
```

Then, go to [http://localhost:4000/portal/home](http://localhost:4000/portal/home).

or

better still [http://app2.com:4000/portal/home](http://app2.com:4000/portal/home).


**BEFORE** signing in make sure that the accompanying `web app` (see other folder in this sample!)
is already running. The login procedure depends on that application for the sign in process (SSO)

Sign in using the username / password you set up for the DB connection, and you're there!
Notice anything about the URL of the Partner signin page?

---
 
## License

The MIT License (MIT)

Copyright (c) 2013 AUTH10 LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
