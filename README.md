# smartcard-mvp
For the embedded smartcard code

### How to setup the development environment
Build an image using the provided Dockerfile. 

### How to run unit tests
Go to the `applets/basiclogin` and run `mvn test`.

### How to run hardware tests
Use the GlobalPlatformPro executable gp.{jar,exe} from a host terminal (i.e., not inside the development container) to load the *.cap file(s) on to the card (mvn not yet configured to generate these). Obviously, you must have a physical smartcard that is compliant with the app's respective version of the JavaCard standard. The version in mine is v3.0.4. GlobalPlatformPro intergrates automatically with most off-the-shelf smartcard USB readers, using your operating system's default/downloaded drivers.

## Dependency Risks
All source code and hardware must be understood and either controlled or trusted, to be secure. Java is basically synonymous with "depencency Hell", but it otherwise has a lot of support for the cryptographic functions.
