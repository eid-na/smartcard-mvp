# smartcard-mvp
For the embedded smartcard code

### How to setup the development environment
Build an image using the provided Dockerfile. 

### How to compile
Go to the respective applet directory and run `ant`.

### How run software tests
Go in to the respective applet directory, such as applets/HelloWorld. Run `make` then `make sim`.

### How to run hardware tests
Use the GlobalPlatformPro executable gp.{jar,exe} from a host terminal (i.e., not inside the development container) to load the *.cap file(s) on to the card. Obviously, you must have a physical smartcard that is compliant with the app's respective version of the JavaCard standard. For example, HelloWorld is targeted for v3.0.4. GlobalPlatformPro intergrates automatically with most off-the-shelf smartcard USB readers, using your operating system's default/downloaded drivers.


## Dependency Risks
The following dependencies must be forked or replicated before commericialization. ALL source code and hardware must be understood and either controlled or trusted, to be secure.
1. The smartcard supply chain
2. GlobalPlatformPro
3. The Ant compile task
4. The Java Development Kit + JavaCard Development Kit
