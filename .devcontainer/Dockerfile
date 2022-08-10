FROM archlinux

RUN pacman -Syu     \
    jdk8-openjdk    \
    maven           \
    ant             \
    junit           \
    git             \
    vim             \
    make            && \         
    mvn install:install-file        \
        -Dfile="/clone/references/jcardsim/jcardsim-3.0.4-SNAPSHOT.jar"      \
        -DgroupId=com.licel       \
        -DartifactId=jcardsim     \
        -Dversion=3.0.4           \
        -Dpackaging=jar           \
        -DgeneratePom=true
