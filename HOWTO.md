# HOW TO BUILD

## For Windows

Prerequisites: Microsoft Visual Studio Version 18

```
cd wincli
.\REBUILDALL.bat
```

## For Java

Prerequisites: Open JDK version 17 (Microsoft or Adoptium), Apache Maven

```
mvn clean package

```

## For Linux

Prerequisites: g++, GNU Make, OpenSSL version 3.6.0 or higher

```
cd lincli
make Release-clean Release
```
