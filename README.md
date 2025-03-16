# basic-dll-loader
an attempt to make a dll/module loader, made to test vulnerabilities in application data tampering (cybersec related)

## table

1. [description](#description)
2. [features](#features)
3. [usage](#usage)

## description

this is a super crude dll/module loader made using a guide as a reference (not linking it) and windows thread and process documentation. 

it is terminal based and you have to manually type or paste the name of the host process and the absolute directory of the dll you want to attach.
i didnt want to implement a GUI because i didnt care and this project was only for testing, if you want something with functionality go use xenos (old) or system informer (process hacker).

it does not work with protected apps and should only be used for educational purposes only (nmr).

## features

- basic dll thread attaching
- admin prompt
- terminal based

## usage

- download the source code OR clone this repository with:
   ```bash
   git clone https://github.com/mikuvn/basic-dll-loader.git
   ```
- compile the code using C/C++ compiler (e.g., MinGW -> G++). 
- run the executable via the terminal.
