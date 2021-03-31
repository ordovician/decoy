# Decoy
An educational example program of Go programming 
based on having some fun creating an old school decoy program. 
This is an old hacker trick, to give people you password. 
No, you are not supposed to use this to actually trick people 
and you most likely can't because most login systems don't work like this anymore.

This is more for fun and historical perspective.

## How Does it Work?
When people use text based login systems like this:

    Login: erik
    Password: qwerty
    Большая Электронно-Счётная Машина 6
    Welcome to БЭСМ-6 comrade erik: March 29, 2021
    > 

The name of the computer is from the Soviet Mainframe BESM-6 from 1965

What a nefarious hacker could easily do 
is to make a program that looks exactly like this, 
but which instead of logging the user in, stores the user password. 
Thus the hacker can come back later and read a file containing
the passwords of users who have previously tried to log in.

## What is the Point?
The point of this program is to teach basic things like:
reading files, dealing with input and output, string manupulation 
and hash functions in Go by pretending to be hackers. 
If you want to be an actual hacker, you need to find other tools 
as this is a totally outdated approach.

