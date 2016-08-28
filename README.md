JunoMS is a MapleStory v62 server emulator written in C without the standard 
library or any dependency at all. Currently, the executable is under 30kb and 
supports linux AMD64 only. Windows support is planned once the core features are
in place.

I have learned many things from developing 
[https://github.com/Francesco149/kagami](kagami), and this project's current aim
is matching kagami's current functionality with way smaller executable size, 
no dependencies, no stdlib and proceed from there.

Current status:

* Only handles 1 player at once for testing purposes
* Most of the login server functionality is there, but with hardcoded accounts 
  and characters (and no character creation)
* Equips are correctly displayed in character selection
* Gets in-game and spawns in you in Henesys

Goal roadmap:
* Implement most basic in-game functionality using the current hardcoded 
  accounts/character testbed
* Implement wz data handling
* Implement a basic plaintext or binary database module to quickly set up tests
  without mysql and shape the code around a database
* Implement a mysql module
* Separate all the platform-specific code into a platform layer
* Windows port

# Usage
You must be on linux x64 / amd64. This was only tested on linux 

```bash
git clone https://github.com/Francesco149/junoms.git
cd junoms
./build.sh
```

You can check executable size with:

```bash
wc -c juno
```


Start the emulator:

```bash
./juno
```

Start a maplestory v62 localhost.

There are a few hardcoded accounts that you can use to test stuff:

* user: errorN (where N is the desired error number) password: doesn't matter - 
  displays failed login errors (check the source to see which ones are valid, as
  some might crash the client).
* user: banN (where N is the desired ban message number) password: doesn't 
  matter - displays ban messages.
* user: asdasd password: asdasd - use this to log in, select the hardcoded 
  character and get in game.
