
* LS VERBOSE ALL ON

* DV VERBOSE ALL ON

# Turn on all traces for APP module on node 1 
* APP VERBOSE ALL ON


# Advance Time pointer by 15 seconds. Allow the routing protocol to stabilize.

TIME 60000

0 APP PING 4 HELLO

TIME 200

LINK DOWN 1 6 

TIME 50000

0 APP PING 4 HI

TIME 200

LINK UP 1 6

TIME 50000

0 APP PING 4 HI

TIME 200

LINK DOWN 0 1

LINK DOWN 0 6

TIME 50000

0 APP PING 4 HI
