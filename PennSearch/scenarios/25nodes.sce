


# Turn on all traces for LS module on node 1
* LS VERBOSE ALL ON
# Turn on traffic traces for APP module on all nodes.
* APP VERBOSE TRAFFIC ON
# Turn on all traces for APP module on node 1 
* APP VERBOSE ALL ON


# Advance Time pointer by 15 seconds. Allow the routing protocol to stabilize.

TIME 60000

14 APP PING 15 HI

TIME 200

LINK DOWN 14 15

LINK DOWN 17 20

LINK DOWN 12 11

TIME 50000

14 APP PING 15 HI

5 APP PING 23 HI

TIME 1000

LINK UP 17 20

TIME 50000

5 APP PING 23 HI


