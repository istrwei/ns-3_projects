


# Turn on all traces for LS module on node 1
* LS VERBOSE ALL ON
# Turn on traffic traces for APP module on all nodes.
* APP VERBOSE TRAFFIC ON
# Turn on all traces for APP module on node 1 
* APP VERBOSE ALL ON


# Advance Time pointer by 15 seconds. Allow the routing protocol to stabilize.

TIME 60000

44 APP PING 43 HI

TIME 200

LINK DOWN 44 39

LINK DOWN 37 19

LINK DOWN 39 35

TIME 50000

44 APP PING 43 HI

30 APP PING 43 HI

TIME 1000

LINK UP 37 19

TIME 50000

30 APP PING 43 HI


