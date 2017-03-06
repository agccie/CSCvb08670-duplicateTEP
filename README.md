# CSCvb08670-duplicateTEP
This is to automate the check for duplicate TEP encountered by CSCvb08670.  More details regarding this software defect can be found on cisco.com:
https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb08670

This script will detect duplicate leases and pools along with highlighting leases that have incorrectly been freed or abandoned.  If a pool is in the affected state (i.e., it has 1 or more leases that are freed or abandoned), then the free ip count will provide the number of new nodes that can be added without encountering a duplicate TEP address.  

The script should be run directly on the APIC.  Copy the file via scp/sftp and execute it directly on the command line: 

```

fab3-apic1# ./check_CSCvb08670.py
fabric nodes             : 6
vleafs                   : 1
dhcp pools               : 8
dhcp leases              : 5
duplicate IPs            : 0
duplicate leases         : 0
Abandoned/Freed Leases   : 2
    pool: 10.0.88.64         <----- pool with 1 or more abandoned/freed leases
        type       : pod
        state      : normal  <----- this is pool is type ‘normal’.  If it is ‘recovery’, then it is unused anyways
        pool size  : 32
        free count : 26      <----- number of new nodes that can be added before duplicate TEP will be assigned
        good leases: 4
        bad leases : 2
           10.0.88.93, node-202, fab3-spine202, FOX2020GE4H   <----- lease/node that has abandoned/freed lease
           10.0.88.95, node-101, fab3-leaf101, FDO202711U6

```

__NOTE__ If a pool is in the 'recovery' state, then no new leases will be assigned from it.  Therefore, even if the free count of a recovery pool is not zero, it is safe to add a new node to the fabric
