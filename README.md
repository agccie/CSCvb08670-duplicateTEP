# CSCvb08670-duplicateTEP
This is to automate the check for duplicate TEP encountered by CSCvb08670.  More details regarding this software defect can be found on cisco.com:
https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb08670

This script will detect duplicate leases and pools along with highlighting leases that have incorrectly been freed or abandoned.  If a pool is in the affected state (i.e., it has 1 or more leases that are freed or abandoned), then the free ip count will provide the number of new nodes that can be added without encountering a duplicate TEP address.  

The script should be run directly on the APIC.  Copy the file via scp/sftp and execute it directly on the command line.  Detailed information is added to summarize the output.  In a broken condition, user will see the following output

```

fab2-apic1# ./check_CSCvb08670.py
fabric nodes                       : 4
vleafs                             : 0
dhcp pools                         : 3
dhcp leases                        : 1
duplicate IPs                      : 0
duplicate leases                   : 0
Recovery Abandoned/Freed Leases    : 0
Abandoned/Freed Leases             : 3

    pool: 10.0.136.64
        type       : pod
        state      : normal
        pool size  : 32
        free count : 28
        good leases: 1
        bad leases : 3
           10.0.136.64, node-103, fab2-leaf103, SAL1821SWJX
           10.0.136.93, node-101, fab2-leaf101, SAL1919ERF0
           10.0.136.94, node-201, fab2-spine201, FOX1919G3BC

*********************************** Summary ***********************************

    There are 3 abandoned/freed leases found that could create a duplicate IP
    address. Apply the workaround as described in CSCvb08670 to mark the
    pool corresponding to the bad lease as 'recovery'.

```

__NOTE__ If a pool is in the 'recovery' state, then no new leases will be assigned from it.  Therefore, even if the free count of a recovery pool is not zero, it is safe to add a new node to the fabric

For users uncomfortable with running scripts directly on the apic, the required objects can be collected into a .tgz file and analyzed offline.  For example:

```

$./check_CSCvb08670.py --offlineHelp

  Offline mode expects a .tgz file.  For example:
  ./check_CSCvb08670.py --offline ./offline_data.tgz

  When executing in offline mode, ensure that all required data is present in
  input tar file. For best results, collect information for all tables using
  the filenames used below. Once all commands have completed, the final tar
  file can be found at:
    /tmp/offline_data.tgz

  bash -c '
   icurl http://127.0.0.1:7777/api/class/dhcpLease.json  > /tmp/off_dhcpLease.json
   icurl http://127.0.0.1:7777/api/class/dhcpPool.json  > /tmp/off_dhcpPool.json
   icurl http://127.0.0.1:7777/api/class/opflexODev.json  > /tmp/off_opflexODev.json
   icurl http://127.0.0.1:7777/api/class/topSystem.json  > /tmp/off_topSystem.json
  rm /tmp/offline_data.tgz
  tar -zcvf /tmp/offline_data.tgz /tmp/off_*
  rm /tmp/off_*
  '

```

