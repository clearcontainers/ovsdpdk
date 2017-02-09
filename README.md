# ovs dpdk with Clear Containers

This is simple standalone Docker Plugin implementation to demonstrate Clear Containers with ovs dpdk.

For more details about Clear Containers
https://github.com/01org/cc-oci-runtime
https://clearlinux.org/clear-containers

For more information about ovs dpdk
http://dpdk.org/


The docker plugin is used to setup and manage ovs dpdk to establish connections between two
clear containers running on the same machine

# How to use this plugin


0. Build this plugin. 

        go build

1. Ensure that your plugin is discoverable https://docs.docker.com/engine/extend/plugin_api/#/plugin-discovery

        sudo cp ovsdpdk.json /etc/docker/plugins


2. Start the plugin

        sudo ./ovsdpdk &
        
   Note: Enable password less sudo to ensure the plugin will run in the background without prompting.

3. Try ovsdpdk connectivity between Clear Containers

	This example demonstrates the ovs-dpdk example as illustrated by
	https://software.intel.com/en-us/articles/using-open-vswitch-with-dpdk-for-inter-vm-nfv-applications


        #Perform cleanup and setup the host to support ovsdpdk


        #Create the ovsdpdk based container networks using the custom ovsdpdk docker driver
        sudo docker network create -d=ovsdpdk --ipam-driver=ovsdpdk --subnet=192.168.1.0/24 --gateway=192.168.1.1  --opt "bridge"="ovsbr" ovsdpdk_net

        #Create a docker containers one on each network using the clear container runtime
        #The IP address of each container is specified
        sudo docker run -d --net=ovsdpdk_net --ip=192.168.1.2 --mac-address=CA:FE:CA:FE:01:02 --name "ccovs1" debian bash -c "ip a; ip route; sleep 30000"

        #Test network connectivity between the two containers over the ovs dpdk based network
        sudo docker run --net=ovsdpdk_net --ip=192.168.1.3 --mac-address=CA:FE:CA:FE:01:03 --name "ccovs2" debian bash -c "ip a; ip route; ping 192.168.1.2"

        #Cleanup
        sudo docker kill `sudo docker ps --no-trunc -aq` ; sudo docker rm `sudo docker ps --no-trunc -aq`
        sudo docker network rm ovsdpdk_net 
