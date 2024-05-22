#!/usr/bin/env bash

function lf_up() {
	sudo $lf_exec -l 0-3 \
    -a $lf_allowed_devices \
    --log-level lf:debug \
    -- \
    -p 0x1 \
    -c $lf_config \
    2> $lf_log\
    &
}

function usage() {
	echo "Usage:"
	echo "$0 lf_exec lf_config lf_log lf_mirror_ip lf_outbound_ip"
}

if [ $# -eq 0 ]
then
	echo "No argument provided."
	usage
	exit 1
fi



# get arguments
lf_exec=$1
lf_allowed_devices=$2
lf_config=$3
lf_log=$4
lf_mirror_ip=$5
lf_outbound_ip=$6

lf_temp_config="lf_temp_config.json"

# start lightning filter
lf_up

echo "LF started"

# wait until the mirror interfaces virtio_user0 is created
while ! sudo ip link show | grep -q virtio_user0; do
    sleep 0.1
done

sudo ip link set virtio_user0 up
sudo ip addr add $lf_mirror_ip/24 dev virtio_user0 


# start python script to make arp request and write modified config
# virtio interface needs some seconds to become operational
sleep 10 
rm -f $lf_temp_config
sudo python3 configure_lf_arp.py $lf_config $lf_temp_config $lf_outbound_ip


# update config of running LF instance
sudo ./lf-ipc.py --cmd="/config" --params="$lf_temp_config"

# wait for interrupt
wait
exit 0