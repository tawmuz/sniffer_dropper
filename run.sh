#!/bin/bash
echo "Cleaning up past executables..."
rm -f *.mp3
echo "Done"

# Add ftp.sh that initiates an ftp connection that is to be sniffed.
echo "Performing ftp operation to verify file size..."
sudo sh ftp.sh $1
echo "Done"

echo "Generating packet drop intervals..."
./gendrops $1 $2
echo "Done"

read -p "Press enter to continue: "

sudo ./sniffer wlp3s0 $2 --$3 $1 &
sudo sh ftp.sh $1
sudo pkill sniffer
echo "FTP packet data captured successfully."
echo "Requested quality degradation performed."
