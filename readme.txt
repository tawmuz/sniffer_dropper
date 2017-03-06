This Sniffer/Dropper program uses the libpcap library to sniff packets of an ongoing network
activity and drop packets according to a specified exponential algorithm. The program can be
used to degrade network quality for streaming audio and video. 

The filter expression in the file sniffer.c can be altered to accomodate several network 
activities running across different ports. A desired algorithm by which to govern packet
drops can be implemented in the drop_interval_gen.c file. The network activity may be 
simulated by using a separate script file which has not been provided.

Commands to execute program:
----------------------------------------------
gcc -Wall sniffer.c -o sniffer -lpcap -lm
gcc -Wall drop_interval_gen.c -o gendrops -lm
sudo ./run.sh switchfoot.mp3 50
----------------------------------------------

Note:
----- 
- The file specified as an argument to the run.sh command is a residue of using the program
  to sniff the ftp transfer of the aforementioned file.
- It is neccessary to install the libpcap-dev or libpcap0.8-dev package on your linux system
  to run the program.


